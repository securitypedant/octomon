//! Per-process network bytes on Windows, from the ETW provider Task Manager
//! itself uses.
//!
//! Windows has no unprivileged per-process byte counter at all — PerfMon's
//! network counters are per-adapter, and `netstat -b` names the owning process
//! but reports no bytes. With privilege there are two sources, and this is the
//! better one: `Microsoft-Windows-Kernel-Network` reports UDP as well as TCP, so
//! it attributes QUIC and HTTP/3, which is traffic neither the macOS nor the
//! Linux backend can see.
//!
//! The other is `GetPerTcpConnectionEStats`, joined to pids via
//! `GetExtendedTcpTable`. It is TCP-only — inheriting exactly the QUIC blind
//! spot this avoids — and needs administrator rights of its own, so it would
//! only ever help where policy blocks ETW but not ESTATS. Worth adding as a
//! fallback if that case turns out to be real.
//!
//! The model is inverted relative to the other platforms. Those sample a
//! counter; this consumes a stream of events and adds them up, so the totals
//! kept here *are* the cumulative counter the collector expects to diff.
//!
//! The session is machine-global and outlives the process, so a crash leaks one
//! and there is a hard cap on how many can exist. Hence the fixed name and the
//! unconditional stop-before-start in [`Session::start`].

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace, StartTraceW, TRACE_LEVEL_INFORMATION,
    WNODE_FLAG_TRACED_GUID,
};
use windows_sys::core::GUID;

use super::ProcSample;

/// `Microsoft-Windows-Kernel-Network`. The same provider Task Manager's Network
/// column and Resource Monitor read.
const KERNEL_NETWORK: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);

/// Session name. Fixed rather than unique so a session leaked by a previous
/// crash can be found and reclaimed instead of accumulating.
const SESSION_NAME: &str = "octomon";

/// Cumulative bytes per pid, summed from the event stream.
///
/// Written by the ETW callback on its own thread, read by `sample`. Totals only
/// ever grow, which is what makes the collector's diffing valid.
static TOTALS: OnceLock<Mutex<HashMap<u32, Totals>>> = OnceLock::new();

#[derive(Clone, Copy, Default)]
struct Totals {
    bytes_in: u64,
    bytes_out: u64,
}

fn totals() -> &'static Mutex<HashMap<u32, Totals>> {
    TOTALS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Kernel-Network event ids. Send and receive are distinct events for each of
/// TCP/UDP over IPv4/IPv6, and every one of those templates begins with the
/// same two fields, which is the only part read here.
const TCP_SENT_V4: u16 = 10;
const TCP_RECV_V4: u16 = 11;
const TCP_SENT_V6: u16 = 26;
const TCP_RECV_V6: u16 = 27;
const UDP_SENT_V4: u16 = 42;
const UDP_RECV_V4: u16 = 43;
const UDP_SENT_V6: u16 = 58;
const UDP_RECV_V6: u16 = 59;

/// Whether an event id is a send, a receive, or neither.
fn direction(id: u16) -> Option<Direction> {
    match id {
        TCP_SENT_V4 | TCP_SENT_V6 | UDP_SENT_V4 | UDP_SENT_V6 => Some(Direction::Out),
        TCP_RECV_V4 | TCP_RECV_V6 | UDP_RECV_V4 | UDP_RECV_V6 => Some(Direction::In),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Direction {
    In,
    Out,
}

/// Add one event's bytes to a pid's running total.
fn record(map: &mut HashMap<u32, Totals>, pid: u32, size: u32, dir: Direction) {
    let e = map.entry(pid).or_default();
    match dir {
        Direction::In => e.bytes_in = e.bytes_in.saturating_add(size as u64),
        Direction::Out => e.bytes_out = e.bytes_out.saturating_add(size as u64),
    }
}

/// The pid and byte count from an event payload.
///
/// Every Kernel-Network data event — TCP or UDP, v4 or v6 — starts its template
/// with `PID` then `size`, both 32-bit. The address fields that follow differ in
/// width between v4 and v6, which is exactly why nothing past the first eight
/// bytes is touched here.
fn parse_payload(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() < 8 {
        return None;
    }
    let pid = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let size = u32::from_le_bytes(data[4..8].try_into().ok()?);
    Some((pid, size))
}

/// ETW record callback. Runs on the trace-processing thread.
unsafe extern "system" fn on_event(event: *mut EVENT_RECORD) {
    if event.is_null() {
        return;
    }
    // SAFETY: ETW hands us a valid record for the duration of the callback.
    let rec = unsafe { &*event };
    let Some(dir) = direction(rec.EventHeader.EventDescriptor.Id) else {
        return;
    };
    if rec.UserData.is_null() || rec.UserDataLength < 8 {
        return;
    }
    // SAFETY: UserData points to UserDataLength bytes owned by the caller and
    // valid until this callback returns; the slice does not escape.
    let data = unsafe {
        std::slice::from_raw_parts(rec.UserData.cast::<u8>(), rec.UserDataLength as usize)
    };
    let Some((pid, size)) = parse_payload(data) else {
        return;
    };
    // A poisoned lock would mean a panic inside this callback; dropping events
    // is better than unwinding across the FFI boundary.
    if let Ok(mut map) = totals().lock() {
        record(&mut map, pid, size, dir);
    }
}

/// Encode a session name as the NUL-terminated UTF-16 the API expects.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `EVENT_TRACE_PROPERTIES` followed by room for the session name.
///
/// The API requires the name to live immediately after the struct in one
/// allocation, with `LoggerNameOffset` pointing at it — a fixed buffer is the
/// usual way to express that. Aligned to the struct so the cast is sound.
#[repr(C)]
struct TraceProps {
    props: EVENT_TRACE_PROPERTIES,
    name: [u16; 128],
}

impl TraceProps {
    fn new(mode: u32) -> Self {
        let mut props = EVENT_TRACE_PROPERTIES::default();
        props.Wnode.BufferSize = std::mem::size_of::<Self>() as u32;
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props.LogFileMode = mode;
        props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        let mut name = [0u16; 128];
        for (slot, ch) in name.iter_mut().zip(wide(SESSION_NAME)) {
            *slot = ch;
        }
        Self { props, name }
    }

    fn as_mut_ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        std::ptr::from_mut(self).cast()
    }
}

/// Stop any session left behind by a previous run.
///
/// ETW sessions survive the process that created them, so a crash leaves ours
/// running and `StartTraceW` then fails with ERROR_ALREADY_EXISTS forever. This
/// is called unconditionally before starting, and its failure is not an error:
/// the usual case is that there was nothing to stop.
fn stop_stale() {
    let mut props = TraceProps::new(0);
    let name = wide(SESSION_NAME);
    // SAFETY: a zero handle with a name asks ETW to look the session up by
    // name. `props` is a live local of the size recorded in Wnode.BufferSize.
    unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            name.as_ptr(),
            props.as_mut_ptr(),
            EVENT_TRACE_CONTROL_STOP,
        )
    };
}

/// A running real-time trace session, stopped when dropped.
struct Session(CONTROLTRACE_HANDLE);

impl Session {
    /// Start the session and subscribe to the provider.
    ///
    /// `Err` when the caller lacks the rights: starting a session needs
    /// Administrator or membership of Performance Log Users.
    fn start() -> Result<Self, u32> {
        stop_stale();

        let mut props = TraceProps::new(EVENT_TRACE_REAL_TIME_MODE);
        let name = wide(SESSION_NAME);
        let mut handle = CONTROLTRACE_HANDLE::default();
        // SAFETY: all three arguments are live locals; `props` is sized as
        // recorded in Wnode.BufferSize.
        let rc = unsafe { StartTraceW(&mut handle, name.as_ptr(), props.as_mut_ptr()) };
        if rc != ERROR_SUCCESS {
            // Nothing to clean up: the session was never created. The one
            // exception is a stale session another user owns, which stop_stale
            // could not touch.
            return Err(rc);
        }
        let session = Self(handle);

        // SAFETY: `handle` is live and the GUID is a static constant.
        let rc = unsafe {
            EnableTraceEx2(
                handle,
                &KERNEL_NETWORK,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_INFORMATION as u8,
                // Every keyword: the provider's traffic is modest and filtering
                // by keyword would only risk excluding a transport.
                u64::MAX,
                0,
                0,
                std::ptr::null(),
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(rc); // `session` drops, stopping the session
        }
        Ok(session)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let mut props = TraceProps::new(0);
        // SAFETY: `self.0` came from a successful StartTraceW.
        unsafe {
            ControlTraceW(
                self.0,
                std::ptr::null(),
                props.as_mut_ptr(),
                EVENT_TRACE_CONTROL_STOP,
            )
        };
    }
}

/// Consume the session's events until it is stopped. Blocks.
fn consume() {
    let mut logfile = EVENT_TRACE_LOGFILEW::default();
    let mut name = wide(SESSION_NAME);
    logfile.LoggerName = name.as_mut_ptr();
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(on_event);

    // SAFETY: `logfile` is a live local for the duration of both calls, and
    // `name` outlives the pointer stored in it.
    let handle = unsafe { OpenTraceW(&mut logfile) };
    if handle.Value == INVALID_HANDLE_VALUE.addr() as u64 {
        return;
    }
    // SAFETY: `handle` came from OpenTraceW. This blocks until the session is
    // stopped, which happens when the Session guard is dropped at shutdown.
    unsafe { ProcessTrace(&handle, 1, std::ptr::null(), std::ptr::null()) };
    // SAFETY: the trace is finished; closing is the documented teardown.
    unsafe { CloseTrace(handle) };
}

/// Whether the collector has been started, and whether it works.
static STATE: OnceLock<bool> = OnceLock::new();

/// Start the session once, on a dedicated thread.
///
/// Returns false when the session could not be started, which on a correctly
/// configured machine means only one thing: not enough privilege.
pub fn ensure_started() -> bool {
    *STATE.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        // ProcessTrace blocks for the lifetime of the session, so it needs a
        // thread of its own rather than a tokio worker. The thread is
        // deliberately detached: it lives as long as the process.
        std::thread::Builder::new()
            .name("octomon-etw".to_string())
            .spawn(move || match Session::start() {
                Ok(session) => {
                    let _ = tx.send(true);
                    consume();
                    // Held until consume returns so the session outlives it.
                    drop(session);
                }
                Err(rc) => {
                    tracing::debug!("ETW session unavailable: {rc}");
                    let _ = tx.send(false);
                }
            })
            .is_ok()
            // The session either starts promptly or not at all; a slow start
            // would otherwise stall octomon's own startup.
            && rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap_or(false)
    })
}

/// A snapshot of the cumulative totals, in the shape the collector diffs.
///
/// `key` is the pid: unlike the Linux backend, which counts per socket, these
/// totals are already per-process and monotonic.
pub fn sample() -> Option<Vec<ProcSample>> {
    if !ensure_started() {
        return None;
    }
    let map = totals().lock().ok()?;
    Some(
        map.iter()
            .map(|(&pid, t)| ProcSample {
                key: pid as u64,
                pid,
                // Names come from sysinfo in the collector; ETW carries none.
                name: String::new(),
                bytes_in: t.bytes_in,
                bytes_out: t.bytes_out,
                // Retransmits live in the separate Microsoft-Windows-TCPIP
                // provider, so this stream cannot supply them.
                retx: 0,
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_data_events_are_counted() {
        // Send and receive, over both transports and both address families.
        assert_eq!(direction(TCP_SENT_V4), Some(Direction::Out));
        assert_eq!(direction(TCP_RECV_V6), Some(Direction::In));
        assert_eq!(direction(UDP_SENT_V6), Some(Direction::Out));
        assert_eq!(direction(UDP_RECV_V4), Some(Direction::In));
        // Connection attempts, disconnects and the rest carry no byte count.
        assert_eq!(direction(12), None);
        assert_eq!(direction(0), None);
    }

    #[test]
    fn a_payload_yields_its_pid_and_size() {
        // pid 4660, 1500 bytes, then address fields this must not read.
        let mut data = Vec::new();
        data.extend_from_slice(&4660u32.to_le_bytes());
        data.extend_from_slice(&1500u32.to_le_bytes());
        data.extend_from_slice(&[0xff; 32]);
        assert_eq!(parse_payload(&data), Some((4660, 1500)));

        // A truncated payload is dropped rather than read past.
        assert_eq!(parse_payload(&data[..7]), None);
        assert_eq!(parse_payload(&[]), None);
    }

    #[test]
    fn totals_accumulate_and_never_decrease() {
        // What makes the collector's diffing valid: successive snapshots of a
        // pid are monotonic, so a delta is always non-negative.
        let mut map = HashMap::new();
        record(&mut map, 100, 500, Direction::In);
        record(&mut map, 100, 300, Direction::Out);
        record(&mut map, 100, 200, Direction::In);

        let t = map[&100];
        assert_eq!(t.bytes_in, 700);
        assert_eq!(t.bytes_out, 300);
    }

    #[test]
    fn a_pid_first_seen_mid_session_starts_from_zero() {
        // A process that appears after the session started must not inherit
        // another pid's history, or its first delta would be enormous.
        let mut map = HashMap::new();
        record(&mut map, 1, 9_000, Direction::In);
        record(&mut map, 2, 40, Direction::In);
        assert_eq!(map[&2].bytes_in, 40);
        assert_eq!(map[&2].bytes_out, 0);
    }

    #[test]
    fn a_giant_event_cannot_wrap_a_total() {
        // Saturating rather than wrapping: a wrapped total would read as a
        // negative delta and show up as a nonsense rate.
        let mut map = HashMap::new();
        map.insert(
            7,
            Totals {
                bytes_in: u64::MAX - 10,
                bytes_out: 0,
            },
        );
        record(&mut map, 7, u32::MAX, Direction::In);
        assert_eq!(map[&7].bytes_in, u64::MAX);
    }
}
