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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

/// Cumulative bytes per pid and remote endpoint, summed from the event stream.
///
/// Written by the ETW callback on its own thread, read by `sample`. Totals only
/// ever grow, which is what makes the collector's diffing valid. Keyed by the
/// remote as well as the pid so the collector can attribute bytes to
/// addresses; a pid's own total is the sum over its remotes.
static TOTALS: OnceLock<Mutex<HashMap<Key, Totals>>> = OnceLock::new();

/// A pid and the far end it was talking to. `None` once the table is full —
/// bytes are still counted for the pid, just no longer per address.
type Key = (u32, Option<(IpAddr, u16)>);

/// Distinct pid+remote pairs kept before new ones fold into the pid alone.
/// Totals never expire (that is what makes them diffable), so without a cap a
/// long session on a busy machine would grow without bound.
const MAX_KEYS: usize = 8192;

#[derive(Clone, Copy, Default)]
struct Totals {
    bytes_in: u64,
    bytes_out: u64,
}

fn totals() -> &'static Mutex<HashMap<Key, Totals>> {
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

/// Whether an event's addresses are 16-byte IPv6 or 4-byte IPv4.
fn is_v6(id: u16) -> bool {
    matches!(id, TCP_SENT_V6 | TCP_RECV_V6 | UDP_SENT_V6 | UDP_RECV_V6)
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Direction {
    In,
    Out,
}

/// Add one event's bytes to a pid+remote running total. Once the table is at
/// its cap, a new remote's bytes go to the pid's remote-less bucket instead.
fn record(
    map: &mut HashMap<Key, Totals>,
    pid: u32,
    remote: Option<(IpAddr, u16)>,
    size: u32,
    dir: Direction,
) {
    let key = if remote.is_some() && map.len() >= MAX_KEYS && !map.contains_key(&(pid, remote)) {
        (pid, None)
    } else {
        (pid, remote)
    };
    let e = map.entry(key).or_default();
    match dir {
        Direction::In => e.bytes_in = e.bytes_in.saturating_add(size as u64),
        Direction::Out => e.bytes_out = e.bytes_out.saturating_add(size as u64),
    }
}

/// One decoded data event.
#[derive(Debug, PartialEq)]
struct Payload {
    pid: u32,
    size: u32,
    /// The far end, when the payload was long enough to carry it.
    remote: Option<(IpAddr, u16)>,
}

/// The pid, byte count and remote endpoint from an event payload.
///
/// Every Kernel-Network data event — TCP or UDP, v4 or v6 — lays its template
/// out as `PID`, `size` (both 32-bit), then `daddr`, `saddr` (4 bytes each for
/// v4, 16 for v6), then `dport`, `sport` (16-bit, network byte order). The
/// provider fills `daddr`/`dport` with the remote endpoint and `saddr`/`sport`
/// with the local one for both directions — the fields describe the connection,
/// not the packet — so `daddr` is the remote here whether sending or receiving.
/// A payload too short for the addresses still yields its pid and size.
fn parse_payload(data: &[u8], v6: bool) -> Option<Payload> {
    if data.len() < 8 {
        return None;
    }
    let pid = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let size = u32::from_le_bytes(data[4..8].try_into().ok()?);
    let alen = if v6 { 16 } else { 4 };
    let need = 8 + 2 * alen + 4;
    let remote = if data.len() >= need {
        let addr = if v6 {
            let b: [u8; 16] = data[8..24].try_into().ok()?;
            IpAddr::V6(Ipv6Addr::from(b))
        } else {
            let b: [u8; 4] = data[8..12].try_into().ok()?;
            IpAddr::V4(Ipv4Addr::from(b))
        };
        let p = 8 + 2 * alen;
        let port = u16::from_be_bytes([data[p], data[p + 1]]);
        Some((addr, port))
    } else {
        None
    };
    Some(Payload { pid, size, remote })
}

/// ETW record callback. Runs on the trace-processing thread.
unsafe extern "system" fn on_event(event: *mut EVENT_RECORD) {
    if event.is_null() {
        return;
    }
    // SAFETY: ETW hands us a valid record for the duration of the callback.
    let rec = unsafe { &*event };
    let id = rec.EventHeader.EventDescriptor.Id;
    let Some(dir) = direction(id) else {
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
    let Some(p) = parse_payload(data, is_v6(id)) else {
        return;
    };
    // A poisoned lock would mean a panic inside this callback; dropping events
    // is better than unwinding across the FFI boundary.
    if let Ok(mut map) = totals().lock() {
        record(&mut map, p.pid, p.remote, p.size, dir);
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
/// One sample per pid+remote pair; each is monotonic, so the collector's
/// per-key diffing holds, and a pid's rate is the sum over its remotes.
pub fn sample() -> Option<Vec<ProcSample>> {
    if !ensure_started() {
        return None;
    }
    let map = totals().lock().ok()?;
    Some(
        map.iter()
            .map(|(&(pid, remote), t)| ProcSample {
                key: sample_key(pid, remote),
                pid,
                // Names come from sysinfo in the collector; ETW carries none.
                name: String::new(),
                bytes_in: t.bytes_in,
                bytes_out: t.bytes_out,
                // Retransmits live in the separate Microsoft-Windows-TCPIP
                // provider, so this stream cannot supply them.
                retx: 0,
                remote,
            })
            .collect(),
    )
}

/// Stable identity for a pid+remote counter across samples.
fn sample_key(pid: u32, remote: Option<(IpAddr, u16)>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    pid.hash(&mut h);
    remote.hash(&mut h);
    h.finish()
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

    fn v4_payload(pid: u32, size: u32, daddr: [u8; 4], dport: u16) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&pid.to_le_bytes());
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(&daddr);
        data.extend_from_slice(&[10, 0, 0, 2]); // saddr: local
        data.extend_from_slice(&dport.to_be_bytes());
        data.extend_from_slice(&52000u16.to_be_bytes()); // sport
        data.extend_from_slice(&[0; 8]); // seqnum, connid
        data
    }

    #[test]
    fn a_v4_payload_yields_pid_size_and_remote() {
        let data = v4_payload(4660, 1500, [1, 1, 1, 1], 443);
        assert_eq!(
            parse_payload(&data, false),
            Some(Payload {
                pid: 4660,
                size: 1500,
                remote: Some((IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443)),
            })
        );
        // Ports are network byte order: 443 is 0x01BB, sent as [0x01, 0xBB].
        assert_eq!(&data[16..18], &[0x01, 0xBB]);

        // Long enough for pid and size but not the addresses: still counted,
        // just not per remote.
        let short = parse_payload(&data[..12], false).unwrap();
        assert_eq!((short.pid, short.size, short.remote), (4660, 1500, None));

        // A truncated payload is dropped rather than read past.
        assert_eq!(parse_payload(&data[..7], false), None);
        assert_eq!(parse_payload(&[], false), None);
    }

    #[test]
    fn a_v6_payload_reads_sixteen_byte_addresses() {
        let daddr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let mut data = Vec::new();
        data.extend_from_slice(&7u32.to_le_bytes());
        data.extend_from_slice(&64u32.to_le_bytes());
        data.extend_from_slice(&daddr.octets());
        data.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        data.extend_from_slice(&53u16.to_be_bytes());
        data.extend_from_slice(&40000u16.to_be_bytes());
        let p = parse_payload(&data, true).unwrap();
        assert_eq!(p.remote, Some((IpAddr::V6(daddr), 53)));
        // Read as v4 by mistake, the port would land in the wrong place — the
        // id decides the layout, so pin that too.
        assert!(is_v6(TCP_RECV_V6) && is_v6(UDP_SENT_V6));
        assert!(!is_v6(TCP_SENT_V4) && !is_v6(UDP_RECV_V4));
    }

    #[test]
    fn totals_accumulate_and_never_decrease() {
        // What makes the collector's diffing valid: successive snapshots of a
        // key are monotonic, so a delta is always non-negative.
        let r = Some((IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443));
        let mut map = HashMap::new();
        record(&mut map, 100, r, 500, Direction::In);
        record(&mut map, 100, r, 300, Direction::Out);
        record(&mut map, 100, r, 200, Direction::In);

        let t = map[&(100, r)];
        assert_eq!(t.bytes_in, 700);
        assert_eq!(t.bytes_out, 300);
    }

    #[test]
    fn a_pid_first_seen_mid_session_starts_from_zero() {
        // A process that appears after the session started must not inherit
        // another pid's history, or its first delta would be enormous.
        let mut map = HashMap::new();
        record(&mut map, 1, None, 9_000, Direction::In);
        record(&mut map, 2, None, 40, Direction::In);
        assert_eq!(map[&(2, None)].bytes_in, 40);
        assert_eq!(map[&(2, None)].bytes_out, 0);
    }

    #[test]
    fn remotes_are_kept_apart_per_pid() {
        let a = Some((IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443));
        let b = Some((IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
        let mut map = HashMap::new();
        record(&mut map, 1, a, 100, Direction::In);
        record(&mut map, 1, b, 5, Direction::In);
        record(&mut map, 2, a, 7, Direction::In);
        assert_eq!(map[&(1, a)].bytes_in, 100);
        assert_eq!(map[&(1, b)].bytes_in, 5);
        assert_eq!(map[&(2, a)].bytes_in, 7);
        // And the sample keys tell them apart, but are stable.
        assert_ne!(sample_key(1, a), sample_key(1, b));
        assert_ne!(sample_key(1, a), sample_key(2, a));
        assert_eq!(sample_key(1, a), sample_key(1, a));
    }

    #[test]
    fn a_full_table_folds_new_remotes_into_the_pid() {
        let mut map = HashMap::new();
        for i in 0..MAX_KEYS as u32 {
            let r = Some((IpAddr::V4(Ipv4Addr::from(i)), 1));
            record(&mut map, 1, r, 1, Direction::In);
        }
        assert_eq!(map.len(), MAX_KEYS);
        // A brand-new remote no longer gets its own key…
        let fresh = Some((IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 9));
        record(&mut map, 1, fresh, 42, Direction::In);
        assert!(!map.contains_key(&(1, fresh)));
        assert_eq!(map[&(1, None)].bytes_in, 42);
        // …but a known one keeps accumulating where it was.
        let known = Some((IpAddr::V4(Ipv4Addr::from(3u32)), 1));
        record(&mut map, 1, known, 1, Direction::In);
        assert_eq!(map[&(1, known)].bytes_in, 2);
    }

    #[test]
    fn a_giant_event_cannot_wrap_a_total() {
        // Saturating rather than wrapping: a wrapped total would read as a
        // negative delta and show up as a nonsense rate.
        let mut map = HashMap::new();
        map.insert(
            (7, None),
            Totals {
                bytes_in: u64::MAX - 10,
                bytes_out: 0,
            },
        );
        record(&mut map, 7, None, u32::MAX, Direction::In);
        assert_eq!(map[&(7, None)].bytes_in, u64::MAX);
    }
}
