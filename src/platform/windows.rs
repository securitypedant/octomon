//! Windows probes: Wi-Fi via the Native Wifi API, power via kernel32.
//!
//! Linux shells out for Wi-Fi (`nmcli`, `iw`), macOS reads CoreWLAN in-process,
//! and this one deliberately does not shell out, for two reasons. `netsh wlan show
//! interfaces` prints its *field names* in the display language, so a parser
//! keyed on "SSID" or "Signal" works on an English install and silently returns
//! nothing on a German one. And subprocess output arrives in the console's OEM
//! codepage rather than UTF-8, which mangles exactly the field most likely to be
//! non-ASCII — the SSID. `DOT11_SSID` hands over raw bytes instead.
//!
//! The cost is a few hundred lines of FFI where forty would parse text.

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::WiFi::{
    DOT11_BSS_TYPE, DOT11_PHY_TYPE, WLAN_API_VERSION_2_0, WLAN_BSS_LIST,
    WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO_LIST, WlanCloseHandle, WlanEnumInterfaces,
    WlanFreeMemory, WlanGetNetworkBssList, WlanOpenHandle, WlanQueryInterface, dot11_BSS_type_any,
    dot11_phy_type_eht, dot11_phy_type_he, dot11_phy_type_ht, dot11_phy_type_vht,
    wlan_interface_state_connected, wlan_intf_opcode_current_connection,
};
use windows_sys::core::GUID;

use super::{ThermalState, WifiSignal};
use crate::app::{Neighbour, WifiInfo};

/// An open WLAN client handle, closed when it goes out of scope.
///
/// The API is a sequence of fallible calls each of which allocates, so the
/// alternative to guards is threading a close through every early return.
struct WlanClient(HANDLE);

/// Whether wlanapi.dll exists on this machine at all. Windows Server ships
/// without it unless the Wireless LAN Service feature is added, so the
/// import is delay-loaded (see build.rs) to let octomon start there —
/// which makes it this function's job to keep every Wlan call from being
/// reached, because a delay-loaded call with no DLL behind it faults.
fn wlan_dll_present() -> bool {
    use std::sync::OnceLock;
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
    static PRESENT: OnceLock<bool> = OnceLock::new();
    // SAFETY: a constant, NUL-terminated wide string. The module handle is
    // deliberately never freed: the DLL staying loaded is what lets the
    // delay-load thunks resolve for the rest of the session.
    *PRESENT
        .get_or_init(|| !unsafe { LoadLibraryW(windows_sys::core::w!("wlanapi.dll")) }.is_null())
}

impl WlanClient {
    fn open() -> Option<Self> {
        // Every WLAN API call in this file starts from a client handle, so
        // this is the one place the missing-DLL guard has to hold.
        if !wlan_dll_present() {
            return None;
        }
        let mut negotiated = 0u32;
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: both out-parameters are owned locals. The handle is only used
        // when the call reports success.
        let rc = unsafe {
            WlanOpenHandle(
                WLAN_API_VERSION_2_0,
                std::ptr::null(),
                &mut negotiated,
                &mut handle,
            )
        };
        // ERROR_SERVICE_NOT_ACTIVE lands here when WLAN AutoConfig is stopped,
        // which is normal on Server and on machines where it has been disabled.
        (rc == ERROR_SUCCESS && !handle.is_null()).then_some(Self(handle))
    }
}

impl Drop for WlanClient {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful WlanOpenHandle and is not
        // used again.
        unsafe { WlanCloseHandle(self.0, std::ptr::null()) };
    }
}

/// A block allocated by the WLAN API, released with `WlanFreeMemory`.
struct WlanMem<T>(*mut T);

impl<T> Drop for WlanMem<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a WLAN API call that reported
            // success, and nothing else frees it.
            unsafe { WlanFreeMemory(self.0.cast()) };
        }
    }
}

/// The GUID of the first connected wireless interface, if any.
fn connected_interface(client: &WlanClient) -> Option<GUID> {
    let mut list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
    // SAFETY: `list` is an owned out-parameter, wrapped below so it is freed on
    // every path out of this function.
    let rc = unsafe { WlanEnumInterfaces(client.0, std::ptr::null(), &mut list) };
    if rc != ERROR_SUCCESS || list.is_null() {
        return None;
    }
    let owned = WlanMem(list);
    // SAFETY: the trailing [T; 1] is the usual Win32 placeholder for a
    // variable-length array; `dwNumberOfItems` entries follow contiguously.
    let items = unsafe {
        std::slice::from_raw_parts(
            (*owned.0).InterfaceInfo.as_ptr(),
            (*owned.0).dwNumberOfItems as usize,
        )
    };
    // A machine with no radio reports zero items rather than failing.
    items
        .iter()
        .find(|i| i.isState == wlan_interface_state_connected)
        .map(|i| i.InterfaceGuid)
}

/// The current connection's association attributes.
fn current_connection(client: &WlanClient, guid: &GUID) -> Option<WLAN_CONNECTION_ATTRIBUTES> {
    let mut size = 0u32;
    let mut data: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: out-parameters are owned locals; the returned block is freed by
    // the guard below.
    let rc = unsafe {
        WlanQueryInterface(
            client.0,
            guid,
            wlan_intf_opcode_current_connection,
            std::ptr::null(),
            &mut size,
            &mut data,
            std::ptr::null_mut(),
        )
    };
    if rc != ERROR_SUCCESS || data.is_null() {
        return None;
    }
    let owned = WlanMem(data.cast::<WLAN_CONNECTION_ATTRIBUTES>());
    if (size as usize) < std::mem::size_of::<WLAN_CONNECTION_ATTRIBUTES>() {
        return None;
    }
    // SAFETY: the pointer is non-null and the block is at least as large as the
    // struct, checked above. Copied out so the guard can free it here.
    Some(unsafe { *owned.0 })
}

/// Every BSS the radio can currently see, ours included.
///
/// Since Windows 10 1803 this needs Location services enabled and returns
/// `ERROR_ACCESS_DENIED` otherwise — the same shape of restriction macOS puts on
/// SSIDs. An empty list is the honest answer: `WifiInfo::congestion` reports a
/// total of zero rather than pretending the airspace is quiet.
fn bss_list(client: &WlanClient, guid: &GUID) -> Vec<BssEntry> {
    let mut list: *mut WLAN_BSS_LIST = std::ptr::null_mut();
    // SAFETY: a null SSID with `dot11_BSS_type_any` asks for everything;
    // `list` is an owned out-parameter freed by the guard below.
    let rc = unsafe {
        WlanGetNetworkBssList(
            client.0,
            guid,
            std::ptr::null(),
            dot11_BSS_type_any as DOT11_BSS_TYPE,
            0,
            std::ptr::null(),
            &mut list,
        )
    };
    if rc != ERROR_SUCCESS || list.is_null() {
        return Vec::new();
    }
    let owned = WlanMem(list);
    // SAFETY: variable-length trailing array, as with the interface list. The
    // entries are fixed-size and contiguous; the beacon IEs they refer to live
    // after the array and are not touched here.
    let entries = unsafe {
        std::slice::from_raw_parts(
            (*owned.0).wlanBssEntries.as_ptr(),
            (*owned.0).dwNumberOfItems as usize,
        )
    };
    // The beacon IEs of each entry live inside the same allocation, past the
    // entry array, at `ulIeOffset` bytes from the start of that entry. The
    // allocation's own size bounds the read, so a malformed offset from a
    // misbehaving driver yields an empty slice rather than a wild one.
    let list_base = owned.0.cast::<u8>();
    // SAFETY: the header has just been read through the same pointer.
    let list_size = unsafe { (*owned.0).dwTotalSize } as usize;
    entries
        .iter()
        .map(|e| {
            let entry_base = std::ptr::from_ref(e).cast::<u8>() as usize;
            let start = entry_base
                .wrapping_add(e.ulIeOffset as usize)
                .wrapping_sub(list_base as usize);
            let end = start.wrapping_add(e.ulIeSize as usize);
            let ies: &[u8] = if start <= end && end <= list_size {
                // SAFETY: `[start, end)` lies within the `list_size` bytes the
                // API wrote, checked above, and `owned` keeps them alive.
                unsafe { std::slice::from_raw_parts(list_base.add(start), end - start) }
            } else {
                &[]
            };
            BssEntry {
                bssid: e.dot11Bssid,
                rssi_dbm: e.lRssi,
                // The API reports kHz; everything else here speaks MHz.
                freq_mhz: e.ulChCenterFrequency / 1000,
                width_mhz: channel_width_mhz(ies),
            }
        })
        .collect()
}

/// The fields we take from a `WLAN_BSS_ENTRY`.
struct BssEntry {
    bssid: [u8; 6],
    rssi_dbm: i32,
    freq_mhz: u32,
    width_mhz: u16,
}

/// The channel width a BSS occupies, read from its beacon's information
/// elements. `ulChCenterFrequency` is the primary 20MHz channel and nothing
/// in the connection attributes says how many more are bonded to it, so this
/// walk is the only place the answer exists (issue #26).
///
/// Each generation describes the width in its own element and an access
/// point carries every element its clients might understand, so the widest
/// reading wins: HT Operation knows about 40MHz, VHT Operation about 80 and
/// 160, HE Operation carries the 6GHz band's own field, and EHT Operation
/// adds 320. Unknown or truncated elements are skipped, and a beacon that says
/// nothing is 20MHz — what every pre-802.11n network is.
fn channel_width_mhz(ies: &[u8]) -> u16 {
    const HT_OPERATION: u8 = 61;
    const VHT_OPERATION: u8 = 192;
    const EXTENSION: u8 = 255;
    const EXT_HE_OPERATION: u8 = 36;
    const EXT_EHT_OPERATION: u8 = 106;

    let mut width = 20u16;
    let mut at = 0usize;
    while at + 2 <= ies.len() {
        let (id, len) = (ies[at], ies[at + 1] as usize);
        let Some(body) = ies.get(at + 2..at + 2 + len) else {
            break; // truncated element: the rest cannot be trusted
        };
        at += 2 + len;

        let found = match id {
            // Primary channel, then HT Operation Information: bits 0-1 of
            // its first byte place the secondary channel (0 none, 1 above,
            // 3 below) and bit 2 allows the station to use it.
            HT_OPERATION if body.len() >= 2 => {
                let info = body[1];
                let secondary = info & 0b11;
                let wide = info & 0b100 != 0;
                if wide && (secondary == 1 || secondary == 3) {
                    40
                } else {
                    20
                }
            }
            // VHT Operation Information: channel width, then the centre
            // frequency of segment 0 and 1. Since 802.11-2016 width 1 covers
            // 80, 160 and 80+80 alike, told apart by segment 1: zero for a
            // single 80MHz block, otherwise a second block exists and the
            // network occupies 160MHz of spectrum, contiguous or not. 2 and
            // 3 are the deprecated explicit 160 and 80+80 encodings.
            VHT_OPERATION if body.len() >= 3 => match body[0] {
                1 if body[2] == 0 => 80,
                1..=3 => 160,
                _ => 0, // 0: 20 or 40, as HT Operation says
            },
            EXTENSION if !body.is_empty() => match body[0] {
                EXT_HE_OPERATION => he_width(&body[1..]),
                EXT_EHT_OPERATION => eht_width(&body[1..]),
                _ => 0,
            },
            _ => 0,
        };
        width = width.max(found);
    }
    width
}

/// HE Operation, after the extension ID: three bytes of parameters, BSS
/// colour, two bytes of basic MCS set, then optional fields in a fixed order
/// whose presence the parameter bits announce — VHT Operation Information
/// (bit 14, 3 bytes), Max Co-Hosted BSSID Indicator (bit 15, 1 byte), and
/// 6 GHz Operation Information (bit 17, 5 bytes). Only the last carries a
/// width, and only 6GHz networks carry it: on the other bands HE access
/// points describe their width through HT and VHT Operation as before.
fn he_width(body: &[u8]) -> u16 {
    if body.len() < 6 {
        return 0;
    }
    let params = u32::from_le_bytes([body[0], body[1], body[2], 0]);
    let vht_info_present = params & (1 << 14) != 0;
    let co_hosted_bss = params & (1 << 15) != 0;
    let six_ghz_present = params & (1 << 17) != 0;
    if !six_ghz_present {
        return 0;
    }
    let mut at = 6;
    if vht_info_present {
        at += 3;
    }
    if co_hosted_bss {
        at += 1;
    }
    // Primary channel, control, segment 0, segment 1, minimum rate. Bits 0-1
    // of control: 20, 40, 80, 160 (or 80+80).
    match body.get(at + 1).map(|control| control & 0b11) {
        Some(0) => 20,
        Some(1) => 40,
        Some(2) => 80,
        Some(3) => 160,
        _ => 0,
    }
}

/// EHT Operation, after the extension ID: one byte of parameters whose bit 0
/// says whether EHT Operation Information follows the four-byte basic MCS
/// set. Its control byte's bits 0-2 give the width: 20, 40, 80, 160, 320.
fn eht_width(body: &[u8]) -> u16 {
    if body.len() < 6 || body[0] & 1 == 0 {
        return 0;
    }
    match body.get(5).map(|control| control & 0b111) {
        Some(0) => 20,
        Some(1) => 40,
        Some(2) => 80,
        Some(3) => 160,
        Some(4) => 320,
        _ => 0,
    }
}

/// Map a centre frequency to (channel, band in GHz).
fn channel_from_freq(mhz: u32) -> Option<(u16, u16)> {
    match mhz {
        2412..=2484 => Some((((mhz - 2407) / 5) as u16, 2)),
        5000..=5895 => Some((((mhz - 5000) / 5) as u16, 5)),
        5955..=7115 => Some((((mhz - 5950) / 5) as u16, 6)),
        _ => None,
    }
}

/// Windows reports link quality as a 0–100 percentage rather than dBm. The
/// mapping is documented rather than guessed: 0 is -100 dBm, 100 is -50 dBm,
/// linear between. Only used when the exact `lRssi` is out of reach.
fn quality_to_dbm(quality: u32) -> i32 {
    -100 + (quality.min(100) / 2) as i32
}

fn phy_name(phy: DOT11_PHY_TYPE) -> String {
    match phy {
        p if p == dot11_phy_type_ht => "802.11n".to_string(),
        p if p == dot11_phy_type_vht => "802.11ac".to_string(),
        p if p == dot11_phy_type_he => "802.11ax".to_string(),
        p if p == dot11_phy_type_eht => "802.11be".to_string(),
        _ => String::new(),
    }
}

/// Live signal for the connected radio.
pub fn wifi_signal() -> Option<WifiSignal> {
    let client = WlanClient::open()?;
    let guid = connected_interface(&client)?;
    let conn = current_connection(&client, &guid)?;
    let assoc = conn.wlanAssociationAttributes;

    // Prefer the beacon's own dBm figure; fall back to the documented mapping
    // when the BSS list is unavailable, which is the usual case with Location
    // services off.
    let rssi_dbm = bss_list(&client, &guid)
        .iter()
        .find(|b| b.bssid == assoc.dot11Bssid)
        .map(|b| b.rssi_dbm)
        .unwrap_or_else(|| quality_to_dbm(assoc.wlanSignalQuality));

    Some(WifiSignal {
        rssi_dbm,
        // Windows measures no noise floor anywhere in the API.
        noise_dbm: None,
        // ulTxRate is in Kbps.
        tx_rate_mbps: assoc.ulTxRate as f64 / 1000.0,
    })
}

/// Wi-Fi details for the active connection.
pub async fn wifi_details() -> Option<WifiInfo> {
    // The whole sequence is blocking FFI, and the BSS scan in particular can
    // take a moment, so it is kept off the async worker threads.
    tokio::task::spawn_blocking(details_blocking).await.ok()?
}

fn details_blocking() -> Option<WifiInfo> {
    let client = WlanClient::open()?;
    let guid = connected_interface(&client)?;
    let conn = current_connection(&client, &guid)?;
    let assoc = conn.wlanAssociationAttributes;

    let ssid_len = (assoc.dot11Ssid.uSSIDLength as usize).min(assoc.dot11Ssid.ucSSID.len());
    let ssid = String::from_utf8_lossy(&assoc.dot11Ssid.ucSSID[..ssid_len]).to_string();

    let bss = bss_list(&client, &guid);
    let ours = bss.iter().find(|b| b.bssid == assoc.dot11Bssid);

    // The beacon frequency is unambiguous about the band. Without the BSS list
    // there is only a bare channel number, which is not: 6GHz channels are
    // numbered from 1 and collide with 2.4GHz.
    let channel = ours
        .and_then(|b| channel_from_freq(b.freq_mhz).map(|(ch, band)| (ch, band, b.width_mhz)))
        .map(|(ch, band, width)| format!("{ch} ({band}GHz, {width}MHz)"))
        .unwrap_or_default();

    let rssi = ours
        .map(|b| b.rssi_dbm)
        .unwrap_or_else(|| quality_to_dbm(assoc.wlanSignalQuality));

    Some(WifiInfo {
        ssid,
        phy: phy_name(assoc.dot11PhyType),
        channel,
        rssi: format!("{rssi} dBm"),
        tx_rate: format!("{:.0} Mbps", assoc.ulTxRate as f64 / 1000.0),
        neighbours: bss
            .iter()
            .filter_map(|b| {
                channel_from_freq(b.freq_mhz).map(|(channel, band_ghz)| Neighbour {
                    channel,
                    band_ghz,
                    width_mhz: b.width_mhz,
                })
            })
            .collect(),
    })
}

/// Power state via `GetSystemPowerStatus` (kernel32, unprivileged).
///
/// No thermal summary: Windows exposes no unprivileged equivalent of pmset's
/// "am I being held back" verdict. `CallNtPowerInformation` would report current
/// against maximum clock, but a modern CPU idles far below its maximum, so that
/// would read as permanently throttled. Battery saver is the one honest throttle
/// signal Windows does hand over, so it is the only one reported.
pub async fn thermal_state() -> Option<ThermalState> {
    use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};

    let mut status = SYSTEM_POWER_STATUS::default();
    // SAFETY: fills a caller-owned POD struct and touches nothing else.
    if unsafe { GetSystemPowerStatus(&mut status) } == 0 {
        return None;
    }
    let saver = status.SystemStatusFlag == 1;
    Some(ThermalState {
        summary: if saver {
            "battery saver on".to_string()
        } else {
            String::new()
        },
        throttled: saver,
        power_source: match status.ACLineStatus {
            0 => "Battery Power".to_string(),
            1 => "AC Power".to_string(),
            // 255 is "unknown", and saying nothing beats guessing.
            _ => String::new(),
        },
    })
}

/// The connection-specific DNS suffix of one adapter — DHCP option 15, the
/// Windows equivalent of a resolv.conf `search` domain. Asked of
/// `GetAdaptersAddresses` with every per-address list skipped, since only
/// the suffix is wanted; an error or an unknown index yields nothing.
pub fn dns_search_domains(iface_index: u32) -> Vec<String> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    // The API sizes its own buffer: ask, grow on overflow, ask again.
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u8> = vec![0; size as usize];
    loop {
        // SAFETY: `buf` is at least `size` bytes and outlives the call; the
        // API writes a linked list of adapters into it.
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut size,
            )
        };
        if rc == ERROR_BUFFER_OVERFLOW {
            buf.resize(size as usize, 0);
            continue;
        }
        if rc != ERROR_SUCCESS {
            return Vec::new();
        }
        break;
    }

    let mut out = Vec::new();
    let mut next = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !next.is_null() {
        // SAFETY: the list lives inside `buf`, which the API just filled; the
        // struct's union holds the index in its named form.
        let adapter = unsafe { &*next };
        let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        if index == iface_index && !adapter.DnsSuffix.is_null() {
            // SAFETY: DnsSuffix is a NUL-terminated wide string owned by the
            // buffer.
            let suffix = unsafe {
                let mut len = 0usize;
                while *adapter.DnsSuffix.add(len) != 0 {
                    len += 1;
                }
                String::from_utf16_lossy(std::slice::from_raw_parts(adapter.DnsSuffix, len))
            };
            let suffix = suffix.trim_end_matches('.').to_string();
            if !suffix.is_empty() {
                out.push(suffix);
            }
        }
        next = adapter.Next;
    }
    out
}

/// The DHCP server of one adapter's current v4 lease, from
/// `GetAdaptersAddresses` — absent (static config, expired lease, unknown
/// index) yields `None`.
pub fn dhcp_server(iface_index: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN};

    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    // The API sizes its own buffer: ask, grow on overflow, ask again.
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u8> = vec![0; size as usize];
    loop {
        // SAFETY: `buf` is at least `size` bytes and outlives the call; the
        // API writes a linked list of adapters into it.
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut size,
            )
        };
        if rc == ERROR_BUFFER_OVERFLOW {
            buf.resize(size as usize, 0);
            continue;
        }
        if rc != ERROR_SUCCESS {
            return None;
        }
        break;
    }

    let mut next = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !next.is_null() {
        // SAFETY: the list lives inside `buf`, which the API just filled; the
        // struct's union holds the index in its named form.
        let adapter = unsafe { &*next };
        let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        if index == iface_index {
            let sa = adapter.Dhcpv4Server.lpSockaddr;
            if sa.is_null() {
                return None;
            }
            // SAFETY: the sockaddr points into `buf`; the family is checked
            // before it is read as v4.
            unsafe {
                if (*sa).sa_family != AF_INET {
                    return None;
                }
                let sin = sa.cast::<SOCKADDR_IN>();
                // S_addr is in network byte order; its in-memory bytes are
                // already the four octets in printing order.
                let b = (*sin).sin_addr.S_un.S_addr.to_ne_bytes();
                let addr = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                return (!addr.is_unspecified()).then(|| addr.to_string());
            }
        }
        next = adapter.Next;
    }
    None
}

/// Whether the font this console window actually renders with contains every
/// glyph in `chars`. `None` when it cannot be asked — output is redirected,
/// there is no conhost window, or the font is a raster font (which
/// `GetGlyphIndicesW` cannot inspect and which lacks these glyphs anyway) —
/// so the caller keeps its pessimistic default.
///
/// This asks the *font*, not the console: conhost can sometimes rescue a
/// missing glyph through GDI font linking, so a `Some(false)` may still
/// render. Falling back to plainer glyphs in that case only costs looks.
pub fn console_font_has_glyphs(chars: &[char]) -> Option<bool> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Graphics::Gdi::{
        CLIP_DEFAULT_PRECIS, CreateCompatibleDC, CreateFontW, DEFAULT_CHARSET, DEFAULT_PITCH,
        DEFAULT_QUALITY, DeleteDC, DeleteObject, FW_NORMAL, GGI_MARK_NONEXISTING_GLYPHS,
        GetGlyphIndicesW, OUT_DEFAULT_PRECIS, SelectObject,
    };
    use windows_sys::Win32::System::Console::{
        CONSOLE_FONT_INFOEX, GetCurrentConsoleFontEx, GetStdHandle, STD_OUTPUT_HANDLE,
    };

    unsafe {
        let console = GetStdHandle(STD_OUTPUT_HANDLE);
        if console.is_null() || console == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut info = CONSOLE_FONT_INFOEX {
            cbSize: size_of::<CONSOLE_FONT_INFOEX>() as u32,
            ..Default::default()
        };
        if GetCurrentConsoleFontEx(console, 0, &mut info) == 0 {
            return None;
        }
        // Raster fonts report an empty or non-TrueType face; the glyph query
        // below would fail on them, so bail out to the pessimistic default.
        if info.FaceName[0] == 0 {
            return None;
        }

        let font = CreateFontW(
            0, // default height — coverage does not depend on size
            0,
            0,
            0,
            FW_NORMAL as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET as u32,
            OUT_DEFAULT_PRECIS as u32,
            CLIP_DEFAULT_PRECIS as u32,
            DEFAULT_QUALITY as u32,
            DEFAULT_PITCH as u32,
            info.FaceName.as_ptr(),
        );
        if font.is_null() {
            return None;
        }
        let dc = CreateCompatibleDC(std::ptr::null_mut());
        if dc.is_null() {
            DeleteObject(font);
            return None;
        }
        let previous = SelectObject(dc, font);

        // All probed glyphs sit in the BMP, so one code unit per char.
        let utf16: Vec<u16> = chars.iter().collect::<String>().encode_utf16().collect();
        let mut indices = vec![0u16; utf16.len()];
        let queried = GetGlyphIndicesW(
            dc,
            utf16.as_ptr(),
            utf16.len() as i32,
            indices.as_mut_ptr(),
            GGI_MARK_NONEXISTING_GLYPHS,
        );

        SelectObject(dc, previous);
        DeleteDC(dc);
        DeleteObject(font);

        if queried as i32 == -1 {
            return None; // GDI_ERROR — a non-TrueType font, most likely
        }
        // 0xffff is the "nonexisting" mark the flag asks for.
        Some(indices.iter().all(|&i| i != 0xffff))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_from_freq_maps_to_the_right_band() {
        assert_eq!(channel_from_freq(2412), Some((1, 2)));
        assert_eq!(channel_from_freq(2437), Some((6, 2)));
        assert_eq!(channel_from_freq(5180), Some((36, 5)));
        assert_eq!(channel_from_freq(5955), Some((1, 6)));
        // Junk, and the kHz figure the API actually returns — pinning that the
        // conversion to MHz happens before this is called.
        assert_eq!(channel_from_freq(1234), None);
        assert_eq!(channel_from_freq(2412000), None);
    }

    #[test]
    fn signal_quality_maps_to_the_documented_dbm_range() {
        assert_eq!(quality_to_dbm(0), -100);
        assert_eq!(quality_to_dbm(50), -75);
        assert_eq!(quality_to_dbm(100), -50);
        // The API promises 0..=100; a bad value must not read as a strong signal.
        assert_eq!(quality_to_dbm(255), -50);
    }

    #[test]
    fn phy_types_are_named_for_the_standard() {
        assert_eq!(phy_name(dot11_phy_type_ht), "802.11n");
        assert_eq!(phy_name(dot11_phy_type_he), "802.11ax");
        assert_eq!(phy_name(dot11_phy_type_eht), "802.11be");
        // Anything older is left blank rather than labelled wrongly.
        assert!(phy_name(0).is_empty());
    }

    #[test]
    fn the_channel_string_round_trips_through_the_shared_parser() {
        // The rest of octomon reads channels back out of this string, so the
        // format has to match what `app::parse_channel` expects.
        let (ch, band) = channel_from_freq(5180).unwrap();
        let info = WifiInfo {
            channel: format!("{ch} ({band}GHz, 20MHz)"),
            ..Default::default()
        };
        let spec = info.channel_spec().expect("channel parses back");
        assert_eq!(spec.channel, 36);
        assert_eq!(spec.band_ghz, 5);
        assert_eq!(spec.width_mhz, 20);
    }

    /// One information element: ID, length, body.
    fn ie(id: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![id, body.len() as u8];
        v.extend_from_slice(body);
        v
    }

    /// HT Operation for `primary` with the secondary channel placed by
    /// `offset` and the station allowed any width when `wide`.
    fn ht_operation(primary: u8, offset: u8, wide: bool) -> Vec<u8> {
        let mut body = vec![primary, offset | if wide { 0b100 } else { 0 }];
        body.resize(22, 0);
        ie(61, &body)
    }

    fn vht_operation(width: u8, seg0: u8, seg1: u8) -> Vec<u8> {
        ie(192, &[width, seg0, seg1, 0xff, 0xff])
    }

    #[test]
    fn a_beacon_without_width_elements_is_20mhz() {
        assert_eq!(channel_width_mhz(&[]), 20);
        // SSID and DS Parameter Set alone: an 802.11g network.
        let mut ies = ie(0, b"home");
        ies.extend(ie(3, &[6]));
        assert_eq!(channel_width_mhz(&ies), 20);
    }

    #[test]
    fn ht_operation_reports_40mhz_only_when_a_secondary_channel_is_in_use() {
        assert_eq!(channel_width_mhz(&ht_operation(36, 1, true)), 40);
        assert_eq!(channel_width_mhz(&ht_operation(40, 3, true)), 40);
        // No secondary channel, or one the station may not use.
        assert_eq!(channel_width_mhz(&ht_operation(1, 0, true)), 20);
        assert_eq!(channel_width_mhz(&ht_operation(36, 1, false)), 20);
    }

    #[test]
    fn vht_operation_reports_80_and_160() {
        // The reporter's network: channel 149 in an 80MHz block centred on
        // 155. Width 1 with no second segment is 80MHz — the proposal in
        // issue #26 read this value as 40.
        let mut ies = ht_operation(149, 1, true);
        ies.extend(vht_operation(1, 155, 0));
        assert_eq!(channel_width_mhz(&ies), 80);
        // Width 1 with a second segment eight channels away: 160MHz.
        let mut ies = ht_operation(36, 1, true);
        ies.extend(vht_operation(1, 42, 50));
        assert_eq!(channel_width_mhz(&ies), 160);
        // The deprecated explicit 160 and 80+80 encodings.
        assert_eq!(channel_width_mhz(&vht_operation(2, 50, 0)), 160);
        assert_eq!(channel_width_mhz(&vht_operation(3, 42, 106)), 160);
        // Width 0 defers to HT Operation.
        let mut ies = ht_operation(36, 1, true);
        ies.extend(vht_operation(0, 0, 0));
        assert_eq!(channel_width_mhz(&ies), 40);
        assert_eq!(channel_width_mhz(&vht_operation(0, 0, 0)), 20);
    }

    #[test]
    fn he_operation_width_comes_only_from_the_6ghz_field() {
        // HE Operation without 6GHz information says nothing about width;
        // the 5GHz HE network falls back to its VHT Operation.
        let he_5ghz = ie(255, &[36, 0x00, 0x40, 0x00, 1, 0xff, 0xff, 0, 0, 0]);
        let mut ies = vht_operation(1, 42, 0);
        ies.extend(he_5ghz.clone());
        assert_eq!(channel_width_mhz(&ies), 80);
        assert_eq!(channel_width_mhz(&he_5ghz), 20);

        // 6GHz: parameters with bit 17 set (byte 2 = 0x02), no VHT info, no
        // co-hosted BSS, then the 6 GHz Operation Information whose control
        // byte says 160MHz.
        let he_6ghz = ie(255, &[36, 0x00, 0x00, 0x02, 1, 0xff, 0xff, 37, 3, 47, 0, 0]);
        assert_eq!(channel_width_mhz(&he_6ghz), 160);

        // With both optional fields present before it, the 6GHz field moves
        // four bytes down: bits 14 and 15 set in byte 1 (0xc0), bit 17 in
        // byte 2.
        let he_6ghz_shifted = ie(
            255,
            &[
                36, 0x00, 0xc0, 0x02, 1, 0xff, 0xff, 1, 42, 0, 2, 5, 2, 39, 0, 0,
            ],
        );
        assert_eq!(channel_width_mhz(&he_6ghz_shifted), 80);

        // Truncated before the 6GHz field: ignored, not misread.
        let truncated = ie(255, &[36, 0x00, 0x00, 0x02, 1, 0xff, 0xff, 37]);
        assert_eq!(channel_width_mhz(&truncated), 20);
    }

    #[test]
    fn eht_operation_reports_320mhz() {
        // Parameters bit 0 set, four-byte MCS set, then control = 4 (320MHz).
        let eht = ie(255, &[106, 0x01, 0xff, 0xff, 0xff, 0xff, 4, 31, 0]);
        assert_eq!(channel_width_mhz(&eht), 320);
        // No operation information present: nothing to say.
        let eht_bare = ie(255, &[106, 0x00, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(channel_width_mhz(&eht_bare), 20);
        // The widest element wins when several describe the same network.
        let mut ies = ht_operation(1, 1, true);
        ies.extend(ie(255, &[106, 0x01, 0xff, 0xff, 0xff, 0xff, 3, 15, 0]));
        assert_eq!(channel_width_mhz(&ies), 160);
    }

    #[test]
    fn malformed_element_streams_are_cut_off_not_read_past() {
        // An element claiming more bytes than remain ends the walk, keeping
        // whatever came before it.
        let mut ies = ht_operation(36, 1, true);
        ies.extend([192, 50, 1, 42]);
        assert_eq!(channel_width_mhz(&ies), 40);
        // A lone ID with no length byte.
        assert_eq!(channel_width_mhz(&[61]), 20);
        // Elements too short for their type are skipped, not indexed.
        let mut ies = ie(61, &[36]);
        ies.extend(ie(192, &[1]));
        ies.extend(ie(255, &[]));
        ies.extend(ie(255, &[36, 1]));
        ies.extend(ie(255, &[106, 1]));
        assert_eq!(channel_width_mhz(&ies), 20);
    }
}
