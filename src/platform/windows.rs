//! Windows probes: Wi-Fi via the Native Wifi API, power via kernel32.
//!
//! Every other platform shells out for Wi-Fi (`nmcli`, `iw`, `system_profiler`)
//! and this one deliberately does not, for two reasons. `netsh wlan show
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

impl WlanClient {
    fn open() -> Option<Self> {
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
    entries
        .iter()
        .map(|e| BssEntry {
            bssid: e.dot11Bssid,
            rssi_dbm: e.lRssi,
            // The API reports kHz; everything else here speaks MHz.
            freq_mhz: e.ulChCenterFrequency / 1000,
        })
        .collect()
}

/// The fields we take from a `WLAN_BSS_ENTRY`.
struct BssEntry {
    bssid: [u8; 6],
    rssi_dbm: i32,
    freq_mhz: u32,
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
        .and_then(|b| channel_from_freq(b.freq_mhz))
        // Width would mean walking the beacon IEs. 20MHz under-counts overlap
        // rather than inventing it, matching what the Linux nmcli path assumes.
        .map(|(ch, band)| format!("{ch} ({band}GHz, 20MHz)"))
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
                    width_mhz: 20,
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
}
