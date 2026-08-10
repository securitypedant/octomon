//! Background collectors. Each runs as an independent async task on its own
//! cadence and writes into the shared [`crate::app::AppState`]. Critical sections
//! never span an `.await`.

pub mod discovery;
pub mod ndt7;
pub mod netinfo;
pub mod ping;
pub mod procbw;
pub mod signal;
pub mod speedtest;
pub mod throughput;
pub mod traceroute;
pub mod vitals;
pub mod wifi;
