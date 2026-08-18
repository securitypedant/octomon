//! Background collectors. Each runs as an independent async task on its own
//! cadence and writes into the shared [`crate::app::AppState`]. Critical sections
//! never span an `.await`.

pub mod discovery;
pub mod dns;
pub mod hopmon;
pub mod http;
pub mod logger;
pub mod ndt7;
pub mod netinfo;
pub mod ping;
pub mod procbw;
pub mod resolve;
pub mod signal;
pub mod speedtest;
pub mod throughput;
pub mod traceroute;
pub mod vitals;
pub mod web;
pub mod whois;
pub mod wifi;
