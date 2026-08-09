//! Background collectors. Each runs as an independent async task on its own
//! cadence and writes into the shared [`crate::app::AppState`]. Critical sections
//! never span an `.await`.

pub mod netinfo;
pub mod ping;
pub mod throughput;
pub mod vitals;
