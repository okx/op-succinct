//! TTL-based eviction loop for the task manager.
//!
//! Wakes every 60 seconds, calls `TaskManager::gc_tick` which scans terminal
//! tasks and removes any whose `end_time_ms` is older than `ttl_ms`. Designed
//! to run forever as a tokio task; `main` shuts it down with `tokio::signal`.

use std::sync::Arc;
use std::time::Duration;

use tokio::time;
use tracing::debug;

use crate::task_manager::TaskManager;

/// Sweep interval. Picked at 60s as a compromise between responsiveness of
/// freeing memory and not adding lock contention on the task map.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

pub async fn run_gc_loop(mgr: Arc<TaskManager>) {
    let mut ticker = time::interval(SWEEP_INTERVAL);
    // Skip the first immediate tick fired by `tokio::time::interval`.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        debug!("TaskManager GC tick");
        mgr.gc_tick().await;
    }
}
