//! Process memory sampling for xlayer-tee-host.
//!
//! Two outputs:
//! 1. `run_rss_logger(interval_secs)` — spawned at startup, logs current and
//!    peak VmRSS every N seconds. Lets you see the long-term RSS curve.
//! 2. `vm_rss_kb()` — synchronous one-shot, used inside per-request handlers
//!    so each big request prints its memory delta.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static PEAK_RSS_KB: AtomicU64 = AtomicU64::new(0);

fn read_status_kb(key: &str) -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

pub fn vm_rss_kb() -> u64 {
    let rss = read_status_kb("VmRSS:");
    PEAK_RSS_KB.fetch_max(rss, Ordering::Relaxed);
    rss
}

pub fn vm_hwm_kb() -> u64 {
    read_status_kb("VmHWM:")
}

pub fn peak_rss_kb() -> u64 {
    PEAK_RSS_KB.load(Ordering::Relaxed)
}

/// Spawn a periodic logger. Returns immediately.
///
/// Logs `host memory snapshot` every `interval_secs` with current and peak RSS.
/// `interval_secs = 0` disables the logger.
pub fn spawn_rss_logger(interval_secs: u64) {
    if interval_secs == 0 {
        tracing::info!("host memory logger disabled (interval=0)");
        return;
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.tick().await; // first tick fires immediately, skip
        loop {
            ticker.tick().await;
            let rss = vm_rss_kb();
            let hwm = vm_hwm_kb();
            let peak = peak_rss_kb();
            tracing::info!(
                rss_mib = rss / 1024,
                hwm_mib = hwm / 1024,
                peak_sampled_mib = peak / 1024,
                "host memory snapshot",
            );
        }
    });
}
