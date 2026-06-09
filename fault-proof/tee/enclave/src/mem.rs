//! Process-level memory sampling for the enclave.
//!
//! `PeakTracker` polls `/proc/self/status` on a fixed interval and keeps the
//! maximum observed `VmRSS` in an atomic. Spawn one per task to capture the
//! task's memory peak across deserialize → kona replay → signing.
//!
//! Caveat: `VmRSS` is process-wide. If `MAX_INFLIGHT_TASKS > 1`, concurrent
//! tasks share the sampler — set inflight to 1 when profiling per-task peak.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

fn read_status_kb(key: &str) -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

pub fn vm_rss_kb() -> u64 {
    read_status_kb("VmRSS:")
}

pub fn vm_hwm_kb() -> u64 {
    read_status_kb("VmHWM:")
}

/// Ask glibc to release as much unused heap arena back to the OS as it can.
/// On Linux/glibc, free()'d memory often stays in process-private arenas; this
/// forces a sweep. No-op on non-Linux. Use after each task completes to test
/// whether observed RSS growth is allocator caching vs a real leak.
pub fn trim_malloc() {
    #[cfg(target_os = "linux")]
    unsafe {
        // glibc-specific. Safe to call even on musl: libc crate exposes a stub.
        libc::malloc_trim(0);
    }
}

pub struct PeakTracker {
    peak_kb: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl PeakTracker {
    pub fn start(interval_ms: u64) -> Self {
        let peak_kb = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let p = Arc::clone(&peak_kb);
        let s = Arc::clone(&stop);
        tokio::spawn(async move {
            while !s.load(Ordering::Relaxed) {
                let rss = vm_rss_kb();
                p.fetch_max(rss, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            }
        });

        Self { peak_kb, stop }
    }

    /// Stop the sampler, take one final reading, return the peak in KiB.
    pub fn finish(self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        let last = vm_rss_kb();
        self.peak_kb.fetch_max(last, Ordering::Relaxed);
        self.peak_kb.load(Ordering::Relaxed)
    }
}
