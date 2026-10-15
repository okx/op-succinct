//! Confirmed-height stagnation tracker for the tz proposer.
//!
//! Tracks the confirmed chain height observed from `/chain/confirmed_block_info` and warns
//! when the height has not changed for longer than a configurable threshold. Warning repeats
//! on every observation after the threshold is exceeded.

use std::sync::Mutex;

use tokio::time::Instant;

/// Threshold used when the configured value is absent, empty or unparseable.
pub const DEFAULT_STAGNATION_THRESHOLD_SECS: u64 = 300;

/// Resolves the stagnation threshold from the raw value of
/// `TZ_CONFIRMED_HEIGHT_STAGNATION_THRESHOLD_SECS`.
///
/// Absent, empty and unparseable values all fall back to
/// [`DEFAULT_STAGNATION_THRESHOLD_SECS`]. A value of zero disables the tracker; it is a valid
/// configuration, not a fallback, so it is preserved.
pub fn parse_threshold_secs(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok()).unwrap_or(DEFAULT_STAGNATION_THRESHOLD_SECS)
}

/// Tracking state guarded by the tracker's own mutex.
struct TrackerState {
    last_observed_height: Option<u64>,
    observed_since: Option<Instant>,
}

/// Tracks the confirmed chain height and how long it has been unchanged.
///
/// [`ConfirmedHeightTracker::observe`] is called once per successful confirmed-height fetch.
/// The first call records the height, a change in either direction restarts the timer, and an
/// unchanged height held past the threshold logs a warning. The warning is not suppressed: it
/// is emitted again on every later observation while the height stays unchanged.
///
/// A threshold of zero disables the tracker, in which case no state is recorded at all.
pub struct ConfirmedHeightTracker {
    state: Mutex<TrackerState>,
    stagnation_threshold: std::time::Duration,
}

impl ConfirmedHeightTracker {
    /// Creates a tracker that warns once a height has been unchanged for `threshold_secs`.
    ///
    /// `threshold_secs == 0` disables it: `observe` returns immediately and records nothing.
    pub fn new(threshold_secs: u64) -> Self {
        Self {
            state: Mutex::new(TrackerState { last_observed_height: None, observed_since: None }),
            stagnation_threshold: std::time::Duration::from_secs(threshold_secs),
        }
    }

    /// Records a successfully observed confirmed height.
    ///
    /// Never call this for a failed read: an error carries no height, and inventing one would
    /// corrupt the staleness signal.
    pub fn observe(&self, height: u64) {
        if self.stagnation_threshold.is_zero() {
            return;
        }

        let mut state = self.state.lock().unwrap();
        match state.last_observed_height {
            None => {
                state.last_observed_height = Some(height);
                state.observed_since = Some(Instant::now());
            }
            Some(previous) if previous == height => {
                if let Some(since) = state.observed_since {
                    let elapsed = since.elapsed();
                    if elapsed >= self.stagnation_threshold {
                        tracing::warn!(
                            "tz_confirmed_height_stagnation: confirmed height {} unchanged for {}s (threshold {}s)",
                            height,
                            elapsed.as_secs(),
                            self.stagnation_threshold.as_secs(),
                        );
                    }
                }
            }
            Some(_) => {
                state.last_observed_height = Some(height);
                state.observed_since = Some(Instant::now());
            }
        }
    }

    /// The most recently observed confirmed height, or `None` before the first observation and
    /// for as long as the tracker is disabled.
    #[cfg(test)]
    pub(crate) fn last_observed_height(&self) -> Option<u64> {
        self.state.lock().unwrap().last_observed_height
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};

    /// Records the message of every WARN event emitted while the returned guard is alive.
    #[derive(Clone, Default)]
    pub(crate) struct WarnCapture {
        messages: Arc<Mutex<Vec<String>>>,
    }

    impl WarnCapture {
        pub(crate) fn messages(&self) -> Vec<String> {
            self.messages.lock().unwrap().clone()
        }

        pub(crate) fn warn_count(&self) -> usize {
            self.messages.lock().unwrap().len()
        }
    }

    struct MessageVisitor(String);

    impl Visit for MessageVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                let mut visitor = MessageVisitor(String::new());
                event.record(&mut visitor);
                self.messages.lock().unwrap().push(visitor.0);
            }
        }
    }

    /// Installs a thread-local subscriber that captures WARN messages. Held guard keeps the
    /// subscriber installed; dropping it restores the previous one.
    pub(crate) fn capture_warns() -> (WarnCapture, tracing::subscriber::DefaultGuard) {
        use tracing_subscriber::layer::SubscriberExt;

        let capture = WarnCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let guard = tracing::subscriber::set_default(subscriber);
        (capture, guard)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::capture_warns;
    use super::*;
    use tokio::time::Duration;

    // T1: First sample — height recorded, no warning.
    #[tokio::test(start_paused = true)]
    async fn first_sample_records_height_no_warn() {
        let (capture, _guard) = capture_warns();
        let tracker = ConfirmedHeightTracker::new(10);

        tracker.observe(100);

        let state = tracker.state.lock().unwrap();
        assert_eq!(state.last_observed_height, Some(100));
        let since = state.observed_since.expect("observed_since set on first sample");
        assert!(since.elapsed() < Duration::from_millis(1));
        drop(state);
        assert_eq!(capture.warn_count(), 0);
    }

    // T2: Same height, before threshold — no warning.
    #[tokio::test(start_paused = true)]
    async fn same_height_before_threshold_no_warn() {
        let (capture, _guard) = capture_warns();
        let tracker = ConfirmedHeightTracker::new(10);

        tracker.observe(100);
        tokio::time::advance(Duration::from_secs(5)).await;
        tracker.observe(100);

        assert_eq!(capture.warn_count(), 0);
    }

    // T3: Same height, exactly at threshold — one warning.
    #[tokio::test(start_paused = true)]
    async fn same_height_at_threshold_warns_once() {
        let (capture, _guard) = capture_warns();
        let tracker = ConfirmedHeightTracker::new(10);

        tracker.observe(100);
        tokio::time::advance(Duration::from_secs(10)).await;
        tracker.observe(100);

        let messages = capture.messages();
        assert_eq!(messages.len(), 1);
        assert!(
            messages[0].contains("confirmed height 100 unchanged for 10s (threshold 10s)"),
            "unexpected message: {}",
            messages[0]
        );
        assert!(
            messages[0].contains("tz_confirmed_height_stagnation"),
            "unexpected message: {}",
            messages[0]
        );
    }

    // T4: Same height, after threshold — the warning repeats on the next observation.
    #[tokio::test(start_paused = true)]
    async fn same_height_after_threshold_repeats_warning() {
        let (capture, _guard) = capture_warns();
        let tracker = ConfirmedHeightTracker::new(10);

        tracker.observe(100);
        tokio::time::advance(Duration::from_secs(20)).await;
        tracker.observe(100);
        tracker.observe(100);

        let messages = capture.messages();
        assert_eq!(messages.len(), 2);
        assert!(messages[0].contains("confirmed height 100 unchanged for 20s"));
        assert!(messages[1].contains("confirmed height 100 unchanged for 20s"));
    }

    // T5: Height increase resets the timer.
    #[tokio::test(start_paused = true)]
    async fn height_increase_resets_timer() {
        let (capture, _guard) = capture_warns();
        let tracker = ConfirmedHeightTracker::new(10);

        tracker.observe(100);
        tokio::time::advance(Duration::from_secs(5)).await;
        tracker.observe(200);

        assert_eq!(capture.warn_count(), 0);
        let state = tracker.state.lock().unwrap();
        assert_eq!(state.last_observed_height, Some(200));
        assert!(state.observed_since.expect("reset on change").elapsed() < Duration::from_millis(1));
    }

    // T6: Height decrease (reorg) resets the timer.
    #[tokio::test(start_paused = true)]
    async fn height_decrease_resets_timer() {
        let (capture, _guard) = capture_warns();
        let tracker = ConfirmedHeightTracker::new(10);

        tracker.observe(200);
        tokio::time::advance(Duration::from_secs(5)).await;
        tracker.observe(150);
        tokio::time::advance(Duration::from_secs(9)).await;
        tracker.observe(150);

        assert_eq!(capture.warn_count(), 0);
        let state = tracker.state.lock().unwrap();
        assert_eq!(state.last_observed_height, Some(150));
        assert!(state.observed_since.expect("reset on reorg").elapsed() < Duration::from_secs(10));
    }

    // T7: Threshold zero disables the tracker entirely — no state, no warning.
    #[tokio::test(start_paused = true)]
    async fn disabled_threshold_zero_noops() {
        let (capture, _guard) = capture_warns();
        let tracker = ConfirmedHeightTracker::new(0);

        tracker.observe(100);
        tokio::time::advance(Duration::from_secs(30)).await;
        tracker.observe(100);

        assert_eq!(capture.warn_count(), 0);
        let state = tracker.state.lock().unwrap();
        assert_eq!(state.last_observed_height, None);
        assert!(state.observed_since.is_none());
    }

    // T8: Threshold parsing — absent, empty and unparseable fall back to the default.
    #[test]
    fn parse_threshold_defaults() {
        assert_eq!(parse_threshold_secs(None), 300);
        assert_eq!(parse_threshold_secs(Some("")), 300);
        assert_eq!(parse_threshold_secs(Some("abc")), 300);
        assert_eq!(parse_threshold_secs(Some("-1")), 300);
        assert_eq!(parse_threshold_secs(Some("0")), 0);
        assert_eq!(parse_threshold_secs(Some("60")), 60);
    }

    // T9: Three observations after the threshold produce three warnings.
    #[tokio::test(start_paused = true)]
    async fn multiple_warnings_on_repeated_observations() {
        let (capture, _guard) = capture_warns();
        let tracker = ConfirmedHeightTracker::new(10);

        tracker.observe(100);
        tokio::time::advance(Duration::from_secs(30)).await;
        tracker.observe(100);
        tracker.observe(100);
        tracker.observe(100);

        assert_eq!(capture.warn_count(), 3);
    }

    // T10: Rapid height changes reset each time — no warning.
    #[tokio::test(start_paused = true)]
    async fn rapid_height_changes_no_warn() {
        let (capture, _guard) = capture_warns();
        let tracker = ConfirmedHeightTracker::new(10);

        tracker.observe(100);
        tracker.observe(101);
        tracker.observe(102);

        assert_eq!(capture.warn_count(), 0);
        let state = tracker.state.lock().unwrap();
        assert_eq!(state.last_observed_height, Some(102));
    }
}