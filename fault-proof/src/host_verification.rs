use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use std::sync::Arc;

use alloy_primitives::U256;

/// Check if the host verification gate allows game creation.
///
/// When `enable_host_verification` is true, game creation is gated on the
/// `last_verified_l2_block` being at or past the proposal target. When false,
/// this function is not called (the original finalized-block path is used instead).
pub fn verification_gate_allows_proposal(
    last_verified_l2_block: &AtomicU64,
    next_l2_block_number_for_proposal: U256,
) -> bool {
    let last_verified = last_verified_l2_block.load(Ordering::Relaxed);
    U256::from(last_verified) >= next_l2_block_number_for_proposal
}

/// Compute chunk boundaries for a verification range.
///
/// Returns a list of (start, end) pairs covering `[range_start, range_end)`.
pub fn compute_chunks(range_start: u64, range_end: u64, chunk_size: u64) -> Vec<(u64, u64)> {
    if range_start >= range_end || chunk_size == 0 {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    let mut cursor = range_start;
    while cursor < range_end {
        let chunk_end = (cursor + chunk_size).min(range_end);
        chunks.push((cursor, chunk_end));
        cursor = chunk_end;
    }
    chunks
}

/// Determine whether the baseline should snap forward to canonical_head.
///
/// Returns `Some(canonical_head)` if a snap is needed, `None` otherwise.
pub fn should_snap_baseline(current: u64, canonical_head: u64) -> Option<u64> {
    if current < canonical_head {
        Some(canonical_head)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod verification_gate {
        use super::*;

        #[test]
        fn blocks_when_verified_below_target() {
            let last_verified = AtomicU64::new(500);
            let target = U256::from(2800);
            assert!(!verification_gate_allows_proposal(&last_verified, target));
        }

        #[test]
        fn allows_when_verified_above_target() {
            let last_verified = AtomicU64::new(3000);
            let target = U256::from(2800);
            assert!(verification_gate_allows_proposal(&last_verified, target));
        }

        #[test]
        fn allows_when_verified_equals_target() {
            let last_verified = AtomicU64::new(2800);
            let target = U256::from(2800);
            assert!(verification_gate_allows_proposal(&last_verified, target));
        }

        #[test]
        fn blocks_when_verified_is_zero() {
            let last_verified = AtomicU64::new(0);
            let target = U256::from(600);
            assert!(!verification_gate_allows_proposal(&last_verified, target));
        }
    }

    mod chunking {
        use super::*;

        #[test]
        fn single_chunk_within_size() {
            let chunks = compute_chunks(100, 400, 300);
            assert_eq!(chunks, vec![(100, 400)]);
        }

        #[test]
        fn multi_chunk_range() {
            let chunks = compute_chunks(100, 800, 300);
            assert_eq!(chunks, vec![(100, 400), (400, 700), (700, 800)]);
        }

        #[test]
        fn exact_chunk_boundary() {
            let chunks = compute_chunks(0, 600, 300);
            assert_eq!(chunks, vec![(0, 300), (300, 600)]);
        }

        #[test]
        fn empty_range_returns_empty() {
            let chunks = compute_chunks(500, 500, 300);
            assert_eq!(chunks, Vec::<(u64, u64)>::new());
        }

        #[test]
        fn reversed_range_returns_empty() {
            let chunks = compute_chunks(800, 100, 300);
            assert_eq!(chunks, Vec::<(u64, u64)>::new());
        }

        #[test]
        fn zero_chunk_size_returns_empty() {
            let chunks = compute_chunks(100, 800, 0);
            assert_eq!(chunks, Vec::<(u64, u64)>::new());
        }

        #[test]
        fn single_block_range() {
            let chunks = compute_chunks(100, 101, 300);
            assert_eq!(chunks, vec![(100, 101)]);
        }

        #[test]
        fn large_chunk_size_caps_at_end() {
            let chunks = compute_chunks(100, 200, 1000);
            assert_eq!(chunks, vec![(100, 200)]);
        }
    }

    mod baseline_snap {
        use super::*;

        #[test]
        fn snaps_forward_on_cold_start() {
            assert_eq!(should_snap_baseline(0, 1000), Some(1000));
        }

        #[test]
        fn no_snap_when_ahead() {
            assert_eq!(should_snap_baseline(1000, 900), None);
        }

        #[test]
        fn no_snap_when_equal() {
            assert_eq!(should_snap_baseline(500, 500), None);
        }

        #[test]
        fn snaps_when_slightly_behind() {
            assert_eq!(should_snap_baseline(999, 1000), Some(1000));
        }
    }

    mod atomic_state {
        use super::*;

        #[test]
        fn arc_atomic_shared_between_reader_and_writer() {
            let shared = Arc::new(AtomicU64::new(100));
            let writer = shared.clone();

            writer.store(500, Ordering::Relaxed);

            assert_eq!(shared.load(Ordering::Relaxed), 500);
            assert!(verification_gate_allows_proposal(&shared, U256::from(500)));
            assert!(!verification_gate_allows_proposal(&shared, U256::from(501)));
        }

        #[test]
        fn monotonic_advance_per_chunk() {
            let last_verified = Arc::new(AtomicU64::new(100));
            let chunks = compute_chunks(100, 800, 300);

            for (_, chunk_end) in &chunks {
                last_verified.store(*chunk_end, Ordering::Relaxed);
            }

            assert_eq!(last_verified.load(Ordering::Relaxed), 800);
        }
    }
}
