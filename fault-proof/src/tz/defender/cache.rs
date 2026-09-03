//! Bounded LRU proof cache keyed by `(leaf_hash, withdrawal_root)` (spec §7.4).
//!
//! A cache hit still requires the caller to re-check on-chain status + deadline before
//! submitting (the cache never authorizes a send on its own). The cache is in-memory only and is
//! intentionally NOT persisted — restart recovery is driven by event rescan, not cached proofs.
//!
//! Hand-rolled (no external `lru` dependency) to keep the Defender self-contained: a `HashMap`
//! for O(1) lookup plus a `VecDeque` recency list. Capacity 0 disables caching.

use std::collections::{HashMap, VecDeque};

use alloy_primitives::B256;

use crate::tz::withdraw::types::HistoricalInclusionProof;

/// LRU key: the exact `(leaf_hash, withdrawal_root)` a verified proof is bound to.
pub type ProofKey = (B256, B256);

/// A bounded LRU cache of verified inclusion proofs.
pub struct ProofCache {
    capacity: usize,
    map: HashMap<ProofKey, HistoricalInclusionProof>,
    recency: VecDeque<ProofKey>,
}

impl ProofCache {
    pub fn new(capacity: usize) -> Self {
        Self { capacity, map: HashMap::new(), recency: VecDeque::new() }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Look up a verified proof, marking it most-recently-used on a hit.
    pub fn get(&mut self, key: &ProofKey) -> Option<HistoricalInclusionProof> {
        if let Some(proof) = self.map.get(key).cloned() {
            self.touch(key);
            Some(proof)
        } else {
            None
        }
    }

    /// Insert a verified proof, evicting the least-recently-used entry at capacity.
    pub fn put(&mut self, key: ProofKey, proof: HistoricalInclusionProof) {
        if self.capacity == 0 {
            return;
        }
        if self.map.insert(key, proof).is_some() {
            self.touch(&key);
            return;
        }
        self.recency.push_back(key);
        while self.map.len() > self.capacity {
            if let Some(evict) = self.recency.pop_front() {
                // Skip stale recency entries (a key touched after insert appears twice).
                if !self.map.contains_key(&evict) {
                    continue;
                }
                self.map.remove(&evict);
            } else {
                break;
            }
        }
    }

    fn touch(&mut self, key: &ProofKey) {
        if let Some(pos) = self.recency.iter().position(|k| k == key) {
            self.recency.remove(pos);
        }
        self.recency.push_back(*key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tz::withdraw::types::WithdrawRecord;
    use alloy_primitives::{Address, B256};

    fn proof(root: B256) -> HistoricalInclusionProof {
        HistoricalInclusionProof {
            record: WithdrawRecord {
                version: 1,
                chain_id: 196,
                transaction_hash: B256::ZERO,
                token_type: 0,
                token_address: Address::ZERO,
                token_ids: vec![],
                amounts: vec![],
                from: Address::ZERO,
                to: Address::ZERO,
            },
            record_hash: B256::ZERO,
            leaf_hash: B256::ZERO,
            canonical_block_height: 1,
            checkpoint_height: 2,
            withdrawal_root: root,
            leaf_index: 0,
            count: 1,
            siblings: [B256::ZERO; 32],
        }
    }

    fn key(a: u8, b: u8) -> ProofKey {
        (B256::repeat_byte(a), B256::repeat_byte(b))
    }

    #[test]
    fn hit_and_miss() {
        let mut c = ProofCache::new(2);
        let k = key(1, 2);
        assert!(c.get(&k).is_none());
        c.put(k, proof(B256::repeat_byte(2)));
        assert!(c.get(&k).is_some());
        // A different withdrawal_root ⇒ different key ⇒ miss (spec §9 item 9).
        assert!(c.get(&key(1, 3)).is_none());
    }

    #[test]
    fn evicts_least_recently_used_at_capacity() {
        let mut c = ProofCache::new(2);
        let (k1, k2, k3) = (key(1, 1), key(2, 2), key(3, 3));
        c.put(k1, proof(B256::repeat_byte(1)));
        c.put(k2, proof(B256::repeat_byte(2)));
        // Touch k1 so k2 becomes LRU.
        assert!(c.get(&k1).is_some());
        c.put(k3, proof(B256::repeat_byte(3)));
        assert_eq!(c.len(), 2);
        assert!(c.get(&k2).is_none(), "k2 should have been evicted");
        assert!(c.get(&k1).is_some());
        assert!(c.get(&k3).is_some());
    }

    #[test]
    fn zero_capacity_disables_cache() {
        let mut c = ProofCache::new(0);
        c.put(key(1, 1), proof(B256::ZERO));
        assert!(c.is_empty());
    }
}
