use std::{
    collections::HashMap,
    sync::{Mutex, RwLock},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use tokio_util::sync::CancellationToken;

use crate::config::ServerConfig;

#[derive(Debug)]
pub enum TaskStatus {
    Running(String),
    Finished { proof_bytes: Vec<u8> },
    Failed { message: String },
    Cancelled,
}

impl TaskStatus {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Running(_))
    }
}

#[derive(Debug, Clone, Default)]
pub struct TaskMetadata {
    pub start_blk_height: Option<u64>,
    pub end_blk_height: Option<u64>,
    pub claimed_output_root: Option<String>,
}

pub struct TaskEntry {
    pub task_id: String,
    pub status: TaskStatus,
    pub witness_hash: B256,
    pub witness_size_bytes: usize,
    pub submitted_to_enclave: bool,
    pub metadata: TaskMetadata,
    pub created_at: Instant,
    pub terminal_time: Option<Instant>,
    pub cancel_token: CancellationToken,
}

struct DedupEntry {
    task_id: String,
    expires_at: Instant,
}

pub struct TaskManager {
    tasks: RwLock<HashMap<String, TaskEntry>>,
    dedup: Mutex<HashMap<B256, DedupEntry>>,
    config: ServerConfig,
}

pub struct RegisterResult {
    pub task_id: String,
    pub already_existed: bool,
}

impl TaskManager {
    pub fn new(config: ServerConfig) -> Self {
        Self { tasks: RwLock::new(HashMap::new()), dedup: Mutex::new(HashMap::new()), config }
    }

    pub fn register(
        &self,
        hash: B256,
        witness_size: usize,
        metadata: TaskMetadata,
    ) -> RegisterResult {
        let mut dedup = self.dedup.lock().expect("dedup lock poisoned");
        if let Some(entry) = dedup.get(&hash) {
            if entry.expires_at > Instant::now() {
                return RegisterResult { task_id: entry.task_id.clone(), already_existed: true };
            }
            dedup.remove(&hash);
        }
        let task_id = uuid::Uuid::new_v4().to_string();
        dedup.insert(
            hash,
            DedupEntry {
                task_id: task_id.clone(),
                expires_at: Instant::now() + Duration::from_secs(self.config.dedup_ttl_secs),
            },
        );
        drop(dedup);

        let entry = TaskEntry {
            task_id: task_id.clone(),
            status: TaskStatus::Running("submitting to enclave".into()),
            witness_hash: hash,
            witness_size_bytes: witness_size,
            submitted_to_enclave: false,
            metadata,
            created_at: Instant::now(),
            terminal_time: None,
            cancel_token: CancellationToken::new(),
        };
        self.tasks.write().expect("tasks write lock").insert(task_id.clone(), entry);
        RegisterResult { task_id, already_existed: false }
    }

    pub fn get_cancel_token(&self, task_id: &str) -> Option<CancellationToken> {
        self.tasks.read().expect("tasks read lock").get(task_id).map(|e| e.cancel_token.clone())
    }

    pub fn set_submitted(&self, task_id: &str, message: &str) {
        if let Some(entry) = self.tasks.write().expect("tasks write lock").get_mut(task_id) {
            entry.submitted_to_enclave = true;
            entry.status = TaskStatus::Running(message.into());
        }
    }

    pub fn set_progress(&self, task_id: &str, message: &str) {
        if let Some(entry) = self.tasks.write().expect("tasks write lock").get_mut(task_id) {
            if !entry.status.is_terminal() {
                entry.status = TaskStatus::Running(message.into());
            }
        }
    }

    pub fn set_finished(&self, task_id: &str, proof_bytes: Vec<u8>) {
        let mut tasks = self.tasks.write().expect("tasks write lock");
        if let Some(entry) = tasks.get_mut(task_id) {
            let witness_hash = entry.witness_hash;
            entry.status = TaskStatus::Finished { proof_bytes };
            entry.terminal_time = Some(Instant::now());
            let mut dedup = self.dedup.lock().expect("dedup lock");
            if let Some(de) = dedup.get_mut(&witness_hash) {
                de.expires_at =
                    Instant::now() + Duration::from_secs(self.config.task_retention_secs);
            }
        }
    }

    pub fn set_failed(&self, task_id: &str, message: &str) {
        let mut tasks = self.tasks.write().expect("tasks write lock");
        if let Some(entry) = tasks.get_mut(task_id) {
            let witness_hash = entry.witness_hash;
            entry.status = TaskStatus::Failed { message: message.into() };
            entry.terminal_time = Some(Instant::now());
            self.dedup.lock().expect("dedup lock").remove(&witness_hash);
        }
    }

    pub fn set_cancelled(&self, task_id: &str) {
        let mut tasks = self.tasks.write().expect("tasks write lock");
        if let Some(entry) = tasks.get_mut(task_id) {
            let witness_hash = entry.witness_hash;
            if !entry.status.is_terminal() {
                entry.status = TaskStatus::Cancelled;
                entry.terminal_time = Some(Instant::now());
            }
            entry.cancel_token.cancel();
            self.dedup.lock().expect("dedup lock").remove(&witness_hash);
        }
    }

    pub fn remove_task(&self, task_id: &str) {
        let mut tasks = self.tasks.write().expect("tasks write lock");
        if let Some(entry) = tasks.remove(task_id) {
            self.dedup.lock().expect("dedup lock").remove(&entry.witness_hash);
        }
    }

    pub fn is_submitted(&self, task_id: &str) -> bool {
        self.tasks
            .read()
            .expect("tasks read lock")
            .get(task_id)
            .is_some_and(|e| e.submitted_to_enclave)
    }

    pub fn non_terminal_task_ids(&self) -> Vec<String> {
        self.tasks
            .read()
            .expect("tasks read lock")
            .iter()
            .filter(|(_, e)| !e.status.is_terminal())
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn with_task<F, R>(&self, task_id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&TaskEntry) -> R,
    {
        self.tasks.read().expect("tasks read lock").get(task_id).map(f)
    }

    pub fn contains(&self, task_id: &str) -> bool {
        self.tasks.read().expect("tasks read lock").contains_key(task_id)
    }

    pub fn task_count(&self) -> usize {
        self.tasks.read().expect("tasks read lock").len()
    }

    pub fn sweep(&self) {
        let retention = Duration::from_secs(self.config.task_retention_secs);
        let now = Instant::now();
        let mut tasks = self.tasks.write().expect("tasks write lock");
        let mut dedup = self.dedup.lock().expect("dedup lock");

        let expired_ids: Vec<String> = tasks
            .iter()
            .filter(|(_, e)| {
                e.status.is_terminal() &&
                    e.terminal_time.is_some_and(|t| now.duration_since(t) > retention)
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in &expired_ids {
            if let Some(entry) = tasks.remove(id) {
                dedup.remove(&entry.witness_hash);
            }
        }
        dedup.retain(|_, entry| entry.expires_at > now && tasks.contains_key(&entry.task_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    fn test_config() -> ServerConfig {
        ServerConfig {
            bind_addr: "127.0.0.1:8080".into(),
            task_retention_secs: 3600,
            dedup_ttl_secs: 300,
            monitor_interval_secs: 30,
        }
    }

    fn test_config_short_ttl() -> ServerConfig {
        ServerConfig {
            bind_addr: "127.0.0.1:8080".into(),
            task_retention_secs: 1,
            dedup_ttl_secs: 1,
            monitor_interval_secs: 30,
        }
    }

    #[test]
    fn register_new_task_returns_unique_id() {
        let mgr = TaskManager::new(test_config());
        let result = mgr.register(keccak256(b"w1"), 1024, TaskMetadata::default());
        assert!(!result.already_existed);
        assert!(!result.task_id.is_empty());
        assert_eq!(mgr.task_count(), 1);
    }

    #[test]
    fn dedup_hit_returns_same_id() {
        let mgr = TaskManager::new(test_config());
        let hash = keccak256(b"same");
        let r1 = mgr.register(hash, 100, TaskMetadata::default());
        let r2 = mgr.register(hash, 100, TaskMetadata::default());
        assert_eq!(r1.task_id, r2.task_id);
        assert!(!r1.already_existed);
        assert!(r2.already_existed);
        assert_eq!(mgr.task_count(), 1);
    }

    #[test]
    fn different_hashes_create_different_tasks() {
        let mgr = TaskManager::new(test_config());
        let r1 = mgr.register(keccak256(b"a"), 100, TaskMetadata::default());
        let r2 = mgr.register(keccak256(b"b"), 200, TaskMetadata::default());
        assert_ne!(r1.task_id, r2.task_id);
        assert_eq!(mgr.task_count(), 2);
    }

    #[test]
    fn set_submitted_updates_state() {
        let mgr = TaskManager::new(test_config());
        let r = mgr.register(keccak256(b"w"), 10, TaskMetadata::default());
        assert!(!mgr.is_submitted(&r.task_id));
        mgr.set_submitted(&r.task_id, "submitted; awaiting result");
        assert!(mgr.is_submitted(&r.task_id));
        mgr.with_task(&r.task_id, |e| {
            assert!(
                matches!(&e.status, TaskStatus::Running(msg) if msg == "submitted; awaiting result")
            );
        });
    }

    #[test]
    fn set_failed_clears_dedup() {
        let mgr = TaskManager::new(test_config());
        let hash = keccak256(b"fail");
        let r1 = mgr.register(hash, 100, TaskMetadata::default());
        mgr.set_failed(&r1.task_id, "error");
        let r2 = mgr.register(hash, 100, TaskMetadata::default());
        assert!(!r2.already_existed);
        assert_ne!(r1.task_id, r2.task_id);
    }

    #[test]
    fn set_finished_preserves_dedup_with_extended_ttl() {
        let mgr = TaskManager::new(test_config());
        let hash = keccak256(b"finish");
        let r1 = mgr.register(hash, 100, TaskMetadata::default());
        mgr.set_finished(&r1.task_id, vec![1, 2, 3]);
        let r2 = mgr.register(hash, 100, TaskMetadata::default());
        assert!(r2.already_existed);
        assert_eq!(r1.task_id, r2.task_id);
    }

    #[test]
    fn set_cancelled_clears_dedup_and_triggers_cancel_token() {
        let mgr = TaskManager::new(test_config());
        let hash = keccak256(b"cancel");
        let r = mgr.register(hash, 100, TaskMetadata::default());
        let token = mgr.get_cancel_token(&r.task_id).unwrap();
        assert!(!token.is_cancelled());
        mgr.set_cancelled(&r.task_id);
        assert!(token.is_cancelled());
        let r2 = mgr.register(hash, 100, TaskMetadata::default());
        assert!(!r2.already_existed);
    }

    #[test]
    fn remove_task_clears_dedup() {
        let mgr = TaskManager::new(test_config());
        let hash = keccak256(b"remove");
        let r = mgr.register(hash, 100, TaskMetadata::default());
        mgr.remove_task(&r.task_id);
        assert!(!mgr.contains(&r.task_id));
        let r2 = mgr.register(hash, 100, TaskMetadata::default());
        assert!(!r2.already_existed);
    }

    #[test]
    fn non_terminal_task_ids_filters_correctly() {
        let mgr = TaskManager::new(test_config());
        let r1 = mgr.register(keccak256(b"w1"), 10, TaskMetadata::default());
        let r2 = mgr.register(keccak256(b"w2"), 10, TaskMetadata::default());
        mgr.set_finished(&r1.task_id, vec![]);
        let ids = mgr.non_terminal_task_ids();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], r2.task_id);
    }

    #[test]
    fn sweep_removes_expired_terminal_tasks() {
        let mgr = TaskManager::new(test_config_short_ttl());
        let hash = keccak256(b"sweep");
        let r = mgr.register(hash, 100, TaskMetadata::default());
        mgr.set_finished(&r.task_id, vec![1]);
        mgr.sweep();
        assert!(mgr.contains(&r.task_id));
        {
            let mut tasks = mgr.tasks.write().unwrap();
            if let Some(entry) = tasks.get_mut(&r.task_id) {
                entry.terminal_time = Some(Instant::now() - Duration::from_secs(10));
            }
        }
        mgr.sweep();
        assert!(!mgr.contains(&r.task_id));
    }

    #[test]
    fn sweep_removes_orphaned_dedup_entries() {
        let mgr = TaskManager::new(test_config_short_ttl());
        let hash = keccak256(b"orphan");
        let r = mgr.register(hash, 100, TaskMetadata::default());
        mgr.tasks.write().unwrap().remove(&r.task_id);
        mgr.sweep();
        let r2 = mgr.register(hash, 100, TaskMetadata::default());
        assert!(!r2.already_existed);
    }

    #[tokio::test]
    async fn concurrent_identical_witness_produces_single_task() {
        let mgr = std::sync::Arc::new(TaskManager::new(test_config()));
        let hash = keccak256(b"concurrent");
        let mut handles = Vec::new();
        for _ in 0..10 {
            let mgr = mgr.clone();
            handles
                .push(tokio::spawn(async move { mgr.register(hash, 10, TaskMetadata::default()) }));
        }
        let mut results = Vec::new();
        for h in handles {
            results.push(h.await.unwrap());
        }
        let ids: std::collections::HashSet<_> = results.iter().map(|r| r.task_id.clone()).collect();
        assert_eq!(ids.len(), 1);
        assert_eq!(results.iter().filter(|r| r.already_existed).count(), 9);
        assert_eq!(mgr.task_count(), 1);
    }

    #[test]
    fn metadata_stored_on_task() {
        let mgr = TaskManager::new(test_config());
        let meta = TaskMetadata {
            start_blk_height: Some(100),
            end_blk_height: Some(200),
            claimed_output_root: Some("0xabc".into()),
        };
        let r = mgr.register(keccak256(b"meta"), 50, meta);
        mgr.with_task(&r.task_id, |e| {
            assert_eq!(e.metadata.start_blk_height, Some(100));
            assert_eq!(e.metadata.end_blk_height, Some(200));
            assert_eq!(e.metadata.claimed_output_root.as_deref(), Some("0xabc"));
        });
    }
}
