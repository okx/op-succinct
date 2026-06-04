use std::{collections::HashMap, sync::Arc};

use alloy_primitives::B256;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::{oneshot, Mutex};
use tracing;

use crate::{config::HostConfig, error::HostError};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status")]
pub enum TaskStatus {
    Running { message: String },
    Finished { proof_bytes: Vec<u8>, enclave_phase: String, end_time: DateTime<Utc> },
    Failed { error_kind: String, message: String, end_time: DateTime<Utc> },
    Cancelled { at_phase: String, end_time: DateTime<Utc> },
}

impl TaskStatus {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Running { .. })
    }

    pub fn status_name(&self) -> &'static str {
        match self {
            Self::Running { .. } => "Running",
            Self::Finished { .. } => "Finished",
            Self::Failed { .. } => "Failed",
            Self::Cancelled { .. } => "Cancelled",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_blk_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_blk_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed_output_root: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskMetrics {
    pub start_time: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    pub witness_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveInfo {
    pub phase: String,
    pub start_time_ms: u64,
    pub end_time_ms: Option<u64>,
}

pub struct TaskEntry {
    pub task_id: String,
    pub status: TaskStatus,
    pub submitted_to_enclave: bool,
    pub witness_hash: B256,
    pub witness_size_bytes: usize,
    pub args: TaskArgs,
    pub start_time: DateTime<Utc>,
    pub enclave_info: Option<EnclaveInfo>,
    pub cancel_tx: Option<oneshot::Sender<()>>,
}

struct DedupEntry {
    task_id: String,
    created_at: tokio::time::Instant,
    terminal_time: Option<tokio::time::Instant>,
}

pub struct TaskManager {
    registry: Mutex<HashMap<String, Arc<Mutex<TaskEntry>>>>,
    dedup: Mutex<HashMap<B256, DedupEntry>>,
    config: Arc<HostConfig>,
}

pub struct RegisterResult {
    pub task_id: String,
    pub is_new: bool,
}

impl TaskManager {
    pub fn new(config: Arc<HostConfig>) -> Self {
        Self { registry: Mutex::new(HashMap::new()), dedup: Mutex::new(HashMap::new()), config }
    }

    pub async fn register_task(
        &self,
        witness_hash: B256,
        witness_size: usize,
        args: TaskArgs,
        cancel_tx: oneshot::Sender<()>,
    ) -> RegisterResult {
        {
            let dedup = self.dedup.lock().await;
            if let Some(entry) = dedup.get(&witness_hash) {
                return RegisterResult { task_id: entry.task_id.clone(), is_new: false };
            }
        }

        let task_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        let entry = TaskEntry {
            task_id: task_id.clone(),
            status: TaskStatus::Running { message: "submitting to enclave".to_string() },
            submitted_to_enclave: false,
            witness_hash,
            witness_size_bytes: witness_size,
            args,
            start_time: now,
            enclave_info: None,
            cancel_tx: Some(cancel_tx),
        };

        let entry_arc = Arc::new(Mutex::new(entry));

        {
            let mut dedup = self.dedup.lock().await;
            if let Some(existing) = dedup.get(&witness_hash) {
                return RegisterResult { task_id: existing.task_id.clone(), is_new: false };
            }
            dedup.insert(
                witness_hash,
                DedupEntry {
                    task_id: task_id.clone(),
                    created_at: tokio::time::Instant::now(),
                    terminal_time: None,
                },
            );
        }

        {
            let mut registry = self.registry.lock().await;
            registry.insert(task_id.clone(), entry_arc);
        }

        tracing::info!(task_id = %task_id, witness_hash = %witness_hash, witness_size = witness_size, "task created");
        RegisterResult { task_id, is_new: true }
    }

    pub async fn get_task(&self, task_id: &str) -> Option<Arc<Mutex<TaskEntry>>> {
        let registry = self.registry.lock().await;
        registry.get(task_id).cloned()
    }

    pub async fn set_submitted(&self, task_id: &str) {
        if let Some(entry_arc) = self.get_task(task_id).await {
            let mut entry = entry_arc.lock().await;
            entry.submitted_to_enclave = true;
            entry.status =
                TaskStatus::Running { message: "submitted; awaiting result".to_string() };
            tracing::info!(task_id = %task_id, "task submitted to enclave");
        }
    }

    pub async fn update_running_message(&self, task_id: &str, msg: &str) {
        if let Some(entry_arc) = self.get_task(task_id).await {
            let mut entry = entry_arc.lock().await;
            if !entry.status.is_terminal() {
                entry.status = TaskStatus::Running { message: msg.to_string() };
            }
        }
    }

    pub async fn set_finished(
        &self,
        task_id: &str,
        proof_bytes: Vec<u8>,
        enclave_phase: String,
        enclave_info: Option<EnclaveInfo>,
    ) {
        if let Some(entry_arc) = self.get_task(task_id).await {
            let mut entry = entry_arc.lock().await;
            if entry.status.is_terminal() {
                return;
            }
            let now = Utc::now();
            entry.status = TaskStatus::Finished { proof_bytes, enclave_phase, end_time: now };
            entry.enclave_info = enclave_info;
            tracing::info!(task_id = %task_id, "task finished");
        }

        let mut dedup = self.dedup.lock().await;
        if let Some(de) = dedup.values_mut().find(|d| d.task_id == task_id) {
            de.terminal_time = Some(tokio::time::Instant::now());
        }
    }

    pub async fn set_failed(&self, task_id: &str, error_kind: &str, message: &str) {
        if let Some(entry_arc) = self.get_task(task_id).await {
            let mut entry = entry_arc.lock().await;
            if entry.status.is_terminal() {
                return;
            }
            let now = Utc::now();
            entry.status = TaskStatus::Failed {
                error_kind: error_kind.to_string(),
                message: message.to_string(),
                end_time: now,
            };
            tracing::warn!(task_id = %task_id, error_kind = %error_kind, "task failed");
        }

        self.remove_dedup_for_task(task_id).await;
    }

    pub async fn set_failed_from_host_error(&self, task_id: &str, err: &HostError) {
        let (kind, msg) = match err {
            HostError::EnclaveError { kind, message } => (format!("{kind:?}"), message.clone()),
            other => ("Internal".to_string(), other.message()),
        };
        self.set_failed(task_id, &kind, &msg).await;
    }

    pub async fn set_failed_capacity_exhausted(&self, task_id: &str) {
        self.set_failed(task_id, "TooManyTasks", "enclave at capacity for 120s; giving up").await;
    }

    pub async fn cancel_task(&self, task_id: &str) -> Result<(), HostError> {
        let entry_arc = self
            .get_task(task_id)
            .await
            .ok_or_else(|| HostError::TaskNotFound(task_id.to_string()))?;

        let mut entry = entry_arc.lock().await;

        if entry.status.is_terminal() {
            return Ok(());
        }

        if let Some(tx) = entry.cancel_tx.take() {
            let _ = tx.send(());
        }

        let at_phase = entry
            .enclave_info
            .as_ref()
            .map(|e| e.phase.clone())
            .unwrap_or_else(|| "Running".to_string());
        let now = Utc::now();
        entry.status = TaskStatus::Cancelled { at_phase, end_time: now };
        drop(entry);

        self.remove_dedup_for_task(task_id).await;

        tracing::info!(task_id = %task_id, "task cancelled");
        Ok(())
    }

    pub async fn remove_task(&self, task_id: &str) {
        let mut registry = self.registry.lock().await;
        if let Some(entry_arc) = registry.remove(task_id) {
            let entry = entry_arc.lock().await;
            let hash = entry.witness_hash;
            drop(entry);
            drop(registry);
            let mut dedup = self.dedup.lock().await;
            dedup.remove(&hash);
        }
    }

    pub async fn sweep_expired(&self) {
        let retention = std::time::Duration::from_secs(self.config.server.task_retention_secs);
        let dedup_ttl = std::time::Duration::from_secs(self.config.server.dedup_ttl_secs);
        let now = tokio::time::Instant::now();

        let mut to_remove_tasks: Vec<String> = Vec::new();
        let mut to_remove_dedup: Vec<B256> = Vec::new();

        {
            let registry = self.registry.lock().await;
            for (tid, entry_arc) in registry.iter() {
                let entry = entry_arc.lock().await;
                match &entry.status {
                    TaskStatus::Finished { end_time, .. } |
                    TaskStatus::Failed { end_time, .. } |
                    TaskStatus::Cancelled { end_time, .. } => {
                        let elapsed = Utc::now()
                            .signed_duration_since(*end_time)
                            .to_std()
                            .unwrap_or_default();
                        if elapsed >= retention {
                            to_remove_tasks.push(tid.clone());
                            to_remove_dedup.push(entry.witness_hash);
                        }
                    }
                    TaskStatus::Running { .. } => {}
                }
            }
        }

        {
            let dedup = self.dedup.lock().await;
            for (hash, de) in dedup.iter() {
                if de.terminal_time.is_none() && now.duration_since(de.created_at) >= dedup_ttl {
                    to_remove_dedup.push(*hash);
                }
                if let Some(tt) = de.terminal_time {
                    if now.duration_since(tt) >= retention {
                        to_remove_dedup.push(*hash);
                    }
                }
            }
        }

        if !to_remove_tasks.is_empty() || !to_remove_dedup.is_empty() {
            let mut registry = self.registry.lock().await;
            for tid in &to_remove_tasks {
                registry.remove(tid);
            }
            drop(registry);

            let mut dedup = self.dedup.lock().await;
            for hash in &to_remove_dedup {
                dedup.remove(hash);
            }

            tracing::info!(
                tasks_removed = to_remove_tasks.len(),
                dedup_removed = to_remove_dedup.len(),
                "sweeper cycle complete"
            );
        }
    }

    pub async fn non_terminal_task_ids(&self) -> Vec<(String, bool)> {
        let registry = self.registry.lock().await;
        let mut result = Vec::new();
        for (tid, entry_arc) in registry.iter() {
            let entry = entry_arc.lock().await;
            if !entry.status.is_terminal() {
                result.push((tid.clone(), entry.submitted_to_enclave));
            }
        }
        result
    }

    pub(crate) async fn remove_dedup_for_task(&self, task_id: &str) {
        let mut dedup = self.dedup.lock().await;
        dedup.retain(|_, de| de.task_id != task_id);
    }

    pub async fn task_count(&self) -> usize {
        self.registry.lock().await.len()
    }

    pub async fn dedup_count(&self) -> usize {
        self.dedup.lock().await.len()
    }
}

pub fn format_duration(start: DateTime<Utc>, end: DateTime<Utc>) -> String {
    let dur = end.signed_duration_since(start);
    let total_secs = dur.num_seconds().unsigned_abs();
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    if mins > 0 {
        format!("{mins}m {secs:02}s")
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    fn test_config() -> Arc<HostConfig> {
        Arc::new(HostConfig {
            server: crate::config::ServerConfig {
                bind_addr: "0.0.0.0:18080".to_string(),
                task_retention_secs: 1,
                dedup_ttl_secs: 1,
                monitor_interval_secs: 30,
            },
            enclave: crate::config::EnclaveConfig::default(),
            attestation: crate::config::AttestationConfig::default(),
        })
    }

    fn test_args() -> TaskArgs {
        TaskArgs { start_blk_height: None, end_blk_height: None, claimed_output_root: None }
    }

    #[tokio::test]
    async fn register_new_task_returns_uuid() {
        let tm = TaskManager::new(test_config());
        let hash = keccak256(b"witness1");
        let (tx, _rx) = oneshot::channel();
        let result = tm.register_task(hash, 1024, test_args(), tx).await;
        assert!(result.is_new);
        assert!(!result.task_id.is_empty());
        assert_eq!(tm.task_count().await, 1);
        assert_eq!(tm.dedup_count().await, 1);
    }

    #[tokio::test]
    async fn dedup_returns_same_task_id() {
        let tm = TaskManager::new(test_config());
        let hash = keccak256(b"witness1");

        let (tx1, _rx1) = oneshot::channel();
        let r1 = tm.register_task(hash, 1024, test_args(), tx1).await;
        assert!(r1.is_new);

        let (tx2, _rx2) = oneshot::channel();
        let r2 = tm.register_task(hash, 1024, test_args(), tx2).await;
        assert!(!r2.is_new);
        assert_eq!(r1.task_id, r2.task_id);
        assert_eq!(tm.task_count().await, 1);
    }

    #[tokio::test]
    async fn set_submitted_updates_flag_and_message() {
        let tm = TaskManager::new(test_config());
        let hash = keccak256(b"witness1");
        let (tx, _rx) = oneshot::channel();
        let result = tm.register_task(hash, 1024, test_args(), tx).await;

        tm.set_submitted(&result.task_id).await;

        let entry_arc = tm.get_task(&result.task_id).await.unwrap();
        let entry = entry_arc.lock().await;
        assert!(entry.submitted_to_enclave);
        assert!(
            matches!(&entry.status, TaskStatus::Running { message } if message == "submitted; awaiting result")
        );
    }

    #[tokio::test]
    async fn update_running_message_changes_progress() {
        let tm = TaskManager::new(test_config());
        let hash = keccak256(b"witness1");
        let (tx, _rx) = oneshot::channel();
        let result = tm.register_task(hash, 1024, test_args(), tx).await;

        tm.update_running_message(&result.task_id, "queued; enclave at capacity").await;

        let entry_arc = tm.get_task(&result.task_id).await.unwrap();
        let entry = entry_arc.lock().await;
        assert!(
            matches!(&entry.status, TaskStatus::Running { message } if message == "queued; enclave at capacity")
        );
    }

    #[tokio::test]
    async fn set_finished_caches_proof_bytes() {
        let tm = TaskManager::new(test_config());
        let hash = keccak256(b"witness1");
        let (tx, _rx) = oneshot::channel();
        let result = tm.register_task(hash, 1024, test_args(), tx).await;

        let proof = vec![0xAB; 100];
        tm.set_finished(&result.task_id, proof.clone(), "Terminal".into(), None).await;

        let entry_arc = tm.get_task(&result.task_id).await.unwrap();
        let entry = entry_arc.lock().await;
        match &entry.status {
            TaskStatus::Finished { proof_bytes, enclave_phase, .. } => {
                assert_eq!(proof_bytes, &proof);
                assert_eq!(enclave_phase, "Terminal");
            }
            other => panic!("expected Finished, got {}", other.status_name()),
        }
    }

    #[tokio::test]
    async fn terminal_transition_is_one_shot() {
        let tm = TaskManager::new(test_config());
        let hash = keccak256(b"witness1");
        let (tx, _rx) = oneshot::channel();
        let result = tm.register_task(hash, 1024, test_args(), tx).await;

        tm.set_finished(&result.task_id, vec![1], "Terminal".into(), None).await;

        tm.set_failed(&result.task_id, "KonaExec", "should not overwrite").await;

        let entry_arc = tm.get_task(&result.task_id).await.unwrap();
        let entry = entry_arc.lock().await;
        assert!(matches!(&entry.status, TaskStatus::Finished { .. }));
    }

    #[tokio::test]
    async fn set_failed_removes_dedup_entry() {
        let tm = TaskManager::new(test_config());
        let hash = keccak256(b"witness1");
        let (tx, _rx) = oneshot::channel();
        let result = tm.register_task(hash, 1024, test_args(), tx).await;
        assert_eq!(tm.dedup_count().await, 1);

        tm.set_failed(&result.task_id, "KonaExec", "failed").await;
        assert_eq!(tm.dedup_count().await, 0);
    }

    #[tokio::test]
    async fn cancel_task_transitions_and_removes_dedup() {
        let tm = TaskManager::new(test_config());
        let hash = keccak256(b"witness1");
        let (tx, _rx) = oneshot::channel();
        let result = tm.register_task(hash, 1024, test_args(), tx).await;

        tm.cancel_task(&result.task_id).await.unwrap();

        let entry_arc = tm.get_task(&result.task_id).await.unwrap();
        let entry = entry_arc.lock().await;
        assert!(matches!(&entry.status, TaskStatus::Cancelled { .. }));
        drop(entry);

        assert_eq!(tm.dedup_count().await, 0);
    }

    #[tokio::test]
    async fn cancel_already_terminal_is_idempotent() {
        let tm = TaskManager::new(test_config());
        let hash = keccak256(b"witness1");
        let (tx, _rx) = oneshot::channel();
        let result = tm.register_task(hash, 1024, test_args(), tx).await;

        tm.set_finished(&result.task_id, vec![1], "Terminal".into(), None).await;
        let res = tm.cancel_task(&result.task_id).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn cancel_not_found_returns_error() {
        let tm = TaskManager::new(test_config());
        let res = tm.cancel_task("nonexistent").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn remove_task_cleans_registry_and_dedup() {
        let tm = TaskManager::new(test_config());
        let hash = keccak256(b"witness1");
        let (tx, _rx) = oneshot::channel();
        let result = tm.register_task(hash, 1024, test_args(), tx).await;

        tm.remove_task(&result.task_id).await;
        assert_eq!(tm.task_count().await, 0);
        assert_eq!(tm.dedup_count().await, 0);
    }

    #[tokio::test]
    async fn failed_task_allows_resubmission() {
        let tm = TaskManager::new(test_config());
        let hash = keccak256(b"witness1");

        let (tx1, _rx1) = oneshot::channel();
        let r1 = tm.register_task(hash, 1024, test_args(), tx1).await;
        tm.set_failed(&r1.task_id, "KonaExec", "failed").await;

        let (tx2, _rx2) = oneshot::channel();
        let r2 = tm.register_task(hash, 1024, test_args(), tx2).await;
        assert!(r2.is_new);
        assert_ne!(r1.task_id, r2.task_id);
    }

    #[tokio::test]
    async fn concurrent_identical_witnesses_yield_same_task() {
        let tm = Arc::new(TaskManager::new(test_config()));
        let hash = keccak256(b"witness_concurrent");

        let mut handles = Vec::new();
        for _ in 0..10 {
            let tm_clone = Arc::clone(&tm);
            let h = hash;
            handles.push(tokio::spawn(async move {
                let (tx, _rx) = oneshot::channel();
                tm_clone
                    .register_task(
                        h,
                        1024,
                        TaskArgs {
                            start_blk_height: None,
                            end_blk_height: None,
                            claimed_output_root: None,
                        },
                        tx,
                    )
                    .await
            }));
        }

        let mut ids = Vec::new();
        for handle in handles {
            ids.push(handle.await.unwrap().task_id);
        }

        let first = &ids[0];
        for id in &ids[1..] {
            assert_eq!(id, first, "all concurrent registrations should return same task_id");
        }
        assert_eq!(tm.task_count().await, 1);
    }

    #[test]
    fn format_duration_minutes_and_seconds() {
        let start = Utc::now();
        let end = start + chrono::Duration::seconds(474);
        assert_eq!(format_duration(start, end), "7m 54s");
    }

    #[test]
    fn format_duration_seconds_only() {
        let start = Utc::now();
        let end = start + chrono::Duration::seconds(45);
        assert_eq!(format_duration(start, end), "45s");
    }

    #[test]
    fn task_status_is_terminal_classification() {
        let cases: Vec<(TaskStatus, bool)> = vec![
            (TaskStatus::Running { message: "x".into() }, false),
            (
                TaskStatus::Finished {
                    proof_bytes: vec![],
                    enclave_phase: "Terminal".into(),
                    end_time: Utc::now(),
                },
                true,
            ),
            (
                TaskStatus::Failed {
                    error_kind: "KonaExec".into(),
                    message: "fail".into(),
                    end_time: Utc::now(),
                },
                true,
            ),
            (TaskStatus::Cancelled { at_phase: "Running".into(), end_time: Utc::now() }, true),
        ];
        for (status, expected) in cases {
            assert_eq!(status.is_terminal(), expected, "{:?}", status.status_name());
        }
    }

    #[test]
    fn task_status_name_returns_correct_strings() {
        assert_eq!(TaskStatus::Running { message: "x".into() }.status_name(), "Running");
        assert_eq!(
            TaskStatus::Finished {
                proof_bytes: vec![],
                enclave_phase: "T".into(),
                end_time: Utc::now()
            }
            .status_name(),
            "Finished"
        );
    }
}
