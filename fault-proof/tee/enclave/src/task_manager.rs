use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::oneshot;
use xlayer_tee_types::{
    CreateTaskResponse, DeleteTaskResponse, TaskId, TaskListResponse, TaskPhase, TaskStateView,
    TaskStatusView, TaskSummary,
};

use crate::{error::Error, runner};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

pub struct TaskState {
    pub phase: TaskPhase,
    pub status: TaskStatusView,
    pub start_time_ms: u64,
    pub end_time_ms: Option<u64>,
}

pub struct TaskEntry {
    pub task_id: TaskId,
    pub state: Mutex<TaskState>,
    pub abort_tx: Mutex<Option<oneshot::Sender<()>>>,
}

pub struct TaskManager {
    tasks: Mutex<HashMap<TaskId, Arc<TaskEntry>>>,
    pcr0: [u8; 32],
    max_inflight: usize,
    ttl_ms: u64,
}

impl TaskManager {
    pub fn new(pcr0: [u8; 32], max_inflight: usize, ttl_secs: u64) -> Self {
        let effective_max = if max_inflight == 0 {
            std::thread::available_parallelism().map(|p| (p.get() / 2).max(1)).unwrap_or(2)
        } else {
            max_inflight
        };

        Self {
            tasks: Mutex::new(HashMap::new()),
            pcr0,
            max_inflight: effective_max,
            ttl_ms: ttl_secs.saturating_mul(1000),
        }
    }

    pub fn pcr0(&self) -> [u8; 32] {
        self.pcr0
    }

    pub async fn create(
        self: &Arc<Self>,
        task_id: TaskId,
        witness_bytes: Bytes,
    ) -> Result<CreateTaskResponse, Error> {
        if uuid::Uuid::parse_str(&task_id).is_err() {
            return Err(Error::InvalidTaskId(task_id));
        }

        let mut tasks = self.tasks.lock();

        if let Some(existing) = tasks.get(&task_id) {
            let state = existing.state.lock();
            return Ok(CreateTaskResponse {
                task_id: task_id.clone(),
                accepted_at_ms: state.start_time_ms,
                already_existed: true,
            });
        }

        let running_count = tasks
            .values()
            .filter(|e| {
                let state = e.state.lock();
                !state.status.is_terminal()
            })
            .count();

        if running_count >= self.max_inflight {
            return Err(Error::TooManyTasks);
        }

        let start_time = now_ms();
        let (abort_tx, abort_rx) = oneshot::channel::<()>();

        let entry = Arc::new(TaskEntry {
            task_id: task_id.clone(),
            state: Mutex::new(TaskState {
                phase: TaskPhase::Pending,
                status: TaskStatusView::Running,
                start_time_ms: start_time,
                end_time_ms: None,
            }),
            abort_tx: Mutex::new(Some(abort_tx)),
        });

        tasks.insert(task_id.clone(), entry.clone());
        drop(tasks);

        let pcr0 = self.pcr0;
        tokio::spawn(async move {
            runner::run_pipeline(entry, witness_bytes, pcr0, abort_rx).await;
        });

        Ok(CreateTaskResponse { task_id, accepted_at_ms: start_time, already_existed: false })
    }

    pub fn snapshot(&self, task_id: &str) -> Result<TaskStateView, Error> {
        let tasks = self.tasks.lock();
        let entry = tasks.get(task_id).ok_or_else(|| Error::TaskUnknown(task_id.to_string()))?;

        let state = entry.state.lock();
        Ok(TaskStateView {
            task_id: task_id.to_string(),
            status: state.status.clone(),
            phase: state.phase,
            start_time_ms: state.start_time_ms,
            end_time_ms: state.end_time_ms,
        })
    }

    pub fn cancel(&self, task_id: &str) -> Result<DeleteTaskResponse, Error> {
        let tasks = self.tasks.lock();
        let entry = tasks.get(task_id).ok_or_else(|| Error::TaskUnknown(task_id.to_string()))?;

        let mut abort_guard = entry.abort_tx.lock();
        let was_running = if let Some(tx) = abort_guard.take() {
            let _ = tx.send(());
            true
        } else {
            false
        };

        if was_running {
            let mut state = entry.state.lock();
            let at_phase = state.phase;
            state.status = TaskStatusView::Cancelled { at_phase };
            state.end_time_ms = Some(now_ms());
        }

        Ok(DeleteTaskResponse { task_id: task_id.to_string(), was_running })
    }

    pub fn list(&self) -> TaskListResponse {
        let tasks = self.tasks.lock();
        let mut running = Vec::new();
        let mut finished = Vec::new();
        let mut failed = Vec::new();
        let mut cancelled = Vec::new();

        for entry in tasks.values() {
            let state = entry.state.lock();
            let summary = TaskSummary {
                task_id: entry.task_id.clone(),
                phase: state.phase,
                start_time_ms: state.start_time_ms,
                end_time_ms: state.end_time_ms,
            };
            match &state.status {
                TaskStatusView::Running => running.push(summary),
                TaskStatusView::Finished(_) => finished.push(summary),
                TaskStatusView::Failed { .. } => failed.push(summary),
                TaskStatusView::Cancelled { .. } => cancelled.push(summary),
            }
        }

        TaskListResponse { running, finished, failed, cancelled }
    }

    pub fn gc_tick(&self) {
        if self.ttl_ms == 0 {
            return;
        }

        let now = now_ms();
        let mut tasks = self.tasks.lock();
        tasks.retain(|_, entry| {
            let state = entry.state.lock();
            if let Some(end_time) = state.end_time_ms {
                if state.status.is_terminal() && now.saturating_sub(end_time) > self.ttl_ms {
                    return false;
                }
            }
            true
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager(max_inflight: usize, ttl_secs: u64) -> Arc<TaskManager> {
        Arc::new(TaskManager::new([0u8; 32], max_inflight, ttl_secs))
    }

    #[tokio::test]
    async fn create_task_with_valid_uuid() {
        let manager = make_manager(2, 3600);
        let task_id = uuid::Uuid::new_v4().to_string();
        let result = manager.create(task_id.clone(), Bytes::new()).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.task_id, task_id);
        assert!(!resp.already_existed);
        assert!(resp.accepted_at_ms > 0);
    }

    #[tokio::test]
    async fn create_task_rejects_invalid_uuid() {
        let manager = make_manager(2, 3600);
        let result = manager.create("not-a-uuid".into(), Bytes::new()).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::InvalidTaskId(_)));
    }

    #[tokio::test]
    async fn create_task_idempotent_returns_existing() {
        let manager = make_manager(2, 3600);
        let task_id = uuid::Uuid::new_v4().to_string();

        let resp1 = manager.create(task_id.clone(), Bytes::new()).await.unwrap();
        assert!(!resp1.already_existed);

        let resp2 = manager.create(task_id.clone(), Bytes::new()).await.unwrap();
        assert!(resp2.already_existed);
        assert_eq!(resp1.accepted_at_ms, resp2.accepted_at_ms);
    }

    #[tokio::test]
    async fn create_task_rejects_at_capacity() {
        let manager = make_manager(1, 3600);
        let id1 = uuid::Uuid::new_v4().to_string();
        let id2 = uuid::Uuid::new_v4().to_string();

        manager.create(id1.clone(), Bytes::new()).await.unwrap();

        let result = manager.create(id2, Bytes::new()).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::TooManyTasks));
    }

    #[tokio::test]
    async fn idempotent_hit_bypasses_capacity_check() {
        let manager = make_manager(1, 3600);
        let id1 = uuid::Uuid::new_v4().to_string();

        manager.create(id1.clone(), Bytes::new()).await.unwrap();

        let result = manager.create(id1.clone(), Bytes::new()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().already_existed);
    }

    #[tokio::test]
    async fn snapshot_returns_running_task() {
        let manager = make_manager(2, 3600);
        let task_id = uuid::Uuid::new_v4().to_string();
        manager.create(task_id.clone(), Bytes::new()).await.unwrap();

        let view = manager.snapshot(&task_id).unwrap();
        assert_eq!(view.task_id, task_id);
        assert!(matches!(view.status, TaskStatusView::Running));
    }

    #[tokio::test]
    async fn snapshot_unknown_task_returns_error() {
        let manager = make_manager(2, 3600);
        let result = manager.snapshot("nonexistent");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::TaskUnknown(_)));
    }

    #[tokio::test]
    async fn cancel_running_task() {
        let manager = make_manager(2, 3600);
        let task_id = uuid::Uuid::new_v4().to_string();
        manager.create(task_id.clone(), Bytes::new()).await.unwrap();

        let resp = manager.cancel(&task_id).unwrap();
        assert!(resp.was_running);

        let view = manager.snapshot(&task_id).unwrap();
        assert!(matches!(view.status, TaskStatusView::Cancelled { .. }));
        assert!(view.end_time_ms.is_some());
    }

    #[tokio::test]
    async fn cancel_already_cancelled_task() {
        let manager = make_manager(2, 3600);
        let task_id = uuid::Uuid::new_v4().to_string();
        manager.create(task_id.clone(), Bytes::new()).await.unwrap();

        manager.cancel(&task_id).unwrap();
        let resp2 = manager.cancel(&task_id).unwrap();
        assert!(!resp2.was_running);
    }

    #[tokio::test]
    async fn cancel_unknown_task_returns_error() {
        let manager = make_manager(2, 3600);
        let result = manager.cancel("nonexistent");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::TaskUnknown(_)));
    }

    #[tokio::test]
    async fn list_groups_tasks_by_status() {
        let manager = make_manager(4, 3600);
        let id1 = uuid::Uuid::new_v4().to_string();
        let id2 = uuid::Uuid::new_v4().to_string();

        manager.create(id1.clone(), Bytes::new()).await.unwrap();
        manager.create(id2.clone(), Bytes::new()).await.unwrap();

        manager.cancel(&id2).unwrap();

        let list = manager.list();
        assert_eq!(list.running.len(), 1);
        assert_eq!(list.cancelled.len(), 1);
        assert_eq!(list.running[0].task_id, id1);
        assert_eq!(list.cancelled[0].task_id, id2);
    }

    #[tokio::test]
    async fn gc_removes_expired_terminal_tasks() {
        let manager = make_manager(4, 1);
        let task_id = uuid::Uuid::new_v4().to_string();
        manager.create(task_id.clone(), Bytes::new()).await.unwrap();
        manager.cancel(&task_id).unwrap();

        {
            let tasks = manager.tasks.lock();
            let entry = tasks.get(&task_id).unwrap();
            let mut state = entry.state.lock();
            state.end_time_ms = Some(now_ms().saturating_sub(2000));
        }

        manager.gc_tick();
        assert!(manager.snapshot(&task_id).is_err());
    }

    #[tokio::test]
    async fn gc_does_not_remove_running_tasks() {
        let manager = make_manager(4, 1);
        let task_id = uuid::Uuid::new_v4().to_string();
        manager.create(task_id.clone(), Bytes::new()).await.unwrap();

        manager.gc_tick();
        assert!(manager.snapshot(&task_id).is_ok());
    }

    #[tokio::test]
    async fn gc_disabled_when_ttl_zero() {
        let manager = make_manager(4, 0);
        let task_id = uuid::Uuid::new_v4().to_string();
        manager.create(task_id.clone(), Bytes::new()).await.unwrap();
        manager.cancel(&task_id).unwrap();

        {
            let tasks = manager.tasks.lock();
            let entry = tasks.get(&task_id).unwrap();
            let mut state = entry.state.lock();
            state.end_time_ms = Some(0);
        }

        manager.gc_tick();
        assert!(manager.snapshot(&task_id).is_ok());
    }
}
