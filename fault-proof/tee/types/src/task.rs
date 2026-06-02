use rkyv::{Archive, Deserialize, Serialize};

use crate::{ErrorKind, RangeTaskResponse};

pub type TaskId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Archive, Serialize, Deserialize)]
pub enum TaskPhase {
    Pending,
    DeserializingWitness,
    LoadingBootInfo,
    RunningKona,
    Signing,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub enum TaskStatusView {
    Running,
    Finished(Box<RangeTaskResponse>),
    Failed { kind: ErrorKind, message: String },
    Cancelled { at_phase: TaskPhase },
}

impl TaskStatusView {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Running)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct CreateTaskResponse {
    pub task_id: TaskId,
    pub accepted_at_ms: u64,
    pub already_existed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct TaskStateView {
    pub task_id: TaskId,
    pub status: TaskStatusView,
    pub phase: TaskPhase,
    pub start_time_ms: u64,
    pub end_time_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct DeleteTaskResponse {
    pub task_id: TaskId,
    pub was_running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct TaskSummary {
    pub task_id: TaskId,
    pub phase: TaskPhase,
    pub start_time_ms: u64,
    pub end_time_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct TaskListResponse {
    pub running: Vec<TaskSummary>,
    pub finished: Vec<TaskSummary>,
    pub failed: Vec<TaskSummary>,
    pub cancelled: Vec<TaskSummary>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{RangeJournalWire, RangeTaskResponse, SIGNATURE_LEN};

    fn sample_response() -> RangeTaskResponse {
        RangeTaskResponse {
            journal: RangeJournalWire {
                pcr0: [0x11; 32],
                config_hash: [0x22; 32],
                l1_origin_hash: [0x33; 32],
                l2_block_number: 42,
                prev_output_root: [0x44; 32],
                output_root: [0x55; 32],
            },
            signature: [0xAB; SIGNATURE_LEN],
        }
    }

    #[test]
    fn is_terminal_classification() {
        let cases: &[(TaskStatusView, bool)] = &[
            (TaskStatusView::Running, false),
            (TaskStatusView::Finished(Box::new(sample_response())), true),
            (TaskStatusView::Failed { kind: ErrorKind::KonaExec, message: "test".into() }, true),
            (TaskStatusView::Cancelled { at_phase: TaskPhase::RunningKona }, true),
        ];
        for (status, expected) in cases {
            assert_eq!(
                status.is_terminal(),
                *expected,
                "{status:?} is_terminal should be {expected}"
            );
        }
    }

    #[test]
    fn finished_carries_response() {
        let resp = sample_response();
        let status = TaskStatusView::Finished(Box::new(resp.clone()));
        if let TaskStatusView::Finished(inner) = status {
            assert_eq!(inner.signature.len(), SIGNATURE_LEN);
            assert_eq!(inner.journal.l2_block_number, 42);
        } else {
            panic!("expected Finished variant");
        }
    }

    #[test]
    fn create_task_response_rkyv_round_trip() {
        let original = CreateTaskResponse {
            task_id: "test-1".into(),
            accepted_at_ms: 1717300000000,
            already_existed: false,
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&original).unwrap();
        let archived =
            rkyv::access::<ArchivedCreateTaskResponse, rkyv::rancor::Error>(&bytes).unwrap();
        let deser: CreateTaskResponse =
            rkyv::deserialize::<CreateTaskResponse, rkyv::rancor::Error>(archived).unwrap();
        assert_eq!(deser, original);
    }

    #[test]
    fn task_state_view_rkyv_round_trip() {
        let original = TaskStateView {
            task_id: "test-1".into(),
            status: TaskStatusView::Running,
            phase: TaskPhase::Pending,
            start_time_ms: 1717300000000,
            end_time_ms: None,
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&original).unwrap();
        let archived = rkyv::access::<ArchivedTaskStateView, rkyv::rancor::Error>(&bytes).unwrap();
        let deser: TaskStateView =
            rkyv::deserialize::<TaskStateView, rkyv::rancor::Error>(archived).unwrap();
        assert_eq!(deser, original);
    }

    #[test]
    fn task_list_response_rkyv_round_trip() {
        let summary = TaskSummary {
            task_id: "task-42".into(),
            phase: TaskPhase::RunningKona,
            start_time_ms: 1717300000000,
            end_time_ms: None,
        };
        let original = TaskListResponse {
            running: vec![summary],
            finished: vec![],
            failed: vec![],
            cancelled: vec![],
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&original).unwrap();
        let archived =
            rkyv::access::<ArchivedTaskListResponse, rkyv::rancor::Error>(&bytes).unwrap();
        let deser: TaskListResponse =
            rkyv::deserialize::<TaskListResponse, rkyv::rancor::Error>(archived).unwrap();
        assert_eq!(deser, original);
    }

    #[test]
    fn delete_task_response_rkyv_round_trip() {
        let original = DeleteTaskResponse { task_id: "test-1".into(), was_running: true };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&original).unwrap();
        let archived =
            rkyv::access::<ArchivedDeleteTaskResponse, rkyv::rancor::Error>(&bytes).unwrap();
        let deser: DeleteTaskResponse =
            rkyv::deserialize::<DeleteTaskResponse, rkyv::rancor::Error>(archived).unwrap();
        assert_eq!(deser, original);
    }
}
