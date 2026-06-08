pub const TASKS_RANGE: &str = "/tasks/range";
pub const TASKS_BY_ID: &str = "/tasks/{task_id}";
pub const TASKS_LIST: &str = "/tasks";
pub const ATTESTATION: &str = "/attestation";

pub const HEADER_TASK_ID: &str = "x-task-id";

pub const OCTET_STREAM: &str = "application/octet-stream";
pub const JSON: &str = "application/json";

pub const MAX_RANGE_BODY_BYTES: usize = 512 * 1024 * 1024;

pub fn task_path(task_id: &str) -> String {
    format!("/tasks/{task_id}")
}
