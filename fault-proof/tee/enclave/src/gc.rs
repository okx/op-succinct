use std::{sync::Arc, time::Duration};

use crate::task_manager::TaskManager;

pub async fn run_gc_loop(manager: Arc<TaskManager>, interval_secs: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        manager.gc_tick();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_manager::TaskManager;

    #[tokio::test]
    async fn gc_loop_runs_without_panic() {
        let manager = Arc::new(TaskManager::new([0u8; 32], 2, 1));
        let mgr_clone = manager.clone();

        let handle = tokio::spawn(async move {
            run_gc_loop(mgr_clone, 1).await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.abort();
    }
}
