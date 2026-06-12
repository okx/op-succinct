use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

pub struct ResidentGuard {
    counter: Arc<AtomicUsize>,
    size: usize,
}

impl ResidentGuard {
    pub fn new(counter: Arc<AtomicUsize>, size: usize) -> Self {
        counter.fetch_add(size, Ordering::Relaxed);
        Self { counter, size }
    }
}

impl Drop for ResidentGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.size, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_increments_on_create_decrements_on_drop() {
        let counter = Arc::new(AtomicUsize::new(0));
        {
            let _guard = ResidentGuard::new(Arc::clone(&counter), 1024);
            assert_eq!(counter.load(Ordering::Relaxed), 1024);
        }
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn multiple_guards_accumulate() {
        let counter = Arc::new(AtomicUsize::new(0));
        let g1 = ResidentGuard::new(Arc::clone(&counter), 100);
        let g2 = ResidentGuard::new(Arc::clone(&counter), 200);
        assert_eq!(counter.load(Ordering::Relaxed), 300);
        drop(g1);
        assert_eq!(counter.load(Ordering::Relaxed), 200);
        drop(g2);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn guard_with_zero_size() {
        let counter = Arc::new(AtomicUsize::new(50));
        {
            let _guard = ResidentGuard::new(Arc::clone(&counter), 0);
            assert_eq!(counter.load(Ordering::Relaxed), 50);
        }
        assert_eq!(counter.load(Ordering::Relaxed), 50);
    }
}
