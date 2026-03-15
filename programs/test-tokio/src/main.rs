//! Test async programming support in SP1 zkVM
//! 
//! This program tests whether tokio runtime can be used in SP1 zkVM.
//! 
//! **Result**: Tokio runtime initialization FAILS in SP1 zkVM!
//! Even without enabling time feature, tokio runtime initialization requires
//! time support which zkVM doesn't provide.
//! 
//! **Conclusion**: Tokio runtime cannot be used in SP1 zkVM environment.
//! Use a simple block_on implementation (like kona_proof::block_on) instead.

#![no_main]
sp1_zkvm::entrypoint!(main);

// Try different approaches to use tokio runtime
#[cfg(feature = "try-tokio-runtime")]
use tokio::runtime::Builder;

// Async task example
async fn async_task() -> u32 {
    println!("Starting async task");
    println!("Async task completed");
    42
}

fn main() {
    // Attempt 1: Try to use tokio runtime without time feature
    // This will fail because runtime initialization requires time support
    #[cfg(feature = "try-tokio-runtime")]
    {
        println!("Attempting to create tokio runtime...");
        match Builder::new_current_thread().build() {
            Ok(rt) => {
                println!("Runtime created successfully!");
                let result = rt.block_on(async_task());
                println!("Result: {}", result);
                sp1_zkvm::io::commit(&result);
                return;
            }
            Err(e) => {
                println!("Failed to create runtime: {:?}", e);
            }
        }
    }
    
    // Fallback: Use simple block_on (this works)
    println!("Using simple block_on instead of tokio runtime");
    use core::future::Future;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    
    fn block_on<T>(f: impl Future<Output = T>) -> T {
        let mut f = Box::pin(f);
        
        fn noop_clone(_: *const ()) -> RawWaker {
            noop_raw_waker()
        }
        const fn noop(_: *const ()) {}
        fn noop_raw_waker() -> RawWaker {
            let vtable = &RawWakerVTable::new(noop_clone, noop, noop, noop);
            RawWaker::new(core::ptr::null(), vtable)
        }
        let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
        let mut context = Context::from_waker(&waker);
        
        loop {
            if let Poll::Ready(v) = f.as_mut().poll(&mut context) {
                return v;
            }
        }
    }
    
    let result = block_on(async_task());
    println!("Result: {}", result);
    sp1_zkvm::io::commit(&result);
}

