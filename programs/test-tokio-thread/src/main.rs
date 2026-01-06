//! Test tokio multi-threading support in SP1 zkVM
//! 
//! This program tests whether tokio's multi-threading features can be used in zkVM.
//! 
//! **Result**: Tokio multi-threading IS supported in SP1 zkVM!
//! Key points:
//! - Use `default-features = false` to avoid I/O dependencies (mio, socket2)
//! - Enable only: `rt`, `rt-multi-thread`, `macros`, `sync`, `time`
//! - Avoid features like `net`, `fs`, `io-util` which require OS support
//!
//! ## About `#[tokio::main(flavor = "multi_thread")]`
//!
//! This macro transforms the async `main` function into a synchronous one that:
//! 1. Creates a tokio runtime with multi-threaded scheduler
//! 2. Calls `rt.block_on()` to execute the async code
//! 3. Provides full tokio runtime features (task scheduling, waker, etc.)
//!
//! It's equivalent to:
//! ```rust
//! fn main() {
//!     let rt = tokio::runtime::Builder::new_multi_thread()
//!         .enable_all()
//!         .build()
//!         .unwrap();
//!     rt.block_on(async { /* your async code */ });
//! }
//! ```

#![no_main]
sp1_zkvm::entrypoint!(main);

use tokio::task;
use tokio::sync::Mutex;
use std::sync::Arc;

async fn async_task(id: u32) -> u32 {
    println!("Tokio task {}: Starting", id);
    // Simulate some async work
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    println!("Tokio task {}: Completed", id);
    id * 2
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    println!("Testing tokio multi-threading in SP1 zkVM");
    
    // Test 1: Spawn multiple tasks
    let mut handles = vec![];
    for i in 0..3 {
        let handle = task::spawn(async_task(i));
        handles.push(handle);
    }
    
    let mut results = vec![];
    for handle in handles {
        let result = handle.await.unwrap();
        results.push(result);
    }
    
    println!("Results: {:?}", results);
    
    // Test 2: Shared state with tokio::sync::Mutex
    let counter = Arc::new(Mutex::new(0u32));
    let mut handles = vec![];
    
    for i in 0..3 {
        let counter = Arc::clone(&counter);
        let handle = task::spawn(async move {
            let mut num = counter.lock().await;
            *num += i;
            println!("Tokio task {}: incremented counter", i);
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.await.unwrap();
    }
    
    println!("Final counter value: {}", *counter.lock().await);
    
    // Commit result
    sp1_zkvm::io::commit(&results[0]);
}

