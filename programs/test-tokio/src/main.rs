//! Test async programming support in SP1 zkVM
//! 
//! This program demonstrates how to use async programming in zkVM environment using tokio.
//! Since SP1 zkVM supports tokio (with proper feature flags), we can use tokio directly
//! instead of implementing custom block_on.

#![no_main]
sp1_zkvm::entrypoint!(main);

use tokio::runtime::Builder;

// Async task example
async fn async_task() -> u32 {
    println!("Starting async task");
    
    // Use tokio's sleep
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    
    println!("Async task completed");
    42
}

fn main() {
    // Create tokio runtime and use block_on
    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = rt.block_on(async_task());
    
    println!("Result: {}", result);
    
    // Commit the result
    sp1_zkvm::io::commit(&result);
}

