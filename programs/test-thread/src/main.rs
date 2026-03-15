//! Test multi-threading support in SP1 zkVM
//! 
//! This program tests whether multi-threading can be used in zkVM environment.
//! 
//! **Result**: SP1 zkVM supports `std::thread`, `Arc`, `Mutex`, and atomic operations!
//! However, note that threads in zkVM may execute sequentially for proof generation.

#![no_main]
sp1_zkvm::entrypoint!(main);

use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU32, Ordering};

fn main() {
    println!("Testing multi-threading in SP1 zkVM");
    
    // Test 1: Basic thread creation
    let handle = thread::spawn(|| {
        println!("Thread 1: Hello from spawned thread!");
        42
    });
    
    let result = handle.join().unwrap();
    println!("Thread 1 result: {}", result);
    
    // Test 2: Shared state with Arc and Mutex
    let counter = Arc::new(Mutex::new(0u32));
    let mut handles = vec![];
    
    for i in 0..3 {
        let counter = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            let mut num = counter.lock().unwrap();
            *num += i;
            println!("Thread {}: incremented counter", i);
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    println!("Final counter value: {}", *counter.lock().unwrap());
    
    // Test 3: Atomic operations
    let atomic_counter = Arc::new(AtomicU32::new(0));
    let mut handles = vec![];
    
    for i in 0..3 {
        let atomic_counter = Arc::clone(&atomic_counter);
        let handle = thread::spawn(move || {
            atomic_counter.fetch_add(i, Ordering::SeqCst);
            println!("Thread {}: atomic increment", i);
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    println!("Final atomic counter value: {}", atomic_counter.load(Ordering::SeqCst));
    
    // Commit result
    sp1_zkvm::io::commit(&result);
}

