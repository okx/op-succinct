//! Test runner for SP1 zkVM ELF files
//! 
//! This program can execute ELF files and generate proofs.

use anyhow::Result;
use clap::Parser;
use sp1_sdk::{utils, ExecutionReport, HashableKey, Prover, ProverClient, SP1ProofMode, SP1PublicValues, SP1Stdin};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "test-runner")]
#[command(about = "Execute SP1 zkVM ELF files and generate proofs")]
struct Args {
    /// Path to the ELF file
    #[arg(short, long)]
    elf: PathBuf,

    /// Path to input file (optional, for stdin)
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// Generate proof (not just execute)
    #[arg(short, long)]
    prove: bool,

    /// Use mock prover (faster, for testing)
    #[arg(short, long)]
    mock: bool,

    /// Output directory for proof
    #[arg(short, long, default_value = "./proofs")]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    utils::setup_logger();
    
    let args = Args::parse();

    // Load ELF file
    println!("Loading ELF file: {:?}", args.elf);
    let elf_bytes = fs::read(&args.elf)?;
    println!("ELF file loaded: {} bytes", elf_bytes.len());

    // Create stdin (empty or from file)
    let mut stdin = SP1Stdin::new();
    if let Some(input_path) = args.input {
        println!("Loading input from: {:?}", input_path);
        let input_bytes = fs::read(input_path)?;
        stdin.write_slice(&input_bytes);
        println!("Input loaded: {} bytes", input_bytes.len());
    }

    // Create prover
    let prover = if args.mock {
        println!("Using mock prover");
        ProverClient::builder().mock().build()
    } else {
        println!("Using CPU prover");
        ProverClient::builder().cpu().build()
    };

    // Setup: generate proving key and verifying key
    println!("Setting up prover (generating keys)...");
    let (pk, vk) = prover.setup(&elf_bytes);
    println!("Setup complete!");
    println!("Verifying key hash: {:?}", vk.vk.hash_u32());

    // Execute the program
    println!("\n=== Executing ELF ===");
    let start_time = std::time::Instant::now();
    let (public_values, report): (SP1PublicValues, ExecutionReport) = prover
        .execute(&elf_bytes, &stdin)
        .calculate_gas(true)
        .deferred_proof_verification(false)
        .run()?;
    let execution_time = start_time.elapsed();

    println!("Execution completed!");
    println!("Execution time: {:?}", execution_time);
    println!("Public values length: {} bytes", public_values.as_slice().len());
    println!("Gas: {:?}", report.gas);

    // Generate proof if requested
    if args.prove {
        println!("\n=== Generating Proof ===");
        let proof_start = std::time::Instant::now();
        
        let proof = if args.mock {
            // Mock mode: create mock proof (faster, for testing)
            println!("Creating mock proof...");
            sp1_sdk::SP1ProofWithPublicValues::create_mock_proof(
                &pk,
                public_values.clone(),
                SP1ProofMode::Compressed,
                "v5.2.4",
            )
        } else {
            // Real proof generation
            prover
                .prove(&pk, &stdin)
                .compressed()
                .run()?
        };
        
        let proof_time = proof_start.elapsed();

        println!("Proof generated!");
        println!("Proof generation time: {:?}", proof_time);
        println!("Proof size: {} bytes", proof.bytes().len());

        // Save proof
        fs::create_dir_all(&args.output)?;
        let proof_path = args.output.join(format!("proof-{}.bin", 
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs()));
        proof.save(&proof_path)?;
        println!("Proof saved to: {:?}", proof_path);

        // Verify proof
        println!("\n=== Verifying Proof ===");
        let verify_start = std::time::Instant::now();
        prover.verify(&proof, &vk)?;
        let verify_time = verify_start.elapsed();
        println!("Proof verified successfully!");
        println!("Verification time: {:?}", verify_time);
    }

    Ok(())
}

