# Test Runner

A simple program to execute SP1 zkVM ELF files and generate proofs.

## Features

- Execute ELF files in SP1 zkVM
- Generate proofs (real or mock)
- Verify proofs
- Support custom input via stdin

## Usage

### Build

```bash
cd programs
just build-test-runner
```

### Run (Execute only)

```bash
# Execute ELF without generating proof
./target/release/test-runner --elf ../elf/test-tokio-elf

# Or using just
just run-test-runner --elf ../elf/test-tokio-elf
```

### Run with Proof Generation

```bash
# Generate real proof (slow)
./target/release/test-runner --elf ../elf/test-tokio-elf --prove

# Generate mock proof (fast, for testing)
./target/release/test-runner --elf ../elf/test-tokio-elf --prove --mock
```

### With Custom Input

```bash
# Execute with input file
./target/release/test-runner --elf ../elf/test-tokio-elf --input input.bin
```

## Options

- `--elf <path>`: Path to ELF file (required)
- `--input <path>`: Path to input file (optional)
- `--prove`: Generate proof (default: false, only execute)
- `--mock`: Use mock prover (faster, for testing)
- `--output <dir>`: Output directory for proof (default: ./proofs)

## Examples

```bash
# Execute test-tokio-elf
./target/release/test-runner --elf ../elf/test-tokio-elf

# Execute and generate mock proof
./target/release/test-runner --elf ../elf/test-tokio-elf --prove --mock

# Execute and generate real proof
./target/release/test-runner --elf ../elf/test-tokio-thread-elf --prove --output ./my-proofs
```

