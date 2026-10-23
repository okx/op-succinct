#!/usr/bin/env bash
# Mutation proof: the signer-wiring tests must FAIL when the wiring step is removed.
#
# The mutation comments out the adapter wiring inside the shared startup function. Two independent
# checks must then fail — the Rust case that reads the adapter back, and the binary-driven case that
# looks up the seeded ID over HTTP. Both must pass again once the file is restored.
#
# The verdict is derived from the actual exit codes, never assumed:
#   CLOSED requires BUILD_RC=0, RUST_RC!=0, BINARY_RC!=0, RESTORE_BUILD_RC=0, RESTORED_RC=0 and
#   RESTORED_RUST_RC=0.
#
# Run from the repository root. The trap restores the file and rebuilds on every exit path.
set -uo pipefail

MUTATION_LOG="docs/superpowers/evidence/gap1-mutation-run.log"
SIGNER_RS="fault-proof/src/tz/defender/signer.rs"
P2_DIR="fault-proof/tests/defender_p2_verification"
mkdir -p "$(dirname "$MUTATION_LOG")"

restore_and_rebuild() {
  echo "=== trap: restoring ${SIGNER_RS} ==="
  git checkout "$SIGNER_RS" 2>&1
  echo "=== trap: rebuilding after restore ==="
  cargo build --bin tz-defender --features "tz,xlayer-verify-test-utils" 2>&1
  local rc=$?
  echo "trap restore+rebuild rc=$rc"
}
trap restore_and_rebuild EXIT

{
  echo "=== Signer wiring mutation run $(date -u) ==="
  echo "Mutation: comment out challenge.set_signer(...) in the shared startup function"
  echo ""

  # ---- Step 1: scripted, verifiable mutation ----
  echo "--- Applying mutation ---"
  sed -i '0,/challenge\.set_signer(Arc::new(lock\.clone()));/s//\/\/ challenge.set_signer(Arc::new(lock.clone())); \/\/ MUTATION/' "$SIGNER_RS"
  if grep -q '// challenge.set_signer(Arc::new(lock.clone())); // MUTATION' "$SIGNER_RS"; then
    echo "MUTATION VERIFIED: the wiring call is commented out in the shared startup function"
  else
    echo "FAIL: mutation did not apply — the wiring line was not found"
    echo "Verdict: OPEN (mutation failed to apply)"
    exit 1
  fi

  # ---- Step 2: build with the mutation ----
  echo ""
  echo "--- Rebuilding with mutation ---"
  cargo build --bin tz-defender --features "tz,xlayer-verify-test-utils" 2>&1
  BUILD_RC=$?
  if [ "$BUILD_RC" -ne 0 ]; then
    echo "FAIL: build failed with rc=$BUILD_RC"
    echo "BUILD_RC=$BUILD_RC RUST_RC=N/A BINARY_RC=N/A"
    echo "Verdict: OPEN (build failure)"
    exit 1
  fi
  echo "Build OK (BUILD_RC=0)"

  # ---- Step 3: the Rust case that reads the adapter back must fail ----
  echo ""
  echo "--- Rust case with mutation (expects failure) ---"
  cargo test -p op-succinct-fp --features "tz,xlayer-verify-test-utils" \
    --test tz_defender_integration -- shared_construction_ptr_equality 2>&1
  RUST_RC=$?
  echo "Rust case rc=$RUST_RC"

  # ---- Step 4: the binary-driven lookup must fail ----
  echo ""
  echo "--- Binary-driven case with mutation (expects failure) ---"
  TZ_DEFENDER_BIN=./target/debug/tz-defender \
    TEST_OUT_DIR="$P2_DIR/test_output/mutation" \
    "$P2_DIR/run_gap1_binary_test.sh" 2>&1
  BINARY_RC=$?
  echo "Binary-driven case rc=$BINARY_RC"

  # ---- Step 5: restore and rebuild ----
  echo ""
  echo "--- Restoring the wiring call ---"
  git checkout "$SIGNER_RS"
  cargo build --bin tz-defender --features "tz,xlayer-verify-test-utils" 2>&1
  RESTORE_BUILD_RC=$?
  echo "Restore build rc=$RESTORE_BUILD_RC"

  if [ "$RESTORE_BUILD_RC" -ne 0 ]; then
    echo "FAIL: the restored tree does not build — later results cannot be trusted"
    echo "BUILD_RC=$BUILD_RC RUST_RC=$RUST_RC BINARY_RC=$BINARY_RC RESTORE_BUILD_RC=$RESTORE_BUILD_RC"
    echo "Verdict: OPEN (restore build failure)"
    exit 1
  fi

  # ---- Step 6: both cases must pass again ----
  echo ""
  echo "--- Binary-driven case after restore (expects pass) ---"
  TZ_DEFENDER_BIN=./target/debug/tz-defender \
    TEST_OUT_DIR="$P2_DIR/test_output/restored" \
    "$P2_DIR/run_gap1_binary_test.sh" 2>&1
  RESTORED_RC=$?
  echo "Restored binary-driven case rc=$RESTORED_RC"

  echo ""
  echo "--- Rust case after restore (expects pass) ---"
  cargo test -p op-succinct-fp --features "tz,xlayer-verify-test-utils" \
    --test tz_defender_integration -- shared_construction_ptr_equality 2>&1
  RESTORED_RUST_RC=$?
  echo "Restored Rust case rc=$RESTORED_RUST_RC"

  # ---- Step 7: verdict from the exit codes ----
  echo ""
  echo "=== Mutation exit codes ==="
  echo "BUILD_RC=$BUILD_RC (expected 0)"
  echo "RUST_RC=$RUST_RC (expected != 0)"
  echo "BINARY_RC=$BINARY_RC (expected != 0)"
  echo "RESTORE_BUILD_RC=$RESTORE_BUILD_RC (expected 0)"
  echo "RESTORED_RC=$RESTORED_RC (expected 0)"
  echo "RESTORED_RUST_RC=$RESTORED_RUST_RC (expected 0)"
  echo ""

  if [ "$BUILD_RC" -eq 0 ] && [ "$RUST_RC" -ne 0 ] && [ "$BINARY_RC" -ne 0 ] && \
     [ "$RESTORE_BUILD_RC" -eq 0 ] && [ "$RESTORED_RC" -eq 0 ] && \
     [ "$RESTORED_RUST_RC" -eq 0 ]; then
    echo "Verdict: wiring mutation is DETECTED"
    echo "  mutated: binary_rc=$BINARY_RC rust_rc=$RUST_RC"
    echo "  restored: binary_rc=$RESTORED_RC rust_rc=$RESTORED_RUST_RC"
  else
    echo "Verdict: wiring mutation is NOT DETECTED"
    echo "  BUILD_RC=$BUILD_RC RUST_RC=$RUST_RC BINARY_RC=$BINARY_RC"
    echo "  RESTORE_BUILD_RC=$RESTORE_BUILD_RC"
    echo "  RESTORED_RC=$RESTORED_RC RESTORED_RUST_RC=$RESTORED_RUST_RC"
    exit 1
  fi
} | tee "$MUTATION_LOG"