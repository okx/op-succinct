#!/usr/bin/env bash
# End-to-end negative tests for `agg_tee_execute`.
#
# Drives the compiled binary against a known-good TEE proof and a set of
# mutated copies, asserting each mutation triggers the expected failure
# (or, for fields the guest no longer reads, that mutation still passes).
#
# The aggregation guest's actual checks (see programs/aggregation/src/main.rs):
#   1. signature length == 65 bytes
#   2. signature.v ∈ {27, 28}  (enforced via `checked_sub(27)`)
#   3. EIP712 digest of `RangeJournal {EXPECTED_PCR0_HASH, configHash,
#      l1OriginHash, l2BlockNumber, prevOutputRoot, outputRoot}` →
#      ecrecover yields `recovered_signer`
#   4. `recovered_signer == attestation-derived signer`
#   5. l1 head must appear in the provided L1 header chain
#
# Notes vs older revisions of this script:
#   * The wire `pcr0` field is NOT read by the guest — it pins PCR0 to a
#     vkey-baked constant. Flipping wire pcr0 must NOT cause a failure.
#   * The "approved enclave set" was removed; signer is now sourced from
#     the per-cycle attestation. Failure messages changed accordingly.
#
# Usage:
#   # from /data/xlayer_user/op-succinct
#   bash scripts/prove/test_tee_execute.sh
#
# Required environment (no defaults that work without it):
#   PROOF_HEX        — ABI-encoded RangeJournalWire blob hex (no 0x).
#                      Get it from a successful mock-proposer run:
#                        cat /tmp/tee_proof.hex
#                      OR set via `PROOF_HEX_FILE=path/to/proof.hex`.
#   ATTESTATION_HEX  — AWS Nitro attestation doc hex (no 0x) for the SAME
#                      enclave session that produced PROOF_HEX. Get via:
#                        curl -s $TEE_HOST/tee/info | jq -r '.data.attestationDoc' \
#                          | base64 -d | xxd -p -c0
#                      OR set via `ATTESTATION_HEX_FILE=path/to/attest.hex`.
#
# Optional environment (defaults shown):
#   BIN              — ./target/release/agg_tee_execute
#   L1_RPC           — http://localhost:8545
#   TEE_HOST         — http://localhost:18081  (only used by the
#                      "fetch from tee-host" convenience below)
#   ONLY_CASE        — empty (run all); set to a case name substring to run
#                      only matching cases, e.g. ONLY_CASE=baseline.

set -uo pipefail

BIN="${BIN:-./target/release/agg_tee_execute}"
L1_RPC="${L1_RPC:-http://localhost:8545}"
TEE_HOST="${TEE_HOST:-http://localhost:18081}"
ONLY_CASE="${ONLY_CASE:-}"

# ----- Load proof + attestation -----------------------------------------------

load_hex_var() {
    # $1 = var name, $2 = corresponding *_FILE var name, $3 = friendly label
    local var=$1 file_var=$2 label=$3
    local file=${!file_var:-}
    if [[ -n "${file}" ]]; then
        [[ -r "${file}" ]] || { echo "ERROR: ${file_var}=${file} not readable"; exit 1; }
        # strip whitespace/newlines + optional 0x prefix
        local v
        v=$(tr -d '[:space:]' <"${file}")
        v=${v#0x}
        printf -v "${var}" '%s' "${v}"
    fi
    local v=${!var:-}
    v=${v#0x}
    printf -v "${var}" '%s' "${v}"
    if [[ -z "${!var}" ]]; then
        echo "ERROR: ${label} not provided. Set ${var}=<hex> or ${file_var}=<path>."
        exit 1
    fi
}

load_hex_var PROOF_HEX       PROOF_HEX_FILE       "PROOF_HEX"
load_hex_var ATTESTATION_HEX ATTESTATION_HEX_FILE "ATTESTATION_HEX"

GOOD_HEX="${PROOF_HEX}"   # alias to keep references readable below

# ----- Helpers ----------------------------------------------------------------

# Flip a single hex char at given position. 0→f, f→0, else +1 (mod 16).
flip_char() {
    local s=$1 pos=$2
    local orig="${s:$pos:1}"
    local new
    case "$orig" in
        0) new="f" ;;
        f|F) new="0" ;;
        *)
           local n=$(printf '%d' "0x$orig")
           n=$(( (n + 1) % 16 ))
           new=$(printf '%x' "$n")
           ;;
    esac
    echo "${s:0:$pos}${new}${s:$((pos+1))}"
}

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# Run one case and assert outcome.
# Args:
#   $1 case name
#   $2 proof hex (no 0x prefix)
#   $3 expected outcome: "pass" or "fail"
#   $4 if fail: extended-regex the output must match (egrep)
run_case() {
    local name=$1 proof=$2 expect=$3 pattern=${4:-}

    if [[ -n "${ONLY_CASE}" && "${name}" != *"${ONLY_CASE}"* ]]; then
        SKIP_COUNT=$((SKIP_COUNT+1))
        return
    fi

    echo
    echo "===== Case: $name ====="
    echo "expect: $expect ${pattern:+(match: $pattern)}"

    local output
    output=$("$BIN" \
        --l1-rpc "$L1_RPC" \
        --proof "0x$proof" \
        --attestation "0x$ATTESTATION_HEX" \
        2>&1) || true

    # A run "passed" only when ALL of:
    #   - exit code 0
    #   - output contains the success banner
    #   - output does NOT contain the explicit failure banner
    # The last condition guards against the SP1 CPU executor swallowing
    # in-guest panics and returning Ok(empty pv) — the binary's empty-pv
    # check turns that into "❌ ... guest panicked", which must count as
    # failure here too.
    local saw_pass saw_fail
    grep -qF "aggregation execute passed" <<<"$output" && saw_pass=1 || saw_pass=0
    grep -qF "aggregation execute failed" <<<"$output" && saw_fail=1 || saw_fail=0

    if [[ "$expect" == "pass" ]]; then
        if [[ $saw_pass -eq 1 && $saw_fail -eq 0 ]]; then
            echo "[OK]"
            PASS_COUNT=$((PASS_COUNT+1))
        else
            echo "[FAIL] expected pass but didn't see clean success. Last 20 lines:"
            tail -20 <<<"$output"
            FAIL_COUNT=$((FAIL_COUNT+1))
        fi
    else
        if [[ $saw_pass -eq 1 && $saw_fail -eq 0 ]]; then
            echo "[FAIL] expected fail but program passed. Last 20 lines:"
            tail -20 <<<"$output"
            FAIL_COUNT=$((FAIL_COUNT+1))
        elif [[ -n "$pattern" ]] && ! grep -qE "$pattern" <<<"$output"; then
            echo "[FAIL] expected fail with pattern /$pattern/, but it didn't match. Last 20 lines:"
            tail -20 <<<"$output"
            FAIL_COUNT=$((FAIL_COUNT+1))
        else
            echo "[OK]"
            PASS_COUNT=$((PASS_COUNT+1))
        fi
    fi
}

# ----- Sanity checks ---------------------------------------------------------

echo "binary:    $BIN"
echo "L1 RPC:    $L1_RPC"
echo "proof:     ${#GOOD_HEX} hex chars"
echo "attest:    ${#ATTESTATION_HEX} hex chars"
[[ -x "$BIN" ]] || { echo "binary not executable; build it first with: cargo build --release --bin agg_tee_execute"; exit 1; }

# Broad signer-mismatch pattern. The guest emits an assert_eq! which Rust
# renders as 'assertion `left == right` failed: TEE signer must match
# attested enclave pubkey'. ecrecover can also fail outright on a malformed
# (r,s) and panic from inside `Signature::from_slice` or
# `recover_from_prehash` — accept either, plus a few likely substrings.
SIGNER_MISMATCH_RE='TEE signer must match attested enclave pubkey|ecrecover|invalid recovery id|could not recover verifying key|malformed \(r,s\) signature'

# ============================================================================
# Cases
# ============================================================================

# Case 0 — baseline. Known-good proof + matching attestation should pass.
run_case "baseline" \
    "$GOOD_HEX" \
    "pass"

# Case 1 — corrupt signature `s`. Flip a byte in the middle of the signature.
# Either ecrecover yields a junk key, recover fails, or the recovered signer
# != attested signer.
BAD_SIG_S=$(flip_char "$GOOD_HEX" 570)
run_case "corrupt signature s byte" \
    "$BAD_SIG_S" \
    "fail" \
    "$SIGNER_MISMATCH_RE"

# Case 2 — `v` below 27. checked_sub(27) underflows → guest panics with
# 'signature v must be 27 or 28'. We use 0x00 to guarantee underflow;
# v=0x1d (= 29) would survive checked_sub and fall through to ecrecover.
BAD_SIG_V="${GOOD_HEX:0:640}00${GOOD_HEX:642}"
run_case "signature v below 27 (underflow)" \
    "$BAD_SIG_V" \
    "fail" \
    "signature v must be 27 or 28"

# Case 3 — flip a byte in wire `pcr0`. The guest pins PCR0 to a vkey-baked
# constant and DOES NOT read wire pcr0. The signature is unchanged → digest
# unchanged → ecrecover yields the same signer → must STILL PASS.
# Documents the no-op invariant.
NOOP_PCR0=$(flip_char "$GOOD_HEX" 5)
run_case "wire pcr0 flip is a no-op (guest pins PCR0)" \
    "$NOOP_PCR0" \
    "pass"

# Case 4 — flip configHash. Goes into BootInfoStruct.rollupConfigHash →
# journal reconstruction in the guest uses the flipped value → digest
# changes → ecrecover yields a different signer → mismatch.
BAD_CFG=$(flip_char "$GOOD_HEX" 70)
run_case "flipped configHash byte" \
    "$BAD_CFG" \
    "fail" \
    "$SIGNER_MISMATCH_RE"

# Case 5 — flip l1OriginHash. Binary tries to fetch L1 header by that hash
# BEFORE entering SP1; L1 RPC returns "block not found" → binary aborts
# with a context error mentioning l1_origin.
BAD_L1=$(flip_char "$GOOD_HEX" 130)
run_case "non-existent l1OriginHash" \
    "$BAD_L1" \
    "fail" \
    "fetch L1 header at l1_origin|Failed to get L1 header|block .* not found"

# Case 6 — flip outputRoot. Same mechanism as Case 4 (boot_info field, used
# in journal reconstruction inside the guest).
BAD_OUT=$(flip_char "$GOOD_HEX" 322)
run_case "flipped outputRoot byte" \
    "$BAD_OUT" \
    "fail" \
    "$SIGNER_MISMATCH_RE"

# Case 7 — flip prevOutputRoot (256..320 in the wire layout).
BAD_PREV=$(flip_char "$GOOD_HEX" 260)
run_case "flipped prevOutputRoot byte" \
    "$BAD_PREV" \
    "fail" \
    "$SIGNER_MISMATCH_RE"

# Case 8 — flip l2BlockNumber. uint64 lives at offset 192..256. Flip a low
# byte to change the number without overflowing u64 bounds.
BAD_L2N=$(flip_char "$GOOD_HEX" 254)
run_case "flipped l2BlockNumber byte" \
    "$BAD_L2N" \
    "fail" \
    "$SIGNER_MISMATCH_RE"

# ============================================================================
# Summary
# ============================================================================
echo
echo "==== Summary ===="
echo "passed:  $PASS_COUNT"
echo "failed:  $FAIL_COUNT"
echo "skipped: $SKIP_COUNT"

# Cases that need rebuilding the ELF (not automated; ~10 min each):
#
#   * Rotate EXPECTED_PCR0_HASH: edit programs/aggregation/src/main.rs to a
#     different constant, `just build-agg-elf`, re-run baseline. Should fail
#     with $SIGNER_MISMATCH_RE because the guest reconstructs the journal
#     with the new pcr0 and the signature was bound to the old one.
#
#   * Fresh enclave session: restart the enclave so OsRng generates a new
#     ENCLAVE_KEY, capture a new proof + attestation, run baseline. Should
#     still pass since signer is derived from the new attestation.
#     If you swap signature+proof from session A with attestation from
#     session B, baseline must fail with $SIGNER_MISMATCH_RE — that's the
#     keystone check the aggregation guest enforces.

[[ $FAIL_COUNT -eq 0 ]] && exit 0 || exit 1
