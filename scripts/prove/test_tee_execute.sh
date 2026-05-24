#!/usr/bin/env bash
# End-to-end negative tests for `agg_tee_execute`.
#
# Drives the existing release binary against a small set of mutated proofs.
# Each negative case asserts a specific panic / error message — proving the
# aggregation program is actually checking what it claims to check, not just
# rubber-stamping anything that decodes.
#
# Cases that require recompiling the aggregation ELF (e.g. rotating
# EXPECTED_PCR0_HASH / AWS_NITRO_ROOT_G1_PUBKEY trust anchors) are documented
# at the bottom but not automated, since rebuilding the ELF takes ~10 minutes.
#
# Usage:
#   # 1. Fetch the attestation doc from a running tee-host:
#   ATTEST_HEX=$(curl -s http://localhost:18080/tee/info | \
#                jq -r .data.attestationDoc | base64 -d | xxd -p | tr -d '\n')
#
#   # 2. Run the suite from /data/xlayer_user/op-succinct:
#   ATTESTATION="$ATTEST_HEX" bash scripts/prove/test_tee_execute.sh
#
# Knobs (env vars):
#   ATTESTATION — hex of raw COSE_Sign1 attestation doc (required)
#   BIN         — compiled binary path (default: ./target/release/agg_tee_execute)
#   L1_RPC      — L1 execution RPC (default: http://localhost:8545)

set -uo pipefail

BIN="${BIN:-./target/release/agg_tee_execute}"
L1_RPC="${L1_RPC:-http://localhost:8545}"
ATTESTATION="${ATTESTATION:-}"

if [[ -z "$ATTESTATION" ]]; then
    echo "ERROR: ATTESTATION env var required (raw COSE_Sign1 hex)"
    echo "Fetch from running tee-host:"
    echo "  ATTEST_HEX=\$(curl -s http://localhost:18080/tee/info | \\"
    echo "               jq -r .data.attestationDoc | base64 -d | xxd -p | tr -d '\\n')"
    exit 1
fi

# The known-good proof — the one we just verified passes end-to-end.
# Field map (each 32 bytes = 64 hex chars):
#   [0..64]    pcr0
#   [64..128]  configHash
#   [128..192] l1OriginHash
#   [192..256] l2BlockNumber
#   [256..320] prevOutputRoot
#   [320..384] outputRoot
#   [384..448] offset to signature bytes (= 0xe0)
#   [448..512] signature length (= 0x41 = 65)
#   [512..642] signature (65 bytes = 130 hex chars)
#   [642..]    padding to 32-byte boundary
GOOD_HEX="c980e59163ce244bb4bb6211f48c7b46f88a4f40943e84eb99bdc41e129bd293012575008d59aee13d8be1b9eb7dbda2a8f0210c9c6cbf91c93e7cdd11d590ec52e956f919387e7c5d3007260a066b568044425ebf1bc58e6882452ab0de86a1000000000000000000000000000000000000000000000000000000000086eef8933fa4957f41b30c502e7b46b8029de8f4373964a286b734d14e943e9b7f53748ecd5beb85fae90bac04d1cb86e668be5068dc0915310158071909b9c093677400000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000004111bc3e4f151f88ea54aeb9c64b768b999ebc295d73ee301b3a43c777f9a4a80f1f56133ccaf7972d2c843c3046e5cca63a19cd7341a4aefd150d7eb2f8bb165c1b00000000000000000000000000000000000000000000000000000000000000"

# Flip a single hex char at given position. Wraps 0→f, otherwise xors low bit
# so the new char is guaranteed different from the original.
flip_char() {
    local s=$1 pos=$2
    local orig="${s:$pos:1}"
    local new
    case "$orig" in
        0) new="f" ;;
        f|F) new="0" ;;
        *) # bump by 1 mod 16 in hex
           local n=$(printf '%d' "0x$orig")
           n=$(( (n + 1) % 16 ))
           new=$(printf '%x' "$n")
           ;;
    esac
    echo "${s:0:$pos}${new}${s:$((pos+1))}"
}

# Run one case and assert outcome.
# Args:
#   $1 case name
#   $2 proof hex (no 0x prefix)
#   $3 expected outcome: "pass" or "fail"
#   $4 if fail: regex the output must match (egrep)
PASS_COUNT=0
FAIL_COUNT=0
run_case() {
    local name=$1 proof=$2 expect=$3 pattern=${4:-}
    echo
    echo "===== Case: $name ====="
    echo "expect: $expect ${pattern:+(match: $pattern)}"

    local output
    output=$("$BIN" --l1-rpc "$L1_RPC" --attestation "$ATTESTATION" --proof "0x$proof" 2>&1) || true

    if [[ "$expect" == "pass" ]]; then
        if grep -qF "aggregation execute passed" <<<"$output"; then
            echo "[OK]"
            PASS_COUNT=$((PASS_COUNT+1))
        else
            echo "[FAIL] expected pass but didn't see success line. Last 15 lines:"
            tail -15 <<<"$output"
            FAIL_COUNT=$((FAIL_COUNT+1))
        fi
    else
        # expect fail
        if grep -qF "aggregation execute passed" <<<"$output"; then
            echo "[FAIL] expected fail but program passed. Last 15 lines:"
            tail -15 <<<"$output"
            FAIL_COUNT=$((FAIL_COUNT+1))
        elif [[ -n "$pattern" ]] && ! grep -qE "$pattern" <<<"$output"; then
            echo "[FAIL] expected fail with pattern /$pattern/, but it didn't match. Last 15 lines:"
            tail -15 <<<"$output"
            FAIL_COUNT=$((FAIL_COUNT+1))
        else
            echo "[OK]"
            PASS_COUNT=$((PASS_COUNT+1))
        fi
    fi
}

echo "binary: $BIN"
echo "L1 RPC: $L1_RPC"
[[ -x "$BIN" ]] || { echo "binary not executable; build it first with: cargo build --release --bin agg_tee_execute"; exit 1; }

# ----------------------------------------------------------------------------
# Case 0 — baseline. Known-good proof should pass.
# ----------------------------------------------------------------------------
run_case "baseline: known-good proof passes" \
    "$GOOD_HEX" \
    "pass"

# ----------------------------------------------------------------------------
# Case 1 — corrupt signature `s` component.
# Flip a byte in the middle of the signature (chars 512..642). The EIP712
# digest is unchanged, but ecrecover yields a different signer that no
# longer matches the attestation-derived session signer.
# ----------------------------------------------------------------------------
BAD_SIG_S=$(flip_char "$GOOD_HEX" 570)
run_case "corrupt signature s byte" \
    "$BAD_SIG_S" \
    "fail" \
    "TEE signer must match attested enclave pubkey|ecrecover"

# ----------------------------------------------------------------------------
# Case 2 — corrupt signature `v` byte (last byte of sig, position 640-641).
# `v` ∈ {27, 28} is the recovery id. Flipping it to 0x1d (= 29) triggers
# the `signature v must be 27 or 28` assert.
# ----------------------------------------------------------------------------
BAD_SIG_V="${GOOD_HEX:0:640}1d${GOOD_HEX:642}"
run_case "out-of-range signature v" \
    "$BAD_SIG_V" \
    "fail" \
    "signature v must be 27 or 28"

# ----------------------------------------------------------------------------
# Case 3 — flip a byte in pcr0 (in the wire blob).
# The pcr0 field in the wire is informational only since the guest uses the
# vkey-baked EXPECTED_PCR0_HASH. So this mutation should *not* affect
# verification — baseline still passes even with a bogus wire pcr0.
# (If this case fails, something's reading pcr0 from the wire when it
# shouldn't.)
# ----------------------------------------------------------------------------
BAD_PCR0=$(flip_char "$GOOD_HEX" 5)
run_case "flipped pcr0 byte (wire only; vkey pcr0 unchanged)" \
    "$BAD_PCR0" \
    "pass"

# ----------------------------------------------------------------------------
# Case 4 — flip a byte in configHash.
# digest changes → ecrecover yields a different signer → mismatch vs
# attestation-derived session signer.
# ----------------------------------------------------------------------------
BAD_CFG=$(flip_char "$GOOD_HEX" 70)
run_case "flipped configHash byte" \
    "$BAD_CFG" \
    "fail" \
    "TEE signer must match attested enclave pubkey"

# ----------------------------------------------------------------------------
# Case 5 — flip l1OriginHash. The host queries L1 for a block hash that
# doesn't exist on chain → fetcher returns Err → binary aborts before
# entering SP1 execute.
# ----------------------------------------------------------------------------
BAD_L1=$(flip_char "$GOOD_HEX" 130)
run_case "non-existent l1OriginHash" \
    "$BAD_L1" \
    "fail" \
    "fetch L1 header at l1_origin|Failed to get L1 header|block .* not found"

# ----------------------------------------------------------------------------
# Case 6 — flip a byte in outputRoot.
# Same as Case 4: digest changes, signer mismatch.
# ----------------------------------------------------------------------------
BAD_OUT=$(flip_char "$GOOD_HEX" 322)
run_case "flipped outputRoot byte" \
    "$BAD_OUT" \
    "fail" \
    "TEE signer must match attested enclave pubkey"

# ----------------------------------------------------------------------------
# Case 7 — corrupt attestation doc.
# Flip a byte in the COSE payload → COSE signature verify fails inside the
# guest (`attestation: COSE_Sign1 signature invalid`).
# ----------------------------------------------------------------------------
BAD_ATTEST="${ATTESTATION:0:200}$(flip_char "$ATTESTATION" 200 | cut -c201)${ATTESTATION:201}"
echo
echo "===== Case: corrupted attestation doc ====="
echo "expect: fail (match: attestation:|COSE)"
output=$("$BIN" --l1-rpc "$L1_RPC" --attestation "$BAD_ATTEST" --proof "0x$GOOD_HEX" 2>&1) || true
if grep -qF "aggregation execute passed" <<<"$output"; then
    echo "[FAIL] corrupted attestation should have been rejected"
    tail -15 <<<"$output"
    FAIL_COUNT=$((FAIL_COUNT+1))
elif grep -qE "attestation:|COSE" <<<"$output"; then
    echo "[OK]"
    PASS_COUNT=$((PASS_COUNT+1))
else
    echo "[FAIL] expected attestation:/COSE match. Last 15 lines:"
    tail -15 <<<"$output"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
echo
echo "==== Summary ===="
echo "passed: $PASS_COUNT"
echo "failed: $FAIL_COUNT"

# Cases that need rebuilding the ELF (not automated):
#
#   * Trust-anchor rotation: edit EXPECTED_PCR0_HASH or
#     AWS_NITRO_ROOT_G1_PUBKEY in programs/aggregation/src/main.rs, run
#     `just build-agg-elf`, and re-run the baseline. EXPECTED_PCR0_HASH
#     mismatch surfaces as "PCR0 hash mismatch" from attestation verify;
#     wrong AWS root pubkey surfaces as the cert-chain verify failing.
#
#   * Enclave restart (fresh ENCLAVE_KEY): the attestation doc binds the new
#     pubkey, so the new signer is implicit — no source change needed.
#     Re-running with the new (attestation, proof) pair should still pass
#     as long as PCR0 is unchanged (same EIF).

[[ $FAIL_COUNT -eq 0 ]] && exit 0 || exit 1
