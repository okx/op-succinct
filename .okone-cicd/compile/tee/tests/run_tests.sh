#!/usr/bin/env bash
# Test harness for .okone-cicd/compile/tee/ scripts
# Covers Decision Matrix scenarios DM-1.x through DM-4.x
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
STUBS_DIR="${SCRIPT_DIR}/stubs"

PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1 — $2"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP: $1 — $2"; SKIP=$((SKIP + 1)); }

setup_test_dir() {
    TEST_DIR="$(mktemp -d)"
    export STUB_LOG_DIR="${TEST_DIR}/logs"
    mkdir -p "${STUB_LOG_DIR}"
    chmod +x "${STUBS_DIR}"/*
}

teardown_test_dir() {
    rm -rf "${TEST_DIR}" 2>/dev/null || true
}

# ============================================================
# FR-1: build.sh tests
# ============================================================
echo "=== FR-1: build.sh ==="

# DM-1.1: Toolchain mismatch abort
test_dm_1_1() {
    setup_test_dir
    cd "${TEST_DIR}"
    mkdir -p fault-proof/tee/enclave
    echo '[package]\nname = "xlayer-tee-enclave"' > fault-proof/tee/enclave/Cargo.toml
    touch Cargo.lock
    echo '[toolchain]\nchannel = "nightly-2025-09-15"' > rust-toolchain.toml
    git init -q . && git add -A && git commit -q -m "init"

    export RUSTC_STUB_VERSION="1.80.0 (stable-2025-06-01)"
    export PATH="${STUBS_DIR}:${PATH}"

    OUTPUT="$(bash "${TEE_DIR}/build.sh" 2>&1 || true)"
    EXIT_CODE=$?

    if echo "${OUTPUT}" | grep -q "nightly-2025-09-15"; then
        pass "DM-1.1: toolchain mismatch abort mentions expected version"
    else
        fail "DM-1.1" "output missing expected toolchain version"
    fi

    if [ ! -f tee-enclave.tar ]; then
        pass "DM-1.1: no artifact produced"
    else
        fail "DM-1.1" "tee-enclave.tar should not exist"
    fi

    teardown_test_dir
}

# DM-1.3: Successful release build
test_dm_1_3() {
    setup_test_dir
    cd "${TEST_DIR}"
    mkdir -p fault-proof/tee/enclave
    echo '[package]\nname = "xlayer-tee-enclave"' > fault-proof/tee/enclave/Cargo.toml
    touch Cargo.lock
    echo '[toolchain]\nchannel = "nightly-2025-09-15"' > rust-toolchain.toml
    git init -q . && git add -A && git commit -q -m "init"

    # Copy script support files
    cp "${TEE_DIR}/Dockerfile" "${TEST_DIR}/"
    cp "${TEE_DIR}/build_eif.sh" "${TEST_DIR}/"
    cp "${TEE_DIR}/start.sh" "${TEST_DIR}/"
    cp "${TEE_DIR}/stop.sh" "${TEST_DIR}/"

    # Patch build.sh SCRIPT_DIR to find support files
    export RUSTC_STUB_VERSION="1.82.0-nightly (nightly-2025-09-15)"
    export RUSTUP_MUSL_INSTALLED=true
    export PATH="${STUBS_DIR}:${PATH}"

    # Create a modified build.sh that uses TEST_DIR for SCRIPT_DIR
    sed "s|SCRIPT_DIR=.*|SCRIPT_DIR=\"${TEST_DIR}\"|" "${TEE_DIR}/build.sh" > "${TEST_DIR}/test_build.sh"
    chmod +x "${TEST_DIR}/test_build.sh"

    OUTPUT="$(bash "${TEST_DIR}/test_build.sh" release 2>&1 || true)"

    if echo "${OUTPUT}" | grep -q "enclave binary hash:"; then
        pass "DM-1.3: binary hash printed"
    else
        fail "DM-1.3" "missing hash output: ${OUTPUT}"
    fi

    if echo "${OUTPUT}" | grep -q "artifact: tee-enclave.tar"; then
        pass "DM-1.3: artifact message printed"
    else
        fail "DM-1.3" "missing artifact message"
    fi

    if [ -f tee-enclave.tar ]; then
        pass "DM-1.3: tee-enclave.tar produced"
    else
        fail "DM-1.3" "tee-enclave.tar not found"
    fi

    # Verify tar contents
    if tar -tzf tee-enclave.tar | grep -q "xlayer-tee-enclave"; then
        pass "DM-1.3: tar contains binary"
    else
        fail "DM-1.3" "tar missing binary"
    fi

    if tar -tzf tee-enclave.tar | grep -q "Dockerfile"; then
        pass "DM-1.3: tar contains Dockerfile"
    else
        fail "DM-1.3" "tar missing Dockerfile"
    fi

    # Verify cargo was called with correct flags
    if grep -q "\-\-release" "${STUB_LOG_DIR}/cargo.log" 2>/dev/null; then
        pass "DM-1.3: cargo invoked with --release"
    else
        fail "DM-1.3" "cargo not invoked with --release"
    fi

    teardown_test_dir
}

# DM-1.2: musl target not pre-installed
test_dm_1_2() {
    setup_test_dir
    cd "${TEST_DIR}"
    mkdir -p fault-proof/tee/enclave
    echo '[package]\nname = "xlayer-tee-enclave"' > fault-proof/tee/enclave/Cargo.toml
    touch Cargo.lock
    echo '[toolchain]\nchannel = "nightly-2025-09-15"' > rust-toolchain.toml
    git init -q . && git add -A && git commit -q -m "init"

    cp "${TEE_DIR}/Dockerfile" "${TEST_DIR}/"
    cp "${TEE_DIR}/build_eif.sh" "${TEST_DIR}/"
    cp "${TEE_DIR}/start.sh" "${TEST_DIR}/"
    cp "${TEE_DIR}/stop.sh" "${TEST_DIR}/"

    export RUSTC_STUB_VERSION="1.82.0-nightly (nightly-2025-09-15)"
    export RUSTUP_MUSL_INSTALLED=false
    export PATH="${STUBS_DIR}:${PATH}"

    sed "s|SCRIPT_DIR=.*|SCRIPT_DIR=\"${TEST_DIR}\"|" "${TEE_DIR}/build.sh" > "${TEST_DIR}/test_build.sh"
    chmod +x "${TEST_DIR}/test_build.sh"
    bash "${TEST_DIR}/test_build.sh" release 2>&1 || true

    if grep -q "target add" "${STUB_LOG_DIR}/rustup.log" 2>/dev/null; then
        pass "DM-1.2: rustup target add invoked"
    else
        fail "DM-1.2" "rustup target add not invoked"
    fi

    teardown_test_dir
}

# ============================================================
# FR-2: build_eif.sh tests (Part 1 — image assembly)
# ============================================================
echo ""
echo "=== FR-2: build_eif.sh (image assembly) ==="

# DM-2.1: Binary presence guard
test_dm_2_1() {
    setup_test_dir
    cd "${TEST_DIR}"
    # No xlayer-tee-enclave binary in cwd
    export PATH="${STUBS_DIR}:${PATH}"

    OUTPUT="$(bash "${TEE_DIR}/build_eif.sh" 2>&1 || true)"
    EXIT_CODE=$?

    if echo "${OUTPUT}" | grep -q "xlayer-tee-enclave not found"; then
        pass "DM-2.1: binary presence guard triggered"
    else
        fail "DM-2.1" "missing guard message"
    fi

    teardown_test_dir
}

# DM-2.4: Successful image assembly (partial — docker import stubbed)
test_dm_2_4() {
    setup_test_dir
    cd "${TEST_DIR}"
    echo "dummy-binary" > xlayer-tee-enclave
    chmod +x xlayer-tee-enclave

    export PATH="${STUBS_DIR}:${PATH}"
    export NITRO_CLI_MODE=host-bin
    export NITRO_CLI_STUB_VERSION=1.3.3

    OUTPUT="$(bash "${TEE_DIR}/build_eif.sh" 2>&1 || true)"

    if echo "${OUTPUT}" | grep -q "rootfs hash:"; then
        pass "DM-2.4: rootfs hash printed (A-15 Finding #1)"
    else
        fail "DM-2.4" "rootfs hash not printed"
    fi

    if grep -q "docker import" "${STUB_LOG_DIR}/docker.log" 2>/dev/null; then
        pass "DM-2.4: docker import invoked"
    else
        fail "DM-2.4" "docker import not invoked"
    fi

    if [ -f enclave.eif ]; then
        pass "DM-2.4: enclave.eif produced"
    else
        fail "DM-2.4" "enclave.eif not found"
    fi

    if [ -f PCR.txt ]; then
        pass "DM-2.4: PCR.txt produced"
    else
        fail "DM-2.4" "PCR.txt not found"
    fi

    teardown_test_dir
}

# DM-2.3: Docker daemon not running
test_dm_2_3() {
    setup_test_dir
    cd "${TEST_DIR}"
    echo "dummy-binary" > xlayer-tee-enclave
    chmod +x xlayer-tee-enclave

    export PATH="${STUBS_DIR}:${PATH}"
    export DOCKER_STUB_FAIL=true
    export NITRO_CLI_MODE=host-bin
    export NITRO_CLI_STUB_VERSION=1.3.3

    OUTPUT="$(bash "${TEE_DIR}/build_eif.sh" 2>&1 || true)"
    EXIT_CODE=$?

    if echo "${OUTPUT}" | grep -q "Cannot connect to the Docker daemon"; then
        pass "DM-2.3: docker failure detected"
    else
        fail "DM-2.3" "docker failure not surfaced"
    fi

    unset DOCKER_STUB_FAIL
    teardown_test_dir
}

# ============================================================
# FR-3: build_eif.sh tests (Part 2 — nitro-cli)
# ============================================================
echo ""
echo "=== FR-3: build_eif.sh (nitro-cli) ==="

# DM-3.2: Host nitro-cli version mismatch
test_dm_3_2() {
    setup_test_dir
    cd "${TEST_DIR}"
    echo "dummy-binary" > xlayer-tee-enclave
    chmod +x xlayer-tee-enclave

    export PATH="${STUBS_DIR}:${PATH}"
    export NITRO_CLI_MODE=host-bin
    export NITRO_CLI_STUB_VERSION=1.2.0

    OUTPUT="$(bash "${TEE_DIR}/build_eif.sh" 2>&1 || true)"

    if echo "${OUTPUT}" | grep -q "1.2.0" && echo "${OUTPUT}" | grep -q "1.3.3"; then
        pass "DM-3.2: version mismatch abort with both versions"
    else
        fail "DM-3.2" "missing version mismatch message"
    fi

    teardown_test_dir
}

# DM-3.5: Auto mode version mismatch (no silent fallback)
test_dm_3_5() {
    setup_test_dir
    cd "${TEST_DIR}"
    echo "dummy-binary" > xlayer-tee-enclave
    chmod +x xlayer-tee-enclave

    export PATH="${STUBS_DIR}:${PATH}"
    export NITRO_CLI_MODE=auto
    export NITRO_CLI_STUB_VERSION=1.2.0

    OUTPUT="$(bash "${TEE_DIR}/build_eif.sh" 2>&1 || true)"

    if echo "${OUTPUT}" | grep -q "1.2.0" && echo "${OUTPUT}" | grep -q "1.3.3"; then
        pass "DM-3.5: auto mode version mismatch abort"
    else
        fail "DM-3.5" "should abort on version mismatch in auto mode"
    fi

    # Verify no source build attempted
    if ! grep -q "clone" "${STUB_LOG_DIR}/git.log" 2>/dev/null; then
        pass "DM-3.5: no source build fallback attempted"
    else
        fail "DM-3.5" "source build should not be attempted on version mismatch"
    fi

    teardown_test_dir
}

# ============================================================
# FR-4a: start.sh tests
# ============================================================
echo ""
echo "=== FR-4a: start.sh ==="

# DM-4.1: Insufficient arguments
test_dm_4_1() {
    setup_test_dir
    cd "${TEST_DIR}"
    export PATH="${STUBS_DIR}:${PATH}"

    OUTPUT="$(bash "${TEE_DIR}/start.sh" 2>&1 || true)"

    if echo "${OUTPUT}" | grep -q "start.sh <CPU_COUNT> <MEMORY_MB>"; then
        pass "DM-4.1: usage message on insufficient args"
    else
        fail "DM-4.1" "missing usage message"
    fi

    teardown_test_dir
}

# DM-4.3: Missing host binary
test_dm_4_3() {
    setup_test_dir
    cd "${TEST_DIR}"
    touch enclave.eif
    # No xlayer-tee-host binary
    export PATH="${STUBS_DIR}:${PATH}"

    OUTPUT="$(bash "${TEE_DIR}/start.sh" 2 512 2>&1 || true)"

    if echo "${OUTPUT}" | grep -q "enclave started"; then
        pass "DM-4.3: enclave started before host check"
    else
        fail "DM-4.3" "enclave start message missing"
    fi

    if echo "${OUTPUT}" | grep -q "xlayer-tee-host not found"; then
        pass "DM-4.3: host binary error detected"
    else
        fail "DM-4.3" "missing host binary error"
    fi

    teardown_test_dir
}

# DM-4.4: Full successful start with config.toml
test_dm_4_4() {
    setup_test_dir
    cd "${TEST_DIR}"
    touch enclave.eif
    echo '#!/bin/bash\nsleep 300' > xlayer-tee-host
    chmod +x xlayer-tee-host
    echo "[enclave]\nvsock_cid = 4" > config.toml
    export PATH="${STUBS_DIR}:${PATH}"

    OUTPUT="$(bash "${TEE_DIR}/start.sh" 2 512 2>&1 || true)"

    if echo "${OUTPUT}" | grep -q "enclave started (cid=4)"; then
        pass "DM-4.4: enclave started with cid=4"
    else
        fail "DM-4.4" "enclave start message missing"
    fi

    if echo "${OUTPUT}" | grep -q "xlayer-tee-host started (pid="; then
        pass "DM-4.4: host started with PID"
    else
        fail "DM-4.4" "host start message missing"
    fi

    # Verify nitro-cli was called with correct args
    if grep -q "run-enclave" "${STUB_LOG_DIR}/nitro-cli.log" 2>/dev/null; then
        pass "DM-4.4: nitro-cli run-enclave invoked"
    else
        fail "DM-4.4" "nitro-cli run-enclave not invoked"
    fi

    # Kill background host process
    pkill -f "sleep 300" 2>/dev/null || true

    teardown_test_dir
}

# DM-4.5: Successful start without config.toml
test_dm_4_5() {
    setup_test_dir
    cd "${TEST_DIR}"
    touch enclave.eif
    echo '#!/bin/bash\nsleep 300' > xlayer-tee-host
    chmod +x xlayer-tee-host
    # No config.toml
    export PATH="${STUBS_DIR}:${PATH}"

    OUTPUT="$(bash "${TEE_DIR}/start.sh" 2 512 2>&1 || true)"

    if echo "${OUTPUT}" | grep -q "xlayer-tee-host started"; then
        pass "DM-4.5: host started without config.toml"
    else
        fail "DM-4.5" "host should start without config.toml"
    fi

    pkill -f "sleep 300" 2>/dev/null || true

    teardown_test_dir
}

# ============================================================
# FR-4b: stop.sh tests
# ============================================================
echo ""
echo "=== FR-4b: stop.sh ==="

# DM-4.10: Idempotent stop (nothing running)
test_dm_4_10() {
    setup_test_dir
    cd "${TEST_DIR}"
    export PATH="${STUBS_DIR}:${PATH}"
    export NITRO_ENCLAVE_RUNNING=false
    export HOST_RUNNING=false

    OUTPUT="$(bash "${TEE_DIR}/stop.sh" 2>&1)"
    EXIT_CODE=$?

    if [ "${EXIT_CODE}" -eq 0 ]; then
        pass "DM-4.10: idempotent exit code 0"
    else
        fail "DM-4.10" "expected exit 0, got ${EXIT_CODE}"
    fi

    if echo "${OUTPUT}" | grep -q "no enclave with cid=4 found"; then
        pass "DM-4.10: no enclave message"
    else
        fail "DM-4.10" "missing no-enclave message"
    fi

    if echo "${OUTPUT}" | grep -q "xlayer-tee-host not running"; then
        pass "DM-4.10: host not running message"
    else
        fail "DM-4.10" "missing host-not-running message"
    fi

    teardown_test_dir
}

# DM-4.8: Enclave running, host not running
test_dm_4_8() {
    setup_test_dir
    cd "${TEST_DIR}"
    export PATH="${STUBS_DIR}:${PATH}"
    export NITRO_ENCLAVE_RUNNING=true
    export HOST_RUNNING=false

    OUTPUT="$(bash "${TEE_DIR}/stop.sh" 2>&1)"

    if echo "${OUTPUT}" | grep -q "enclave terminated"; then
        pass "DM-4.8: enclave terminated"
    else
        fail "DM-4.8" "missing enclave terminated message"
    fi

    if echo "${OUTPUT}" | grep -q "xlayer-tee-host not running"; then
        pass "DM-4.8: host not running message"
    else
        fail "DM-4.8" "missing host-not-running message"
    fi

    teardown_test_dir
}

# ============================================================
# FR-6: Misuse guard tests
# ============================================================
echo ""
echo "=== FR-6: Misuse guards ==="

# DM-6.1: Binary presence guard (same as DM-2.1, verify exit code)
test_dm_6_1() {
    setup_test_dir
    cd "${TEST_DIR}"
    export PATH="${STUBS_DIR}:${PATH}"

    bash "${TEE_DIR}/build_eif.sh" 2>&1 || EXIT_CODE=$?

    if [ "${EXIT_CODE:-0}" -ne 0 ]; then
        pass "DM-6.1: binary guard returns non-zero exit"
    else
        fail "DM-6.1" "should exit non-zero when binary missing"
    fi

    teardown_test_dir
}

# ============================================================
# Dockerfile validation
# ============================================================
echo ""
echo "=== Dockerfile ==="

test_dockerfile() {
    if grep -q "FROM scratch" "${TEE_DIR}/Dockerfile"; then
        pass "Dockerfile: FROM scratch base"
    else
        fail "Dockerfile" "missing FROM scratch"
    fi

    if grep -q "744" "${TEE_DIR}/Dockerfile"; then
        pass "Dockerfile: chmod 744 permission"
    else
        fail "Dockerfile" "missing 744 permission"
    fi

    if grep -q 'CMD \["/xlayer-tee-enclave"\]' "${TEE_DIR}/Dockerfile"; then
        pass "Dockerfile: correct CMD"
    else
        fail "Dockerfile" "incorrect CMD"
    fi
}

# ============================================================
# A-15 Adversarial Review finding verification
# ============================================================
echo ""
echo "=== A-15: Adversarial Review Findings ==="

test_a15_findings() {
    # Finding #1: rootfs.tar sha256 hash capture
    if grep -q "sha256sum rootfs.tar" "${TEE_DIR}/build_eif.sh"; then
        pass "A-15 #1: rootfs hash capture step exists in build_eif.sh"
    else
        fail "A-15 #1" "rootfs hash capture missing"
    fi

    if grep -q "rootfs hash:" "${TEE_DIR}/build_eif.sh"; then
        pass "A-15 #1: rootfs hash echoed to stdout"
    else
        fail "A-15 #1" "rootfs hash echo missing"
    fi

    # Finding #2: TEE_HOST vsock CID/port defaults
    if grep -q "TEE_HOST__ENCLAVE__VSOCK_CID" "${TEE_DIR}/start.sh"; then
        pass "A-15 #2: vsock CID default set in start.sh"
    else
        fail "A-15 #2" "vsock CID default missing"
    fi

    if grep -q "TEE_HOST__ENCLAVE__VSOCK_PORT" "${TEE_DIR}/start.sh"; then
        pass "A-15 #2: vsock port default set in start.sh"
    else
        fail "A-15 #2" "vsock port default missing"
    fi

    # Finding #3: trap for cleanup
    if grep -q "trap" "${TEE_DIR}/build_eif.sh"; then
        pass "A-15 #3: trap cleanup exists in build_eif.sh"
    else
        fail "A-15 #3" "trap cleanup missing"
    fi
}

# ============================================================
# Script interface contract validation
# ============================================================
echo ""
echo "=== Script interface contracts ==="

test_script_contracts() {
    for script in build.sh build_eif.sh start.sh stop.sh; do
        if head -1 "${TEE_DIR}/${script}" | grep -q '#!/usr/bin/env bash'; then
            pass "${script}: correct shebang"
        else
            fail "${script}" "missing bash shebang"
        fi

        if grep -q 'set -euo pipefail' "${TEE_DIR}/${script}"; then
            pass "${script}: strict mode enabled"
        else
            fail "${script}" "missing set -euo pipefail"
        fi
    done
}

# ============================================================
# Run all tests
# ============================================================
echo ""
echo "Running all tests..."
echo "===================="

test_dm_1_1
test_dm_1_3
test_dm_1_2
test_dm_2_1
test_dm_2_4
test_dm_2_3
test_dm_3_2
test_dm_3_5
test_dm_4_1
test_dm_4_3
test_dm_4_4
test_dm_4_5
test_dm_4_10
test_dm_4_8
test_dm_6_1
test_dockerfile
test_a15_findings
test_script_contracts

echo ""
echo "===================="
echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "===================="

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
