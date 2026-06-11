#!/usr/bin/env bash
# loadtest.sh — unified mock-proposer load test driver.
#
# MODE=serial    每隔 INTERVAL_SEC 启动一次，跑 MAX_ITERATIONS 次
# MODE=parallel  每隔 BURST_INTERVAL_SEC 齐射 PARALLELISM 个，跑 MAX_BURSTS 轮
#
# AGG_MODE=skip   跑到 range proof + TEE 签名为止（秒级到几分钟）
# AGG_MODE=prove  跑完整 SP1 aggregation prove（几十分钟到 4 小时）
#
# Usage:
#   MODE=serial   ANCHOR_BLOCK=8617400 ./loadtest.sh
#   MODE=parallel ANCHOR_BLOCK=8617400 PARALLELISM=10 ./loadtest.sh
#   MODE=serial   ANCHOR_BLOCK=8617400 RANGE_SIZE=4000 CHUNK_SIZE=1000 ./loadtest.sh
#   MODE=parallel ANCHOR_BLOCK=8766000 PARALLELISM=3 START_STRIDE=1 ./loadtest.sh   # 起点 anchor, anchor+1, ...（重叠压测）
#   # Reuse one cached witness for every run (max throughput test, no witness gen):
#   MODE=serial MAX_ITERATIONS=50 ANCHOR_BLOCK=8725200 RANGE_SIZE=4000 CHUNK_SIZE=4000 START_STRIDE=0 \
#     WITNESS_CACHE_DIR=./wcache ./tee-test.sh
#   # True parallel: same start, different end → witness differs → host won't dedup:
#   MODE=parallel PARALLELISM=3 MAX_BURSTS=5 ANCHOR_BLOCK=8725200 \
#     RANGE_SIZE=1000 START_STRIDE=0 END_STRIDE=1000 ./tee-test.sh
#   # → worker 0: [8725200, 8726200] / worker 1: [8725200, 8727200] / worker 2: [8725200, 8728200]
#
# === Required ===
#   MODE            serial | parallel
#   ANCHOR_BLOCK    base L2 block height
#
# === Common (with defaults) ===
#   AGG_MODE                 skip | prove                        (default: prove)
#   RANGE_SIZE               每次 run 的区块跨度 [start,end]       (default: 1000)
#   CHUNK_SIZE               --chunk-size，把每个 run 再切块        (default: =RANGE_SIZE → 1 chunk/run)
#                            每个 chunk = 一份 witness = 一个 TEE 任务
#   START_STRIDE             相邻 run 起点的间隔                   (default: =RANGE_SIZE → 不重叠)
#                            设为 1 → anchor, anchor+1, anchor+2 ...（范围互相重叠，重复证明）
#                            设为 0 → 所有 run 起点相同（搭配 END_STRIDE 让长度递增）
#   END_STRIDE               相邻 run 终点的额外偏移               (default: 0 → end = start + RANGE_SIZE)
#                            非 0 时：end = start + RANGE_SIZE + idx * END_STRIDE
#                            搭配 START_STRIDE=0 → 所有 run 起点相同，终点递增（同 anchor 长度递增）。
#                            为何重要：host 用 keccak256(witness_body) 去重——同 [start,end] 必去重，
#                            "假并发"实际只跑 1 个 task。让 end 不同 → witness 不同 → 真并发。
#   MAX_CONCURRENT_WITNESS   --max-concurrent-witness            (default: 4)
#   WITNESS_CACHE_DIR        --witness-cache-dir 路径            (default: 空 = 不复用，每次重新生成 witness)
#                            放置已 prefab 好的 <start>-<end>.witness.rkyv 文件，
#                            当 [start, end] 跟缓存 chunk 完全一致时跳过 witness gen，直接 POST。
#                            搭配 START_STRIDE=0 让所有 run 命中同一份缓存，压测纯 enclave 侧负载。
#   TEE_HOST                 tee-host endpoint                   (default: ELB)
#   L1_RPC / L1_BEACON_RPC / L2_RPC / L2_NODE_RPC                (TEE-box defaults)
#   BIN                      path to xlayer-tee-mock-proposer    (default: ./target/release/...)
#
# === Serial-only ===
#   INTERVAL_SEC    gap between launches                         (default: 60)
#   MAX_ITERATIONS  total runs                                   (default: 12)
#   OVERLAP_POLICY  queue | skip | parallel                      (default: queue)
#
# === Parallel-only ===
#   PARALLELISM         workers per burst                        (default: 10)
#   BURST_INTERVAL_SEC  gap between bursts                       (default: 600)
#   MAX_BURSTS          total bursts                             (default: 3)
#
# === Prove-only ===
#   REDIS_NODES      Redis nodes                                 (default: redis://:redispassword@127.0.0.1:6379/0)
#   CLUSTER_RPC      SP1 cluster RPC                             (default: 127.0.0.1:50051)
#   PROVER_ADDRESS   prover address                              (default: 0x98F5...0xaA0)
#   PROOF_MODE       groth16 | plonk | compressed                (default: groth16)
#   CLUSTER_TIMEOUT  per-run cluster timeout sec                 (default: 14400)

set -uo pipefail

# ---------- Required ----------
: "${MODE:?must set MODE=serial|parallel}"
: "${ANCHOR_BLOCK:?must set ANCHOR_BLOCK}"

# ---------- Common ----------
AGG_MODE="${AGG_MODE:-prove}"
RANGE_SIZE="${RANGE_SIZE:-1000}"                          # 每次 run 的区块跨度 [start,end]
CHUNK_SIZE="${CHUNK_SIZE:-$RANGE_SIZE}"                   # --chunk-size：把每个 run 再切块（默认 1 chunk/run）
START_STRIDE="${START_STRIDE:-$RANGE_SIZE}"              # 相邻 run 起点间隔：=RANGE_SIZE 不重叠，=1 则 anchor,anchor+1,...
END_STRIDE="${END_STRIDE:-0}"                            # 相邻 run 终点的额外偏移（0=固定长度，>0=长度递增）
MAX_CONCURRENT_WITNESS="${MAX_CONCURRENT_WITNESS:-4}"     # --max-concurrent-witness
WITNESS_CACHE_DIR="${WITNESS_CACHE_DIR:-}"                # --witness-cache-dir：空字符串=不启用
TEE_HOST="${TEE_HOST:-http://teexlayer-36134a95d1051793.elb.ap-northeast-1.amazonaws.com:443}"
L1_RPC="${L1_RPC:-http://127.0.0.1:8545}"
L1_BEACON_RPC="${L1_BEACON_RPC:-http://127.0.0.1:3500}"
L2_RPC="${L2_RPC:-http://127.0.0.1:8123}"
L2_NODE_RPC="${L2_NODE_RPC:-http://127.0.0.1:9555}"
BIN="${BIN:-./target/release/xlayer-tee-mock-proposer}"

# ---------- Serial ----------
INTERVAL_SEC="${INTERVAL_SEC:-60}"
MAX_ITERATIONS="${MAX_ITERATIONS:-12}"
OVERLAP_POLICY="${OVERLAP_POLICY:-queue}"

# ---------- Parallel ----------
PARALLELISM="${PARALLELISM:-10}"
BURST_INTERVAL_SEC="${BURST_INTERVAL_SEC:-600}"
MAX_BURSTS="${MAX_BURSTS:-3}"

# ---------- Prove ----------
REDIS_NODES="${CLI_REDIS_NODES:-redis://:redispassword@127.0.0.1:6379/0}"
CLUSTER_RPC="${CLUSTER_RPC:-http://127.0.0.1:50051}"
PROVER_ADDRESS="${PROVER_ADDRESS:-0x98F5fABf388120b055e583b44e072C2806Bb0aA0}"
PROOF_MODE="${PROOF_MODE:-groth16}"
CLUSTER_TIMEOUT="${CLUSTER_TIMEOUT:-14400}"

# ---------- Sanity ----------
case "$MODE" in serial|parallel) ;; *) echo "MODE must be serial|parallel"; exit 1;; esac
case "$AGG_MODE" in skip|prove) ;; *) echo "AGG_MODE must be skip|prove"; exit 1;; esac
[[ -x "$BIN" ]] || { echo "BIN not executable: $BIN"; exit 1; }
[[ "$RANGE_SIZE" -ge 1 ]] || { echo "RANGE_SIZE must be ≥ 1"; exit 1; }
[[ "$CHUNK_SIZE" -ge 1 ]] || { echo "CHUNK_SIZE must be ≥ 1"; exit 1; }
[[ "$START_STRIDE" -ge 0 ]] || { echo "START_STRIDE must be ≥ 0"; exit 1; }
[[ "$END_STRIDE" -ge 0 ]]   || { echo "END_STRIDE must be ≥ 0";   exit 1; }
[[ "$MAX_CONCURRENT_WITNESS" -ge 1 ]] || { echo "MAX_CONCURRENT_WITNESS must be ≥ 1"; exit 1; }
(( CHUNK_SIZE > RANGE_SIZE )) && echo "note: CHUNK_SIZE($CHUNK_SIZE) > RANGE_SIZE($RANGE_SIZE) → 每个 run 实际只有 1 个 chunk"
(( START_STRIDE == 0 && END_STRIDE == 0 )) && echo "note: START_STRIDE=0 & END_STRIDE=0 → 所有 run 跑同一个 range（复用 witness cache；host 会按 keccak256(witness) 去重，并发场景下只有 1 个真 task）"
(( START_STRIDE == 0 && END_STRIDE >  0 )) && echo "note: START_STRIDE=0 & END_STRIDE=$END_STRIDE → 同 start 长度递增，witness 各不同（绕开 host 去重，真并发）"
(( START_STRIDE > 0 && START_STRIDE < RANGE_SIZE )) && echo "note: START_STRIDE($START_STRIDE) < RANGE_SIZE($RANGE_SIZE) → 各 run 区块范围重叠（重复证明）"
if [[ -n "$WITNESS_CACHE_DIR" && "$END_STRIDE" -ne 0 ]]; then
    echo "note: END_STRIDE=$END_STRIDE → 每个 run 的 [start,end] 不同，需要为每条 range 都 prefab <start>-<end>.witness.rkyv，否则会 fallback 现场生成 witness"
fi
if [[ -n "$WITNESS_CACHE_DIR" ]]; then
    [[ -d "$WITNESS_CACHE_DIR" ]] || { echo "WITNESS_CACHE_DIR not a directory: $WITNESS_CACHE_DIR"; exit 1; }
    echo "note: WITNESS_CACHE_DIR=$WITNESS_CACHE_DIR → mock-proposer 会尝试复用缓存的 <start>-<end>.witness.rkyv"
fi

LOG_DIR="tmp/loadtest_${MODE}_${AGG_MODE}_$(date +%Y%m%d-%H%M%S)"
PROOF_DIR="$LOG_DIR/proofs"
mkdir -p "$PROOF_DIR"
SUMMARY="$LOG_DIR/summary.csv"

# Different CSV headers for the two modes
if [[ "$MODE" == "serial" ]]; then
    echo "iter,start_block,end_block,launch_ts,duration_sec,exit_code,status,proof_file" > "$SUMMARY"
else
    echo "burst,worker,start_block,end_block,launch_ts,duration_sec,exit_code,status,proof_file" > "$SUMMARY"
fi

echo "==============================================="
echo "loadtest: $(date)  MODE=$MODE  AGG_MODE=$AGG_MODE"
echo "  anchor=$ANCHOR_BLOCK  range=$RANGE_SIZE  start_stride=$START_STRIDE  end_stride=$END_STRIDE  chunk=$CHUNK_SIZE  max_witness=$MAX_CONCURRENT_WITNESS  tee_host=$TEE_HOST"
echo "  witness_cache_dir=${WITNESS_CACHE_DIR:-<none>}"
if [[ "$AGG_MODE" == "prove" ]]; then
    echo "   cluster=$CLUSTER_RPC  proof_mode=$PROOF_MODE  cluster_timeout=${CLUSTER_TIMEOUT}s"
fi
if [[ "$MODE" == "serial" ]]; then
    echo "  interval=${INTERVAL_SEC}s  max_iter=$MAX_ITERATIONS  overlap=$OVERLAP_POLICY"
else
    echo "  burst_interval=${BURST_INTERVAL_SEC}s  parallelism=$PARALLELISM  max_bursts=$MAX_BURSTS"
fi
echo "  log dir:   $LOG_DIR"
echo "  proof dir: $PROOF_DIR"
echo "==============================================="

# -----------------------------------------------------------------------------
# Unified runner: build the right command for AGG_MODE then exec
# -----------------------------------------------------------------------------
run_once() {
    local start=$1 end=$2 log=$3 proof=$4

    # Common args
    local -a args=(
        --tee-host                "$TEE_HOST"
        --l1-rpc                  "$L1_RPC"
        --l1-beacon-rpc           "$L1_BEACON_RPC"
        --l2-rpc                  "$L2_RPC"
        --l2-node-rpc             "$L2_NODE_RPC"
        --start-block             "$start"
        --end-block               "$end"
        --chunk-size              "$CHUNK_SIZE"
        --max-concurrent-witness  "$MAX_CONCURRENT_WITNESS"
    )

    if [[ -n "$WITNESS_CACHE_DIR" ]]; then
        args+=( --witness-cache-dir "$WITNESS_CACHE_DIR" )
    fi

    if [[ "$AGG_MODE" == "skip" ]]; then
        args+=( --agg-mode skip )
        "$BIN" "${args[@]}" > "$log" 2>&1
    else
        args+=(
            --agg-mode        prove
            --prover-backend  cluster
            --proof-mode      "$PROOF_MODE"
            --cluster-timeout "$CLUSTER_TIMEOUT"
            --output-proof    "$proof"
            --prover-address  "$PROVER_ADDRESS"
        )
        CLI_REDIS_NODES="$REDIS_NODES" \
        SP1_PROVER=cluster \
        CLI_CLUSTER_RPC="$CLUSTER_RPC" \
        RUST_LOG="${RUST_LOG:-info}" \
        "$BIN" "${args[@]}" > "$log" 2>&1
    fi
}

# Classify a finished run's log
classify_status() {
    local log=$1 rc=$2 proof=$3
    local status="ok"
    if grep -q "queued (capacity)\|TooManyTasks" "$log"; then status="${status}+throttled"; fi
    if grep -q "cluster timeout\|timed out"      "$log"; then status="${status}+cluster_timeout"; fi
    if grep -q "signer mismatch\|ClaimMismatch"  "$log"; then status="${status}+verify_fail"; fi
    [[ $rc -ne 0 ]] && status="failed"
    if [[ "$AGG_MODE" == "prove" ]] && [[ ! -f "$proof" ]] && [[ "$status" == "ok" ]]; then
        status="ok+no_proof"
    fi
    echo "$status"
}

# -----------------------------------------------------------------------------
# Mode: serial
# -----------------------------------------------------------------------------
run_serial() {
    local prev_pid=""
    for ((iter=0; iter<MAX_ITERATIONS; iter++)); do
        local start=$((ANCHOR_BLOCK + iter * START_STRIDE))
        local end=$((start + RANGE_SIZE + iter * END_STRIDE))
        local log="$LOG_DIR/run-$(printf '%03d' $iter).log"
        local proof="$PROOF_DIR/proof-$(printf '%03d' $iter).bin"
        local launch_ts=$(date +%s)
        local launch_iso=$(date -Iseconds)

        if [[ -n "$prev_pid" ]] && kill -0 "$prev_pid" 2>/dev/null; then
            case "$OVERLAP_POLICY" in
                queue)
                    echo "[$launch_iso] iter=$iter waiting for prev pid=$prev_pid..."
                    wait "$prev_pid"
                    ;;
                skip)
                    echo "[$launch_iso] iter=$iter SKIPPED (prev still running)"
                    echo "$iter,$start,$end,$launch_ts,0,-1,skipped," >> "$SUMMARY"
                    sleep "$INTERVAL_SEC"
                    continue
                    ;;
                parallel) : ;;
            esac
        fi

        echo "[$launch_iso] iter=$iter launching [$start, $end]"
        (
            t0=$(date +%s)
            run_once "$start" "$end" "$log" "$proof"
            rc=$?
            t1=$(date +%s)
            dt=$((t1 - t0))
            status=$(classify_status "$log" "$rc" "$proof")
            echo "$iter,$start,$end,$t0,$dt,$rc,$status,$proof" >> "$SUMMARY"
            echo "[iter=$iter] done rc=$rc dt=${dt}s status=$status"
        ) &
        prev_pid=$!

        sleep "$INTERVAL_SEC"
    done

    echo "waiting for in-flight runs to complete..."
    wait
}

# -----------------------------------------------------------------------------
# Mode: parallel
# -----------------------------------------------------------------------------
run_parallel() {
    for ((burst=0; burst<MAX_BURSTS; burst++)); do
        local burst_iso=$(date -Iseconds)
        echo
        echo "[$burst_iso] BURST $burst — launching $PARALLELISM workers"

        local pids=()
        for ((w=0; w<PARALLELISM; w++)); do
            local global_idx=$((burst * PARALLELISM + w))
            local start=$((ANCHOR_BLOCK + global_idx * START_STRIDE))
            local end=$((start + RANGE_SIZE + global_idx * END_STRIDE))
            local log="$LOG_DIR/burst-$(printf '%02d' $burst)-w$(printf '%02d' $w).log"
            local proof="$PROOF_DIR/proof-b$(printf '%02d' $burst)-w$(printf '%02d' $w).bin"

            (
                t0=$(date +%s)
                run_once "$start" "$end" "$log" "$proof"
                rc=$?
                t1=$(date +%s)
                dt=$((t1 - t0))
                status=$(classify_status "$log" "$rc" "$proof")
                echo "$burst,$w,$start,$end,$t0,$dt,$rc,$status,$proof" >> "$SUMMARY"
                echo "[burst=$burst worker=$w] done rc=$rc dt=${dt}s status=$status"
            ) &
            pids+=($!)
        done

        echo "[burst=$burst] $PARALLELISM workers launched, pids: ${pids[*]}"
        echo "[burst=$burst] waiting for burst to drain..."
        for pid in "${pids[@]}"; do
            wait "$pid"
        done

        echo "[$(date -Iseconds)] BURST $burst complete"
        if (( burst < MAX_BURSTS - 1 )); then
            sleep "$BURST_INTERVAL_SEC"
        fi
    done
}

# -----------------------------------------------------------------------------
# Dispatch
# -----------------------------------------------------------------------------
if [[ "$MODE" == "serial" ]]; then
    run_serial
else
    run_parallel
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
# CSV column indices differ between modes
if [[ "$MODE" == "serial" ]]; then
    dt_col=5
    status_col=7
else
    dt_col=6
    status_col=8
fi

echo
echo "==============================================="
echo "summary:"
echo "==============================================="
total=$(awk 'END{print NR-1}' "$SUMMARY")
echo "  total runs:      $total"
echo "  ok:              $(awk -F, -v c=$status_col 'NR>1 && $c~/^ok$/ {n++} END{print n+0}'              "$SUMMARY")"
echo "  throttled:       $(awk -F, -v c=$status_col 'NR>1 && $c~/throttled/ {n++} END{print n+0}'         "$SUMMARY")"
if [[ "$AGG_MODE" == "prove" ]]; then
echo "  cluster_timeout: $(awk -F, -v c=$status_col 'NR>1 && $c~/cluster_timeout/ {n++} END{print n+0}'   "$SUMMARY")"
echo "  no_proof:        $(awk -F, -v c=$status_col 'NR>1 && $c~/no_proof/ {n++} END{print n+0}'          "$SUMMARY")"
fi
echo "  verify_fail:     $(awk -F, -v c=$status_col 'NR>1 && $c~/verify_fail/ {n++} END{print n+0}'       "$SUMMARY")"
echo "  failed:          $(awk -F, -v c=$status_col 'NR>1 && $c=="failed" {n++} END{print n+0}'           "$SUMMARY")"
echo "  skipped:         $(awk -F, -v c=$status_col 'NR>1 && $c=="skipped" {n++} END{print n+0}'          "$SUMMARY")"
echo "  avg duration:    $(awk -F, -v c=$dt_col 'NR>1 && $c>0 {s+=$c; n++} END{if(n>0) print s/n " sec"; else print "n/a"}' "$SUMMARY")"
echo "  max duration:    $(awk -F, -v c=$dt_col 'NR>1 && $c>0 && $c>m {m=$c} END{if(m>0) print m " sec"; else print "n/a"}' "$SUMMARY")"
echo "  csv:             $SUMMARY"
