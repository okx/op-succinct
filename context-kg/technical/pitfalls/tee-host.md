---
name: "tee-host"
description: "Pitfalls for TEE proof path — axum body limits, binary encoding, ABI encoding, witness serialization"
---
# TEE Host Pitfalls

## axum Default Body Limit

[Pitfall] axum's `DefaultBodyLimit` is 2 MiB — any handler receiving large payloads (e.g. 256 MiB rkyv witness bytes) will silently reject requests with a bare HTTP 413 before reaching the handler.
**Trigger**: adding a new axum route that accepts large binary bodies without overriding the default limit.
**Correct**: set `DefaultBodyLimit::max(desired_limit)` on the axum router layer; check body length inside the handler for structured error responses.

```rust
// Correct: override default and check inside handler
let app = Router::new()
    .route("/tee/task", post(create_task))
    .layer(DefaultBodyLimit::max(MAX_RANGE_BODY_BYTES + 1024));

// Inside handler — structured error, not bare 413
if body.len() > MAX_RANGE_BODY_BYTES {
    return ApiResponse::from_error(HostError::BodyTooLarge { actual: body.len(), limit: MAX_RANGE_BODY_BYTES });
}
```

[Rule] Every axum service in op-succinct that handles binary payloads > 2 MiB must explicitly set `DefaultBodyLimit` on the router.
**Module**: `fault-proof/tee/host/src/main.rs`
**Source**: PRD FR-1 / review-finding F-06
**Date**: 2026-06-04
**Hit count**: 1

## Binary Data Decoded as UTF-8

[Pitfall] COSE_Sign1 attestation documents (and other binary protocol data like rkyv responses) contain non-UTF-8 bytes. Using `String::from_utf8` or any text decode on raw binary causes a decode error that gets misreported as "enclave unreachable" (code=20001).
**Trigger**: handling binary HTTP response bodies and converting them to String before further processing.
**Correct**: operate on raw `Vec<u8>` / `Bytes`; use `base64::engine::general_purpose::STANDARD.encode(&raw_bytes)` for human-readable serialization; use `rkyv::util::AlignedVec` for rkyv decode.

```rust
// WRONG — panics or errors on non-UTF-8
let doc = String::from_utf8(raw_bytes)?;

// CORRECT — binary stays binary, base64 for JSON output
let doc = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);
```

[Rule] Never decode binary protocol data (rkyv, COSE_Sign1, protobuf) as UTF-8 text. Use the appropriate binary-aware encoding (base64 for JSON, AlignedVec for rkyv).
**Module**: `fault-proof/tee/host/src/server.rs`, `fault-proof/tee/host/src/enclave_client.rs`
**Source**: PRD FR-4 / review-finding F-07
**Date**: 2026-06-04
**Hit count**: 1

## abi_encode_params vs abi_encode

[Pitfall] `abi_encode()` prepends a 32-byte dynamic-tuple offset before the actual data; `abi_encode_params()` encodes parameters directly without this wrapper. When the on-chain contract does `abi.decode(proofBytes, (RangeJournal, bytes))`, using `abi_encode()` produces bytes that fail to decode because of the extra offset.
**Trigger**: encoding Solidity-compatible structs with alloy's `SolValue` trait for direct `abi.decode` consumption.
**Correct**: use `(journal, sig_bytes).abi_encode_params()`, NOT `abi_encode()`.

```rust
// WRONG — adds 32-byte offset, breaks on-chain abi.decode
let proof = (journal, sig_bytes).abi_encode();

// CORRECT — direct parameter encoding, matches abi.decode expectation
let proof = (journal, sig_bytes).abi_encode_params();
```

[Rule] When encoding data for consumption by Solidity `abi.decode(data, (T1, T2, ...))`, always use `abi_encode_params()`. Reserve `abi_encode()` for top-level function call encoding where the offset is expected.
**Module**: `fault-proof/tee/host/src/packager.rs`, `fault-proof/src/tee_client.rs`
**Source**: PRD FR-9 / review-finding F-08
**Date**: 2026-06-04
**Hit count**: 2

## WitnessData into_parts() for rkyv Serialization

[Pitfall] The generic `WitnessData` trait (returned by `host.run()`) does not derive `rkyv::Archive`/`rkyv::Serialize`. Calling `rkyv::to_bytes(&witness_data)` directly fails to compile. The TEE proof path needs to send witness bytes to the TEE host via HTTP.
**Trigger**: Trying to rkyv-serialize the trait object returned from `host.run()` in the TEE proof path.
**Correct**: Call `witness_data.into_parts()` to decompose into concrete types (`MultiChainBootInfo`, `SerializableOracleData`, `BlobData`), then reconstruct a `DefaultWitnessData` which does derive rkyv:

```rust
// WRONG — WitnessData trait doesn't have rkyv bounds
let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&witness_data)?;

// CORRECT — decompose, reconstruct concrete type, then serialize
let (boot, oracle, blob) = witness_data.into_parts();
let concrete = DefaultWitnessData::new(boot, oracle, blob);
let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&concrete)?;
```

[Rule] When serializing witness data for external transport (TEE host, cache, etc.), always use `into_parts()` → `DefaultWitnessData` reconstruction. Do NOT attempt to add rkyv derives to the `WitnessData` trait — it would propagate rkyv bounds to all DA-specific host implementations.
**Module**: `fault-proof/src/proposer.rs` (prove_game_tee)
**Source**: TDD summary design decision #3 (XLOP-1090)
**Date**: 2026-06-04
**Hit count**: 1
