---
name: "signer"
description: "Signer pitfalls — XLayer protocol, AES key length, sensitive logging, OperateType routing"
---
# Signer Pitfalls

## AES Key Length

[Pitfall] `utils/signer/src/xlayer_remote_client.rs::encrypt_aes_ecb`: `secret_key` must be 16, 24, or 32 bytes (AES-128/192/256). Wrong length returns an error at signature time. Trigger: misconfigured env var or operator mistake. Correct approach: validate at startup so the operator sees a config error instead of a runtime error.

## Empty Auth Keys

[Pitfall] When either `access_key` or `secret_key` is empty, `add_auth_headers` skips both headers entirely (mirrors Go `addAuth`). Trigger: dev/test environments without credentials. Correct approach: expected behavior; production must enforce both keys via env var presence check.

## GET Signature Composition

[Pitfall] The query (poll) endpoint signs the **sorted URL parameter VALUES + body** — NOT the JSON serialization of the query struct. Trigger: refactoring the signature path. Correct approach: do not invent a new composition; mirror Go `generateSignature`. Reference: `core-flows/xlayer-remote-signing.md`.

## OperateType Routing

[Pitfall] `OperateType` enum (`i32` repr) values 20/21/22/23/27/28 are wire-visible to the asset-onchain service. Renumbering breaks server routing. Trigger: cleanup-style refactoring. Correct approach: never change enum integer values; only add new variants.

## TEE-Specific OtherInfo Fields

[Pitfall] `OtherInfo.operateType` and `proofBytes` are only emitted for TEE prove (`0x375bfa5d`); TEE challenge emits `operateType` only. Other operate types leave both fields `None`. Trigger: adding a new TEE method. Correct approach: extend `build_other_info` and ensure server agrees on the field shape.

## refOrderId LRU Cache

[Pitfall] `utils/signer/src/xlayer_remote_client.rs::refOrderCache` has capacity 1000. After 1000 sign requests, the oldest IDs are evicted. If the signer restarts, in-flight callbacks return "unknown order". Trigger: long-running services with high tx volume. Correct approach: persistent storage for refOrderIds; OR rely on upstream idempotency.

## Sensitive Data in Logs

[Rule] Never log `access_key`, `secret_key`, raw private keys, or signed-tx bytes. `XLayerConfig::Debug` redacts as `***REDACTED***`. The `[xlayer] >>>` HTTP log lines deliberately omit `accessKey`/`sign` headers. Reviewers must reject diffs that print raw key material.

## Production Signer Backend

[Rule] `LocalSigner` (in-memory private key) is for tests and dev only. Production must use `Web3Signer`, `CloudHsmSigner` (GCP-KMS), or `XLayerRemoteSigner`. The factory `Signer::from_env()` enforces a priority order: XLayer → CloudHSM → Web3Signer → LocalSigner.

## Anvil "to" Field

[Pitfall] `utils/signer/src/lib.rs:268`: Anvil's wallet filler requires `to` to be set even on contract creation txs. Trigger: local dev with anvil. Correct approach: set `Address::ZERO` manually for deploy txs. Not applicable in production.
