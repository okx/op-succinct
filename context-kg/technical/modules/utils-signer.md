---
name: "utils-signer"
description: "Remote-signer abstraction — Signer enum (Web3Signer / Local / GCP-KMS / XLayer) and XLayerRemoteClient HTTP protocol"
---
# utils/signer Module

## Responsibilities
- Expose a `Signer` enum that abstracts over 4 signing backends.
- Implement the OKX XLayer remote-signer HTTP protocol (`XLayerRemoteClient`) with AES-ECB + HMAC auth.
- Provide `SignerLock` (`Arc<Mutex<Signer>>`) so async senders cannot race nonces.

## NOT Responsible For
- Building transaction bodies (caller supplies a `TransactionRequest`).
- Decoding signed transactions for verification (the client decodes + verifies, but the higher-level proposer state machine is separate).
- Caching signatures.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `Signer` | enum: `Web3Signer`, `LocalSigner`, `CloudHsmSigner`, `XLayerRemoteSigner` | Backend dispatch |
| `SignerLock` | `Arc<Mutex<Signer>>`, cached `address` | Thread-safe sender |
| `XLayerConfig` | endpoint, address, user_id, symbol/project_symbol/operate_symbol, request_sign_uri, query_sign_uri, access_key, secret_key, timeout | Runtime config |
| `XLayerRemoteClient` | `reqwest::Client`, config, ref-order cache | HTTP client |
| `OperateType` (enum, `i32` repr) | `Proposer=20`, `ChallengerResolveClaim=21`, `ChallengerResolve=22`, `ChallengerClaimCredit=23`, `Prove=27`, `Challenge=28` | Routes to server-side handlers |
| `XLayerSignerError` | `HttpError`, `SigningFailed`, `VerificationError`, `InvalidResponse`, `SignatureTimeout`, `NetworkError`, `ConfigError` | `thiserror` enum |

## Dependencies
- Refer to `arch/dependency.md`. Direct deps: `alloy-signer-*`, `alloy-rpc-types-eth`, `reqwest`, `aes`, `sha2`, `hmac`, `base64`.

## Relevant Flows
- See `core-flows/xlayer-remote-signing.md` for the full sign → poll → decode flow.

## Module-Specific Pitfalls

[Pitfall] `utils/signer/src/xlayer_remote_client.rs`: XLayer sign timeout after 3 retries with 5s delay — total ~20s plus initial attempt. Trigger: server unreachable or signature consistently rejected. Correct approach: log attempt count; consider exponential backoff if upstream operator wants longer retries.

[Pitfall] Nonce conflicts when multiple async tasks call `send_transaction_request` on the same `Signer` without `SignerLock`. Correct approach: always wrap `Signer` in `SignerLock` for production.

[Pitfall] `XLayerConfig.secret_key` must be 16/24/32 bytes (AES-128/192/256). Wrong length panics at signature time. Correct approach: validate at startup; surface a config-time error rather than a runtime error.

[Pitfall] Empty `access_key` OR `secret_key` skips auth entirely (matches Go `addAuth`). Trigger: dev/test environments without credentials configured. Correct approach: expected — server side controls whether anonymous mode is allowed.

[Pitfall] Anvil tx workaround (`utils/signer/src/lib.rs:268`): Anvil's wallet filler requires `to` set even for deploy txs; we set `Address::ZERO` manually. Trigger: local dev with anvil; pitfall doesn't affect production.

[Warning] `XLayerConfig::Debug` redacts keys as `***REDACTED***`. The `eprintln!("[xlayer] >>> …")` HTTP logs deliberately omit `accessKey`/`sign` headers; future contributors should preserve this.
