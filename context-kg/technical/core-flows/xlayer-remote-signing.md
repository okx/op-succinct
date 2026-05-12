---
name: "xlayer-remote-signing"
description: "XLayer remote-signer flow — detect operate type, build OtherInfo, POST sign + GET poll, verify signed tx"
---
# XLayer Remote Signing Flow

## Entry Point
`Signer::XLayerRemoteSigner.send_transaction_request_with_timeout()` → `XLayerRemoteClient::sign_transaction()`.

## Primary Entities
`XLayerRemoteClient`, `XLayerConfig`, `OperateType`, `XLayerSignRequest`, `XLayerQueryRequest`, `XLayerSignResponse`, `XLayerOtherInfo`, `XLayerSignerError`.

## State Transitions

| Current State | Trigger | Target State |
|--------------|---------|-------------|
| (initial) | `detect_operate_type(tx)` matches a known selector | OperateType identified |
| OperateType identified | POST `/ecologyOperate` returns `success=true` with `data=<orderId>` | Order submitted |
| Order submitted | GET `/querySignDataByOrderNo` returns `success=true` with `data=<hex>` | Signed |
| Order submitted | GET poll budget exhausted (300 × 1s) | SignatureTimeout |
| any | Network error | NetworkError / HttpError |

**[Rule] Terminal states must never be reversed**: `Signed`, `SignatureTimeout`, `SigningFailed`, `VerificationError`.

## Normal Flow Steps

| Step | Action | Module |
|------|--------|--------|
| 1 | `detect_operate_type(tx)` — selector → `OperateType` (Proposer / ChallengerResolveClaim / ChallengerResolve / ChallengerClaimCredit / Prove / Challenge) | `xlayer_remote_client.rs::detect_operate_type` |
| 2 | `build_other_info(tx)` — populate `XLayerOtherInfo` with contract address, gas, fee fields, value, data hex, business params (gameType / rootClaim / extraData / recipient / claimIndex / numToResolve / proofBytes / operateType) | `xlayer_remote_client.rs::build_other_info` |
| 3 | Generate `refOrderId` (UUID v4); store in client cache | `xlayer_remote_client.rs` |
| 4 | Build `XLayerSignRequest` with `userId`, `operateType`, `operateAddress` (lower-cased), symbols, `refOrderId`, `otherInfo`, `depositeAddress`, `toAddress` | `xlayer_remote_client.rs` |
| 5 | Serialize with sorted JSON keys (`sorted_json_marshal`) | `xlayer_remote_client.rs::sorted_json_marshal` |
| 6 | Compute signature: `base64(AES-ECB(sha256_hex(sorted_url_values + body), secret_key))` (only when both `access_key` and `secret_key` are set) | `add_auth_headers`, `generate_signature` |
| 7 | POST `request_sign_uri` with `Content-Type: application/json` + (`accessKey` + `sign` if auth) | `post_sign_request` |
| 8 | On non-200: raise `HttpError`. On `success=false`: raise `SigningFailed` with `msg`/`detailMsg`. | `post_sign_request` |
| 9 | Poll loop (`wait_sign_result`): every `SIGN_RESULT_POLL_INTERVAL` (1s), build `XLayerQueryRequest`, GET `query_sign_uri?userId=…&orderId=…&projectSymbol=…` | `wait_sign_result` |
| 10 | Parse `XLayerSignResponse`. If `success=true` and `data` non-empty → break out of poll | `wait_sign_result` |
| 11 | After 300 attempts (5 min total) → raise `SignatureTimeout` | `wait_sign_result` |
| 12 | Decode `hex::decode(data)` → `TxEnvelope::decode_2718` | `sign_transaction` |
| 13 | `verify_signed_transaction()` — check signed tx matches original (to, data, nonce, value, chain_id, type) and recover signer address | `verify_signed_transaction` |
| 14 | Return signed tx bytes | `sign_transaction` |

## Exception Branches

| Trigger | State Change | Compensation |
|---------|-------------|-------------|
| `detect_operate_type` unknown selector | n/a | Return `anyhow::Error("Unknown method signature…")`; do NOT submit |
| Both `access_key` and `secret_key` set, but `secret_key.len() not in {16,24,32}` | n/a | `encrypt_aes_ecb` returns error before any HTTP |
| Either `access_key` or `secret_key` empty | (anonymous mode) | Skip auth headers entirely; server side enforces policy |
| POST returns HTTP 4xx/5xx | HttpError | Raised with status + body; outer retry budget handles re-attempt |
| POST returns `success=false` | SigningFailed | Surface `msg`/`detailMsg` for operator triage |
| GET poll returns shape that does not match `XLayerSignResponse` | InvalidResponse | Raw body included in error context for diagnosis |
| `verify_signed_transaction` recovers wrong signer | VerificationError | Signed bytes rejected; never broadcast |

## Flow-Specific Pitfalls

[Pitfall] Query (GET) signature uses URL parameter VALUES (sorted lexicographically) + body — NOT the JSON serialization of the query struct. Mirrors Go `generateSignature`; deviating breaks server-side validation.

[Pitfall] `secret_key` length must match an AES variant exactly. Diagnose at startup, not at signature time.

[Pitfall] Empty auth keys silently skip auth — fine in dev/test, dangerous in production. Operator must enforce that real environments have both keys set.

[Pitfall] `refOrderId` is cached in an LRU keyed by id; cache size = 1000. If signer is restarted, old in-flight orders are lost (their callbacks return "unknown order"). Idempotency relies on the upstream service.

[Pitfall] `OtherInfo.operateType` and `proofBytes` are only emitted for TEE prove (`0x375bfa5d`); TEE challenge emits `operateType` only. Mismatch with Go would break server routing.
