---
name: "rest-api-conventions"
description: "API conventions for op-succinct — inbound REST (xlayer-tee-host) and outbound HTTP patterns"
---
# REST API Conventions

## Inbound REST — xlayer-tee-host

`xlayer-tee-host` (`fault-proof/tee/host/`) is the first inbound REST service in op-succinct, exposing 4 JSON endpoints for proposer interaction:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/tee/task` | POST | Create range task (rkyv witness body) |
| `/tee/task/{id}` | GET | Query task status + retrieve proofBytes |
| `/tee/task/{id}` | DELETE | Cancel task |
| `/tee/info` | GET | Query enclave attestation (cached) |

**Response envelope**: `{ "code": <int>, "message": <string>, "data": <T|null> }`

| Code | Meaning |
|------|---------|
| 0 | Success |
| 10001 | Client error (empty body, oversize, invalid input, non-TaskUnknown enclave errors) |
| 10004 | Task not found / TaskUnknown |
| 20001 | Server-side error: enclave unreachable, enclave error, or host witness buffer full (BufferFull) |

[Convention] All error responses go through `HostError → ApiResponse` — no magic number `ApiResponse::error(10001, ...)` in handlers.

[Convention] Numeric error codes are intentionally limited to 4 values. This is a deliberate deviation from op-succinct's prior pattern (no centralized error codes) — the 4-code set is specified by the TEE design document for the northbound contract.

## Other Runtime Services

- `validity` — long-running proposer daemon that calls L1/L2 RPC outbound; no inbound HTTP server.
- `fault-proof` (proposer / challenger) — same shape; outbound RPC only.
- `scripts/*` — one-shot CLI tools.

## Outbound HTTP

The single non-trivial outbound HTTP client is `XLayerRemoteClient` (see `utils/signer/src/xlayer_remote_client.rs`):

| Field | Convention |
|-------|-----------|
| Wrapper | `XLayerSignResponse { code: i32, data: String, msg: String, detailMsg: Option<String>, status: i32, success: bool }` |
| Success | HTTP 200 with `success == true` and non-empty `data` |
| Error | Either non-200 HTTP status (raised as `HttpError`) or `success == false` (raised as `SigningFailed` with `msg`/`detailMsg`) |
| Headers | `accessKey` + `sign` when both keys are configured; skip auth headers entirely when either is empty |
| Method | `POST` to `request_sign_uri` (JSON body); `GET` to `query_sign_uri` (URL query params) |
| Versioning | None — pinned by URI path (`/priapi/v1/...`) |
| Idempotency | `refOrderId` is a UUID generated per sign request and cached in the client to track callbacks |
| Pagination | n/a |

## Outbound RPC

JSON-RPC over HTTP to L1, L2, and beacon nodes; uses `alloy-provider`. No bespoke RPC conventions beyond the standard alloy interface.
