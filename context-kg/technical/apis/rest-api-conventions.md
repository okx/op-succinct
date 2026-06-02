---
name: "rest-api-conventions"
description: "API conventions for op-succinct — xlayer-tee-host exposes inbound REST; other services remain outbound-only"
---
# REST API Conventions

Most op-succinct services do not expose inbound HTTP — they are outbound-only RPC callers:

- `validity` — long-running proposer daemon that calls L1/L2 RPC outbound; no inbound HTTP server.
- `fault-proof` (proposer / challenger) — same shape; outbound RPC only.
- `scripts/*` — one-shot CLI tools.
- `xlayer-tee-host` — **exception**: exposes 4 inbound REST endpoints (see below).

## Inbound REST — xlayer-tee-host

`xlayer-tee-host` (`fault-proof/tee/host`) is the first inbound HTTP service in op-succinct. It uses axum 0.8 with a JSON envelope convention.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/tee/task` | POST | Create range task (body: rkyv witness bytes) |
| `/tee/task/{id}` | GET | Query task status + retrieve proofBytes |
| `/tee/task/{id}` | DELETE | Cancel task |
| `/tee/info` | GET | Query enclave attestation (cached) |

**Response envelope**: `{ "code": <int>, "message": "<string>", "data": <T|null> }`

**Error codes** (intentional deviation from "no centralized error codes"):
- `0` — success
- `10001` — client error (empty body, oversized body, enclave-sourced validation errors)
- `10004` — task not found
- `20001` — enclave/internal error

[Convention] New inbound REST services in op-succinct should follow this envelope pattern unless the upstream consumer requires a different shape.

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
