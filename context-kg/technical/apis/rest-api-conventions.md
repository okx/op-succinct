---
name: "rest-api-conventions"
description: "API conventions for op-succinct — note: this workspace exposes no public REST API"
---
# REST API Conventions

**Not applicable.** op-succinct does not expose a public REST API. The runtime services are:

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
