# SP1 Gateway Proxy

In environments that cannot directly access the SP1 Prover Network (e.g. restricted networks, production-isolated environments), all SP1 SDK outbound requests can be routed through an API gateway (e.g. APISIX).

## How It Works

The gateway acts as a reverse proxy. The SDK replaces the original destination host with the gateway host and passes the original host via custom headers, allowing the gateway to forward requests to the correct upstream service.

Two types of requests are proxied:
- **gRPC requests**: Communication with the SP1 Prover Network (proof submission, status queries, etc.)
- **HTTP requests**: Presigned URL uploads (PUT) and downloads (GET), including S3 and other object storage

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SP1_GATEWAY_HOST` | Yes | Gateway address, e.g. `http://host:port` |
| `SP1_GATEWAY_TOKEN` | Yes* | Value for the `third-token` header, used for gRPC gateway authentication |
| `SP1_GATEWAY_S3_TOKEN` | No | Separate `third-token` value for S3 artifact requests. Falls back to `SP1_GATEWAY_TOKEN` if unset |
| `SP1_GATEWAY_SOURCE_SERVICE` | Yes* | Value for the `source-service` header, identifies the calling service |

> \* Required only when `SP1_GATEWAY_HOST` is set. If `SP1_GATEWAY_HOST` is set but `SP1_GATEWAY_TOKEN` or `SP1_GATEWAY_SOURCE_SERVICE` is missing, the program will panic on startup with a clear error message.

## Request Rewriting Rules

Example with a gRPC request to `https://rpc.production.succinct.xyz/v1/proof`:

| Field | Original | Rewritten |
|-------|----------|-----------|
| URL | `https://rpc.production.succinct.xyz/v1/proof` | `http://<SP1_GATEWAY_HOST>/v1/proof` |
| Header `third-host` | — | `rpc.production.succinct.xyz` |
| Header `third-token` | — | `<SP1_GATEWAY_TOKEN>` |
| Header `source-service` | — | `<SP1_GATEWAY_SOURCE_SERVICE>` |

For presigned URLs (e.g. S3 uploads/downloads), `third-host` is dynamically extracted as the corresponding S3 domain. Query parameters (including signatures) are preserved as-is.

## Usage

### 1. Configure Environment Variables

```bash
export SP1_GATEWAY_HOST="http://your-gateway-host:9080"
export SP1_GATEWAY_TOKEN="your-grpc-gateway-token"
export SP1_GATEWAY_S3_TOKEN="your-s3-gateway-token"   # optional, falls back to SP1_GATEWAY_TOKEN
export SP1_GATEWAY_SOURCE_SERVICE="your-service-name"
```

### 2. Start the Service

No code changes or startup flags are needed. The SDK automatically detects the environment variables and enables the gateway proxy.

### 3. Disable Gateway

Simply leave `SP1_GATEWAY_HOST` unset. The SDK behaves exactly as the upstream version.

## Gateway-Side Configuration

The gateway needs to:
1. Read the `third-host` header from incoming requests as the upstream target
2. Validate the `third-token` header
3. Forward the request to the upstream specified by `third-host`, preserving the path and query parameters
4. Establish TLS connections for HTTPS upstreams

## Dependency

This feature is implemented via a patched `sp1-sdk` in `Cargo.toml`:

```toml
[patch.crates-io]
sp1-sdk = { git = "https://github.com/okx/sp1", branch = "feat/gateway-proxy-v6.0.2" }
```

Based on SP1 v6.0.2. Only the `sp1-sdk` crate is modified; no other SP1 components are affected.
