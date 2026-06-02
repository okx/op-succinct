---
name: "error-codes"
description: "Error registration conventions for op-succinct — uses anyhow + thiserror, no numeric error codes"
---
# Error Codes

op-succinct does NOT use a centralised numeric error-code registry. Errors flow as:

| Mechanism | Where | Notes |
|-----------|-------|-------|
| `anyhow::Result<T>` | Most service code (`validity`, `fault-proof`, `host-utils`, `proof-utils`, `scripts/*`) | Errors annotated with `.context("…")` and `anyhow!("…")` for diagnostic strings |
| `HostError::code() -> i32` | `xlayer-tee-host` only | **Intentional deviation**: 4-band numeric codes (0/10001/10004/20001) required by proposer contract. See `apis/rest-api-conventions.md` for details |
| `thiserror::Error` enums | Crate-specific error types | e.g. `utils/signer/src/xlayer_remote_client.rs::XLayerSignerError` — variants: `HttpError`, `SigningFailed`, `VerificationError`, `InvalidResponse`, `SignatureTimeout`, `NetworkError`, `ConfigError` |
| Prometheus error counters | `validity::ValidityGauge` (e.g. `WitnessgenErrorCount`, `RangeProofRequestErrorCount`, `AggProofRequestErrorCount`, `ProofRequestTimeoutErrorCount`, `RetryErrorCount`, `TotalErrorCount`) | Increment before returning `Err`; no numeric error code attached |
| On-chain revert | Solidity reverts surface through alloy `error.is_revert()` | Logged but not retried within the same loop iteration |

## Registration Conventions

| Convention | Rule |
|-----------|------|
| `[Rule]` New error variants | When adding a new `thiserror` variant, mark `#[error("…")]` with a stable, human-readable message — downstream services grep on these strings in operator runbooks. |
| `[Rule]` Metric increment | On error in `validity`, increment the matching `ValidityGauge::*ErrorCount` **before** returning `Err`. — Reason: alerts depend on it; silent errors won't page anyone. |
| `[Rule]` Sensitive data in error messages | NEVER include `access_key`, `secret_key`, raw transaction data, or raw signed bytes in any error message. — `Debug` impl on `XLayerConfig` already redacts these; new errors must follow suit. |
