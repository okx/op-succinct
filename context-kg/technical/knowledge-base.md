---
name: "knowledge-base"
description: "Highest-authority rules for op-succinct — all Skills defer to this on conflicts"
---
# Knowledge Base

> This is the highest-weight file in the knowledge base. All Skills that support context-kg defer to this file when conflicts arise with general AI knowledge.

## Data Type Constraints

[Rule] `utils/signer/src/xlayer_remote_client.rs`: `XLayerConfig.secret_key` must be 16, 24, or 32 bytes (AES-128/192/256). — Reason: matches Go `aes.NewCipher` behavior and the asset-onchain remote signer's key length contract.

[Rule] `utils/signer/src/xlayer_remote_client.rs`: auth headers (`accessKey`, `sign`) must NOT be added when either `access_key` or `secret_key` is empty. — Reason: mirrors Go `addAuth` short-circuit; lets the service run with anonymous mode when no credentials are configured.

[Rule] `utils/client/src/oracle/blob_provider.rs`: KZG verification panics — never wrap in a `Result`. — Reason: a single invalid blob inside the zkVM guest must abort the proof; recovery is not meaningful in-guest.

[Rule] `validity/src/db/types.rs`: `RequestStatus`/`RequestType`/`RequestMode` `i16` → enum conversions assume valid DB rows; corrupted values panic. — Reason: documented panic-on-corruption invariant; callers must trust the DB schema migrations.

## Naming Constraints

[Rule] `fault-proof/src/contract.rs`: contract binding instances use `*Instance` suffix (e.g. `DisputeGameFactoryInstance`, `OPSuccinctL2OOContract`). — Reason: alloy `sol!`-generated naming convention; cross-module callers depend on this pattern.

[Rule] `validity/src/db/types.rs`: enum variants use PascalCase mapped to `i16` repr (`Unrequested = 0`, `Range = 0`, `Real = 0`). — Reason: stable serialization to Postgres `smallint`; renumbering breaks existing DB rows.

[Rule] `utils/signer/src/xlayer_remote_client.rs`: `OperateType` enum repr is `i32` with externally-visible values (20, 21, 22, 23, 27, 28). — Reason: values are serialized to the remote signer service and must match Go's `OperateType` constants exactly.

## Dependency Constraints

[Rule] `Cargo.toml` (workspace `[patch.crates-io]`): sp1-* and slop-* crates must be patched to `github.com/okx/sp1#feat/gateway-proxy-v6.1.0`. — Reason: cluster proxy auth requires the OKX fork; removing the patch breaks production cluster access.

[Rule] `utils/host/Cargo.toml`: must NOT add `kona-rpc`. — Reason: triggers `reth-optimism-primitives` → alloy version conflict with hokulea v1.1.4; RPC types are defined locally in `utils/host/src/rpc_types.rs` instead.

[Rule] `utils/client/src/lib.rs`: client crate (zkVM guest) must NOT import `utils/host`, `utils/signer`, `utils/proof`, or any `*-host-utils`. — Reason: hard boundary between zkVM-guest code (no RPC, no syscalls beyond preimage oracle) and host orchestration.

[Rule] `fault-proof/Cargo.toml` ↔ `validity/Cargo.toml`: must NOT depend on each other. — Reason: validity (L2OutputOracle path) and fault-proof (DisputeGameFactory path) are intentionally separate services; cross-imports indicate a design mistake.

[Rule] `utils/proof/src/lib.rs`: DA layer is selected by Cargo feature flag (`ethereum` / `celestia` / `eigenda`) at compile time; do not attempt multi-DA in one build. — Reason: `cfg_if` dispatch in `initialize_host()` only allows a single host impl per binary.

## Security Constraints

[Rule] `utils/signer/src/lib.rs`: production deployments must use `XLayerRemoteSigner`, `CloudHsmSigner` (GCP-KMS), or `Web3Signer`; never `LocalSigner` (in-memory private key). — Reason: HSM-backed key custody is required for funded proposer/challenger addresses.

[Rule] `utils/signer/src/xlayer_remote_client.rs`: private keys, access keys, and secret keys must never be logged. The `Debug` impl redacts them as `***REDACTED***`. — Reason: HTTP debug logs are written to stderr and persisted in test pipelines.

[Rule] `validity/src/env.rs` and `fault-proof/src/config.rs`: all secrets (DB password, signer key, KMS resource) must be read from environment variables; never hardcode in source. — Reason: source is checked in and visible to all developers; secrets management is delegated to the deployment environment.

[Rule] `utils/signer/src/xlayer_remote_client.rs`: when both `access_key` and `secret_key` are set, signature header is computed as `base64(AES-ECB(sha256_hex(sorted_url_values + body), secret_key))`. — Reason: must remain byte-identical to Go `generateSignature` so requests verify against the asset-onchain service.
