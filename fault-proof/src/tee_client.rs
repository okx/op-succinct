use alloy_primitives::Bytes as AlloBytes;
use alloy_sol_types::SolValue;
use alloy_transport_http::reqwest::{Client, StatusCode, Url};
use anyhow::{bail, Context, Result};
use base64::Engine;
use op_succinct_client_utils::boot::BootInfoStruct;
use serde::Deserialize;
use tokio::time::{sleep, timeout, Duration};
use xlayer_tee_types::journal::RangeJournal;

pub struct TeeHostClient {
    base_url: Url,
    http: Client,
    poll_interval: Duration,
    task_timeout: Duration,
}

impl TeeHostClient {
    pub fn new(base_url: Url, poll_interval_ms: u64, task_timeout_s: u64) -> Self {
        Self {
            base_url,
            http: Client::new(),
            poll_interval: Duration::from_millis(poll_interval_ms),
            task_timeout: Duration::from_secs(task_timeout_s),
        }
    }

    pub async fn submit_task(
        &self,
        witness: &[u8],
        start_blk: u64,
        end_blk: u64,
    ) -> Result<String> {
        let url = self.base_url.join("/tee/task")?;
        let resp = self
            .http
            .post(url)
            .header("content-type", "application/octet-stream")
            .header("x-start-block", start_blk.to_string())
            .header("x-end-block", end_blk.to_string())
            .body(witness.to_vec())
            .send()
            .await
            .context("TEE host unreachable")?;

        let status = resp.status();
        let body: ApiResponse<CreateTaskData> =
            resp.json().await.context("failed to parse TEE task submission response")?;

        if status.is_success() {
            Ok(body.data.context("missing task data")?.task_id)
        } else {
            bail!("TEE task submission failed: HTTP {status}")
        }
    }

    pub async fn wait_for_proof(&self, task_id: &str) -> Result<Vec<u8>> {
        let url = self.base_url.join(&format!("/tee/task/{task_id}"))?;
        let poll_fut = async {
            loop {
                let resp = self
                    .http
                    .get(url.clone())
                    .send()
                    .await
                    .context("TEE host unreachable during poll")?;

                if resp.status() == StatusCode::NOT_FOUND {
                    bail!("TEE task {task_id} not found (404)");
                }

                let body: ApiResponse<QueryTaskData> =
                    resp.json().await.context("failed to parse TEE task query response")?;
                let data = body.data.context("missing task data in query response")?;

                match data.status.as_str() {
                    "Finished" => {
                        let proof_hex =
                            data.proof_bytes.context("finished task missing proof_bytes")?;
                        let proof = hex::decode(proof_hex.trim_start_matches("0x"))
                            .context("invalid hex in proof_bytes")?;
                        return Ok(proof);
                    }
                    "Failed" => {
                        let msg = data
                            .detail
                            .and_then(|d| d.failure_message)
                            .unwrap_or_else(|| "unknown failure".to_string());
                        bail!("TEE task {task_id} failed: {msg}");
                    }
                    "Running" => {
                        sleep(self.poll_interval).await;
                    }
                    other => {
                        bail!("TEE task {task_id} unexpected status: {other}");
                    }
                }
            }
        };

        timeout(self.task_timeout, poll_fut).await.map_err(|_| {
            anyhow::anyhow!("TEE task {task_id} timed out after {:?}", self.task_timeout)
        })?
    }

    pub async fn get_attestation(&self) -> Result<Vec<u8>> {
        let url = self.base_url.join("/tee/info")?;
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .context("TEE host unreachable during attestation fetch")?;
        let body: ApiResponse<AttestationData> =
            resp.json().await.context("failed to parse TEE info response")?;
        let data = body.data.context("missing attestation data")?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&data.attestation_doc)
            .context("invalid base64 in attestation_doc")?;
        Ok(raw)
    }
}

// --- Pure functions ---

pub fn unpack_proof_bytes(bytes: &[u8]) -> Result<(RangeJournal, Vec<u8>)> {
    type ProofTuple = (RangeJournal, AlloBytes);
    let (journal, sig_bytes) =
        ProofTuple::abi_decode_params(bytes).context("ABI decode of TEE proof bytes failed")?;
    Ok((journal, sig_bytes.to_vec()))
}

pub fn journal_to_boot_info(j: &RangeJournal) -> BootInfoStruct {
    BootInfoStruct {
        l1Head: j.l1OriginHash,
        l2PreRoot: j.prevOutputRoot,
        l2PostRoot: j.outputRoot,
        l2BlockNumber: j.l2BlockNumber,
        rollupConfigHash: j.configHash,
    }
}

// --- JSON response serde types (private) ---

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiResponse<T> {
    data: Option<T>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTaskData {
    task_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueryTaskData {
    status: String,
    proof_bytes: Option<String>,
    detail: Option<QueryDetail>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueryDetail {
    failure_message: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestationData {
    attestation_doc: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::FixedBytes;
    use xlayer_tee_types::journal::RangeJournalWire;

    fn make_wire(pcr0: u8, cfg: u8, l1: u8, block: u64, prev: u8, out: u8) -> RangeJournalWire {
        RangeJournalWire {
            pcr0: [pcr0; 32],
            config_hash: [cfg; 32],
            l1_origin_hash: [l1; 32],
            l2_block_number: block,
            prev_output_root: [prev; 32],
            output_root: [out; 32],
        }
    }

    fn pack_proof_bytes(wire: &RangeJournalWire, signature: &[u8; 65]) -> Vec<u8> {
        let journal = RangeJournal::from(wire);
        let sig_bytes = AlloBytes::copy_from_slice(signature);
        (journal, sig_bytes).abi_encode_params()
    }

    #[test]
    fn unpack_round_trip_typical() {
        let wire = make_wire(0x01, 0x02, 0x03, 12345678, 0x04, 0x05);
        let sig = [0xAB_u8; 65];
        let packed = pack_proof_bytes(&wire, &sig);

        let (journal, recovered_sig) = unpack_proof_bytes(&packed).expect("unpack should succeed");

        assert_eq!(journal.pcr0.0, [0x01; 32]);
        assert_eq!(journal.configHash.0, [0x02; 32]);
        assert_eq!(journal.l1OriginHash.0, [0x03; 32]);
        assert_eq!(journal.l2BlockNumber, 12345678);
        assert_eq!(journal.prevOutputRoot.0, [0x04; 32]);
        assert_eq!(journal.outputRoot.0, [0x05; 32]);
        assert_eq!(recovered_sig, vec![0xAB; 65]);
    }

    #[test]
    fn unpack_round_trip_all_zero() {
        let wire = make_wire(0, 0, 0, 0, 0, 0);
        let sig = [0_u8; 65];
        let packed = pack_proof_bytes(&wire, &sig);

        let (journal, recovered_sig) = unpack_proof_bytes(&packed).expect("unpack should succeed");
        assert_eq!(journal.l2BlockNumber, 0);
        assert_eq!(recovered_sig, vec![0u8; 65]);
    }

    #[test]
    fn unpack_corrupted_input() {
        let result = unpack_proof_bytes(&[0xDE, 0xAD]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ABI decode"), "error should mention ABI decode: {err}");
    }

    #[test]
    fn journal_to_boot_info_field_mapping() {
        let journal = RangeJournal {
            pcr0: FixedBytes([0xAA; 32]),
            configHash: FixedBytes([0xBB; 32]),
            l1OriginHash: FixedBytes([0xCC; 32]),
            l2BlockNumber: 42,
            prevOutputRoot: FixedBytes([0xDD; 32]),
            outputRoot: FixedBytes([0xEE; 32]),
        };

        let boot = journal_to_boot_info(&journal);

        assert_eq!(boot.l1Head, FixedBytes([0xCC; 32]), "l1Head should map from l1OriginHash");
        assert_eq!(
            boot.l2PreRoot,
            FixedBytes([0xDD; 32]),
            "l2PreRoot should map from prevOutputRoot"
        );
        assert_eq!(
            boot.l2PostRoot,
            FixedBytes([0xEE; 32]),
            "l2PostRoot should map from outputRoot"
        );
        assert_eq!(boot.l2BlockNumber, 42);
        assert_eq!(
            boot.rollupConfigHash,
            FixedBytes([0xBB; 32]),
            "rollupConfigHash should map from configHash"
        );
    }

    #[test]
    fn journal_to_boot_info_pcr0_not_mapped() {
        let journal = RangeJournal {
            pcr0: FixedBytes([0xFF; 32]),
            configHash: FixedBytes([0x00; 32]),
            l1OriginHash: FixedBytes([0x00; 32]),
            l2BlockNumber: 0,
            prevOutputRoot: FixedBytes([0x00; 32]),
            outputRoot: FixedBytes([0x00; 32]),
        };

        let boot = journal_to_boot_info(&journal);
        assert_ne!(
            boot.l1Head.0, [0xFF; 32],
            "pcr0 must NOT be mapped to any BootInfoStruct field"
        );
        assert_ne!(boot.rollupConfigHash.0, [0xFF; 32]);
    }

    #[test]
    fn unpack_uses_abi_decode_params_not_abi_decode() {
        let wire = make_wire(0x01, 0x02, 0x03, 42, 0x04, 0x05);
        let sig = [0xAB_u8; 65];

        // Pack with abi_encode (wrong) and verify unpack fails or gives wrong result
        let journal = RangeJournal::from(&wire);
        let sig_bytes = AlloBytes::copy_from_slice(&sig);
        let wrong_encoding = (journal, sig_bytes).abi_encode();

        // abi_decode_params on abi_encode'd data should fail or produce different results
        let result = unpack_proof_bytes(&wrong_encoding);
        // The data encoded with abi_encode has an extra offset that will cause decode mismatch
        if let Ok((j, s)) = &result {
            // If it somehow decodes, the values should be different
            let correct_packed = pack_proof_bytes(&wire, &sig);
            let (correct_j, correct_s) = unpack_proof_bytes(&correct_packed).unwrap();
            assert!(
                j != &correct_j || s != &correct_s,
                "abi_encode vs abi_encode_params should produce different results"
            );
        }
        // Either way the test passes -- the important thing is pack_proof_bytes uses
        // abi_encode_params
    }
}
