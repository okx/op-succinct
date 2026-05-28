mod common;

use xlayer_tee_enclave::attestation::DEV_ATTESTATION_MARKER;
use xlayer_tee_types::wire;

#[tokio::test]
async fn attestation_returns_dev_marker_blob() {
    let app = common::app();
    let (status, body) = common::call(&app, common::get(wire::ATTESTATION)).await;
    assert_eq!(status, 200);
    assert!(body.len() >= DEV_ATTESTATION_MARKER.len());
    assert!(
        body.starts_with(DEV_ATTESTATION_MARKER),
        "dev attestation must start with the dev marker"
    );
    // Tail of the doc embeds the enclave pubkey — we can sanity check by
    // length: marker + 2 (len) + N (user_data) + 65 (pubkey).
    assert!(body.len() >= DEV_ATTESTATION_MARKER.len() + 2 + 65);
}
