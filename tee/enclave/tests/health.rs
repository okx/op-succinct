mod common;

use serde_json::Value;
use xlayer_tee_types::paths;

#[tokio::test]
async fn health_returns_200_with_signer_info() {
    let app = common::app();
    let (status, body) = common::call(&app, common::get(paths::HEALTH)).await;
    assert_eq!(status, 200);
    let json: Value = serde_json::from_slice(&body).expect("health body is JSON");
    assert_eq!(json["status"], "ready");
    assert!(
        json["signer_address"].as_str().unwrap().starts_with("0x"),
        "signer_address present"
    );
    assert_eq!(
        json["signer_address"].as_str().unwrap().len(),
        42,
        "20-byte address as 0x-prefixed hex"
    );
    let pk = json["signer_pubkey"].as_str().unwrap();
    assert!(pk.starts_with("0x04"), "uncompressed SEC1 pubkey starts with 0x04");
    assert_eq!(pk.len(), 2 + 65 * 2);
    assert_eq!(json["pcr0"], "0x".to_string() + &"00".repeat(32));
}
