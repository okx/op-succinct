//! Startup-level check of the refOrderId lookup endpoint on the challenger
//! side.
//!
//! The endpoint is served from the very client that signs, so the check drives
//! the same startup sequence the challenger runs: read the signer from the
//! environment, then start the lookup endpoint before any signing work begins.
//! A real socket is then asked the documented question over HTTP.
//!
//! The scenarios are steps of one test because the configuration they vary is
//! read from process environment variables, which every test in this binary
//! shares; separate tests would race on that state. Each step configures and
//! starts its own signer in turn.
//!
//! Everything runs on the loopback interface. No order is issued to a real
//! service and no chain or funds are involved.

#![cfg(feature = "tz")]

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use op_succinct_signer_utils::SignerLock;

/// Prefix the challenger stamps on the order IDs it issues. It has to differ
/// from the proposer's, because both services feed the same asset-management
/// service and their order IDs must stay distinguishable.
const CHALLENGER_PREFIX: &str = "CHALLENGER_TZ_";

/// Prefix the proposer uses; the challenger must not reuse it.
const PROPOSER_PREFIX: &str = "PROPOSER_TZ_";

/// Default lookup address the proposer example configuration ships with.
const PROPOSER_VERIFY_ADDR: &str = "127.0.0.1:9191";

/// Applies the remote-signer configuration a challenger deployment uses, with
/// the lookup endpoint on `verify_addr`.
fn configure_challenger_signer(verify_addr: &str) {
    std::env::set_var("XLAYER_SIGNER_ENABLED", "true");
    std::env::set_var("XLAYER_SIGNER_ENDPOINT", "http://127.0.0.1:1");
    std::env::set_var("XLAYER_SIGNER_ADDRESS", "0x9b3F173823E944d183D532ed236Ee3B83Ef15E1d");
    std::env::set_var("XLAYER_ACCESS_KEY", "test-access-key");
    std::env::set_var("XLAYER_SECRET_KEY", "0123456789abcdef");
    std::env::set_var("XLAYER_SIGNER_REF_ORDER_PREFIX", CHALLENGER_PREFIX);
    std::env::set_var("XLAYER_SIGNER_VERIFY_ADDR", verify_addr);
    std::env::set_var("ENABLE_KMS", "false");
}

/// Reserves a loopback port by binding and immediately releasing it, so the
/// endpoint can be given a known address to bind.
async fn reserve_loopback_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    port
}

/// Queries the lookup endpoint, retrying until it has accepted its first
/// connection — a readiness signal rather than a fixed sleep.
async fn lookup(addr: SocketAddr, ref_order_id: &str) -> (u16, u16, i64, String) {
    let url = format!("http://{addr}/signer/get?refOrderId={ref_order_id}");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match reqwest::get(&url).await {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap();
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                return (
                    status,
                    parsed["status"].as_u64().unwrap() as u16,
                    parsed["code"].as_i64().unwrap(),
                    parsed["msg"].as_str().unwrap().to_string(),
                );
            }
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "the lookup endpoint never became reachable at {addr}: {error}"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

/// Drives the challenger's startup sequence on a configured lookup address.
///
/// These are the same two calls the challenger binary makes, in the same order:
/// read the signer from the environment, then start the lookup endpoint before
/// any signing work begins.
async fn start_challenger_signer(verify_addr: &str) -> Result<SocketAddr, anyhow::Error> {
    configure_challenger_signer(verify_addr);
    let signer = SignerLock::from_env().await.unwrap();
    signer.maybe_spawn_xlayer_verify_server().await?;
    Ok(verify_addr.parse().unwrap())
}

/// The challenger's startup sequence really binds and serves the documented
/// lookup contract, answers before any signing request has been made, and
/// reports an unusable or disabled configuration instead of hiding it.
#[tokio::test]
async fn test_challenger_lookup_endpoint_startup() {
    // --- Scenario 1: a configured address is bound and serves the contract ---
    let port = reserve_loopback_port().await;
    // The listener must be distinct from the proposer's so the two services can
    // run side by side on one host.
    assert_ne!(format!("127.0.0.1:{port}"), PROPOSER_VERIFY_ADDR);
    assert_ne!(CHALLENGER_PREFIX, PROPOSER_PREFIX);

    let addr = start_challenger_signer(&format!("127.0.0.1:{port}")).await.unwrap();

    // Nothing has been issued yet: this is the state a callback sees before
    // any signing request has been made.
    let (status, code, msg, _) = lookup(addr, "CHALLENGER_TZ_99_9999_ffffffff").await;
    assert_eq!((status, code), (200, 1), "an unissued id must answer 200/not-found");
    assert_eq!(msg, "not found");

    // An empty parameter keeps answering the documented error body.
    let (status, code, msg, _) = lookup(addr, "").await;
    assert_eq!((status, code), (400, 1));
    assert_eq!(msg, "refOrderId is required");

    // --- Scenario 2: an unset address starts nothing ---
    let unused_port = reserve_loopback_port().await;
    let unused_addr: SocketAddr = format!("127.0.0.1:{unused_port}").parse().unwrap();
    start_challenger_signer("").await.unwrap();
    assert!(
        reqwest::get(format!("http://{unused_addr}/signer/get?refOrderId=ANY")).await.is_err(),
        "no listener may be started when the lookup address is unset"
    );

    // --- Scenario 3: an unparseable address stops startup ---
    let err = start_challenger_signer("definitely-not-a-socket-addr")
        .await
        .expect_err("an unparseable lookup address must stop startup");
    assert!(err.to_string().contains("invalid XLAYER_SIGNER_VERIFY_ADDR"), "got: {err}");

    // --- Scenario 4: an address that is already taken stops startup ---
    let occupant = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied_port = occupant.local_addr().unwrap().port();
    start_challenger_signer(&format!("127.0.0.1:{occupied_port}"))
        .await
        .expect_err("binding to an occupied address must fail");
    drop(occupant);
}
