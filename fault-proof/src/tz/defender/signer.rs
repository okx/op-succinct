//! Shared signer construction for the Defender binary and its integration tests.
//!
//! Both `tz-defender` and the fault-proof integration tests call [`wire_defender_signer`], and both
//! of its build-specific shapes delegate to `wire_defender_signer_core` — the single, `cfg`-free
//! function that constructs the signer, starts the refOrderId lookup endpoint and wires it into the
//! challenge manager. Only the seed of a known reference-order ID through the wired path is
//! test-only. Sharing one wiring statement is what makes the wiring testable: deleting the
//! `set_signer` call in the core silently unpins the signer from the adapter in *every*
//! configuration, and every test that seeds through `get_signer()` then fails instead of passing on
//! a differently wired adapter.

use std::sync::Arc;

use anyhow::Result;
use op_succinct_signer_utils::SignerLock;
// The client type is a public export of the signer crate, so it is imported unconditionally and
// `build_defender_signer` compiles in a production build. Only the *methods*
// `seed_ref_order_id` and the `SignerLock::xlayer_verify_target` accessor are feature-gated.
use op_succinct_signer_utils::XLayerRemoteClient;

use super::{challenge_manager::ChallengeManagerContract, leaf_locator::DirectLeafLocator};

/// Constructs the Defender's signer from the environment, gated on `XLAYER_SIGNER_ENABLED`.
///
/// Returns:
/// - `(None, None)` when `XLAYER_SIGNER_ENABLED` is unset or not `"true"` — the Defender then runs
///   without a signer, verifying challenges locally without broadcasting;
/// - `(Some(lock), Some(client))` when the signer is enabled and resolves a lookup target;
/// - `(Some(lock), None)` when the signer is enabled without a lookup target.
///
/// The client is only collected for test assertions; in a production build the extraction is
/// compiled out and the second element is always `None`. The signer itself is always constructed
/// here, because a production build calls this function too.
pub async fn build_defender_signer() -> Result<(Option<SignerLock>, Option<Arc<XLayerRemoteClient>>)>
{
    let enabled =
        std::env::var("XLAYER_SIGNER_ENABLED").map(|v| v.to_lowercase() == "true").unwrap_or(false);

    if !enabled {
        tracing::info!("signer not enabled — running without a transaction signer");
        return Ok((None, None));
    }

    let lock = SignerLock::from_env().await?;

    #[cfg(any(test, feature = "xlayer-verify-test-utils"))]
    let client: Option<Arc<XLayerRemoteClient>> =
        lock.xlayer_verify_target().await?.map(|(_, client)| client);
    #[cfg(not(any(test, feature = "xlayer-verify-test-utils")))]
    let client: Option<Arc<XLayerRemoteClient>> = None;

    tracing::info!(
        verify_addr = %client.as_ref().map(|c| c.verify_addr()).unwrap_or("(none)"),
        "Defender signer constructed"
    );

    Ok((Some(lock), client))
}

/// The one and only wiring path.
///
/// 1. constructs the signer through [`build_defender_signer`];
/// 2. starts the refOrderId lookup endpoint (a no-op when no address is configured);
/// 3. wires the signer into the challenge manager through `set_signer`.
///
/// There is deliberately **no `cfg` on this function**: every build — the delivered binary and the
/// test-utils build alike — reaches `set_signer` through here. So the `set_signer` call below is
/// the single wiring statement in this file, and deleting it changes every configuration at once.
/// That is what makes a mutation of that line meaningful evidence about the delivered wiring rather
/// than about a test-only branch.
///
/// `lock.clone()` shares the inner signer rather than duplicating it: `SignerLock` is
/// `#[derive(Clone)]` over `inner: Arc<Mutex<Signer>>`, so the endpoint serving the lookup and the
/// signer the broadcast path holds are one instance. A future refactor must not "simplify" this
/// into a freshly constructed `SignerLock`.
///
/// A failing lookup endpoint (an address that cannot be bound) is an error, not a warning: the
/// asset-management callback must not be left unanswered for the order IDs this service issues, so
/// startup stops here.
///
/// Returns the client that serves the endpoint, for callers that assert on listener identity. It
/// deliberately does not return the `SignerLock`: the caller that needs the signer handle reads it
/// back with `get_signer()`, which is the handle the seed step needs anyway, and which keeps a
/// second `Arc::new(lock.clone())` off the wiring path.
async fn wire_defender_signer_core(
    challenge: &Arc<ChallengeManagerContract<DirectLeafLocator>>,
) -> Result<Option<Arc<XLayerRemoteClient>>> {
    let (lock_opt, listener_client) = build_defender_signer().await?;

    if let Some(ref lock) = lock_opt {
        lock.maybe_spawn_xlayer_verify_server().await?;
        challenge.set_signer(Arc::new(lock.clone()));
        tracing::info!("Defender signer enabled: lookup endpoint started, submit path reserved");
    } else {
        tracing::info!("Defender running without a signer");
    }

    Ok(listener_client)
}

/// Full signer wiring for the Defender binary and its integration tests.
///
/// Delegates the build/spawn/wire sequence to [`wire_defender_signer_core`], then adds the one step
/// that is genuinely test-only: seeding the ID named by `XLAYER_TEST_SEED_REF_ORDER_ID` through the
/// signer that was just wired — `get_signer()` → `xlayer_verify_target()` → `seed_ref_order_id()`.
/// The seed reads back what the wiring step stored, so removing the wiring makes the seed silently
/// disappear and the known-ID lookup answer "not found".
///
/// Test builds return the client that serves the endpoint so a caller can assert it is the same
/// instance the adapter holds; production returns `()`.
#[cfg(any(test, feature = "xlayer-verify-test-utils"))]
pub async fn wire_defender_signer(
    challenge: &Arc<ChallengeManagerContract<DirectLeafLocator>>,
) -> Result<Option<Arc<XLayerRemoteClient>>> {
    let listener_client = wire_defender_signer_core(challenge).await?;

    if let Ok(seed_id) = std::env::var("XLAYER_TEST_SEED_REF_ORDER_ID") {
        match challenge.get_signer() {
            Some(wired) => match wired.xlayer_verify_target().await? {
                Some((_addr, client)) => {
                    client.seed_ref_order_id(&seed_id).await;
                    tracing::info!(%seed_id, "seeded refOrderId through the wired signer");
                }
                None => {
                    tracing::warn!("seed requested but the wired signer resolves no lookup target")
                }
            },
            None => tracing::warn!(
                "seed requested but the adapter holds no signer — the wiring step did not run"
            ),
        }
    }

    Ok(listener_client)
}

/// Production build: the same wiring, without the test-only seed hook and without returning the
/// client.
#[cfg(not(any(test, feature = "xlayer-verify-test-utils")))]
pub async fn wire_defender_signer(
    challenge: &Arc<ChallengeManagerContract<DirectLeafLocator>>,
) -> Result<()> {
    wire_defender_signer_core(challenge).await?;
    Ok(())
}
