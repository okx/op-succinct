// TZ-specific implementations of `OPSuccinctChallenger` methods.
//
// Declared as a child module of `challenger` (via `#[path]`), so `use super::*` gives access to
// all types and private fields from challenger.rs without changing their visibility.

use super::*;

impl<P> OPSuccinctChallenger<P>
where
    P: Provider + Clone,
{
    /// Creates a new challenger with an injected L2 provider.
    /// Avoids constructing the provider from config.l2_rpc and allows a custom L2 data source.
    pub fn new_with_l2_provider(
        config: ChallengerConfig,
        l1_provider: L1Provider,
        anchor_state_registry: AnchorStateRegistryInstance<P>,
        factory: DisputeGameFactoryInstance<P>,
        signer: SignerLock,
        l2_provider: Arc<dyn L2ProviderTrait + Send + Sync>,
    ) -> Self {
        OPSuccinctChallenger {
            config,
            signer,
            l1_provider,
            l2_provider,
            anchor_state_registry,
            factory,
            challenger_bond: OnceLock::new(),
            state: Arc::new(Mutex::new(ChallengerState {
                cursor: U256::ZERO,
                games: HashMap::new(),
            })),
        }
    }
}
