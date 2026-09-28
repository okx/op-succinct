//! Cross-repo leaf-encoding compatibility gate.
//!
//! The Merkle leaf carried by a challenge event is only useful for proving if it equals the leaf
//! the Witness Builder keys its tree by. Those two encodings live in separate repositories and are
//! computed independently: the contract's withdraw hash encodes eight fields, while the Witness
//! Builder record hash encodes nine (it prepends a protocol-version field). Differing arity means
//! the two keccak hashes cannot be equal, so a leaf read straight from the event cannot locate a
//! verifiable Witness-Builder proof.
//!
//! [`LeafEncodingGate`] is the SINGLE, non-bypassable entry to the whole proof flow. It owns one
//! decision — `Proven` iff an immutable, deployment-bound compatibility declaration (published by
//! the contract and Witness Builder owners, bound to the deployment address / chain id / encoding
//! version) matches the deployment this Defender is wired to, else `LeafEncodingMismatch`. No
//! runtime flag, config, environment variable, operator action, or test result can otherwise open
//! it, and there is no local re-encode shim: masking the mismatch is forbidden. An offline equality
//! fixed vector (see the module tests) is a REGRESSION check only — never the release authority.

use alloy_primitives::Address;

/// A field-by-field summary of why the two leaf encodings differ, surfaced on a blocked challenge so
/// an operator sees exactly why no proof is attempted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodingMismatchSummary {
    /// Number of ABI fields the contract's withdraw hash encodes.
    pub contract_field_count: u8,
    /// Number of ABI fields the Witness Builder record hash encodes.
    pub witness_builder_field_count: u8,
    /// A human-readable, field-level description of the difference.
    pub detail: String,
}

impl EncodingMismatchSummary {
    /// The known contract-vs-Witness-Builder difference: the contract withdraw hash encodes eight
    /// fields (chain id, transaction hash, token kind, token, token ids, amounts, user, receiver);
    /// the Witness Builder record hash encodes nine, prepending a protocol-version field. The
    /// differing arity guarantees unequal keccak, so an event leaf cannot locate a record-hash
    /// proof by equality.
    pub fn contract_vs_witness_builder() -> Self {
        Self {
            contract_field_count: 8,
            witness_builder_field_count: 9,
            detail: "contract withdraw hash encodes 8 fields (chainId, txHash, kind, token, \
                     tokenIds, amounts, user, receiver); witness-builder record hash encodes 9, \
                     prepending a protocol-version field — differing arity yields unequal keccak, \
                     so an event leaf cannot locate a record-hash proof"
                .to_string(),
        }
    }
}

/// The gate's single decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeafEncodingDecision {
    /// The two encodings are declared compatible for the wired deployment; the proof flow may run.
    Proven,
    /// The encodings are not declared compatible; the proof flow is blocked with this summary.
    LeafEncodingMismatch(EncodingMismatchSummary),
}

/// The deployment (contract address + chain id) the Defender is wired to. A compatibility
/// declaration must be bound to exactly this deployment to open the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeploymentTarget {
    pub address: Address,
    pub chain_id: u64,
}

/// An immutable, deployment-bound declaration — published by the contract and Witness Builder
/// owners — that the two leaf encodings agree for a specific deployment. It is the SOLE input that
/// can open the gate. It carries the deployment it is bound to (address + chain id) and the encoding
/// version it certifies; it opens the gate only when it matches the wired deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompatibilityDeclaration {
    pub address: Address,
    pub chain_id: u64,
    pub encoding_version: u32,
}

impl CompatibilityDeclaration {
    fn matches(&self, target: &DeploymentTarget) -> bool {
        self.address == target.address && self.chain_id == target.chain_id
    }
}

/// The process-level gate: one decision, no bypass.
pub struct LeafEncodingGate {
    decision: LeafEncodingDecision,
}

impl LeafEncodingGate {
    /// Production constructor: the gate is `Proven` iff `declaration` is present AND bound to
    /// `target` (address + chain id); otherwise it is `LeafEncodingMismatch`. Production wiring
    /// passes `None` until the contract and Witness Builder owners publish a matching declaration —
    /// there is no other way to open it.
    pub fn new(target: DeploymentTarget, declaration: Option<CompatibilityDeclaration>) -> Self {
        let decision = match declaration {
            Some(d) if d.matches(&target) => LeafEncodingDecision::Proven,
            _ => LeafEncodingDecision::LeafEncodingMismatch(
                EncodingMismatchSummary::contract_vs_witness_builder(),
            ),
        };
        Self { decision }
    }

    /// The gate's decision — the sole precondition of the entire Witness-Builder proof flow.
    pub fn decision(&self) -> LeafEncodingDecision {
        self.decision.clone()
    }

    /// Test seam standing in for a matching, deployment-bound compatibility declaration.
    #[cfg(test)]
    pub fn forced_proven() -> Self {
        Self { decision: LeafEncodingDecision::Proven }
    }

    /// Test seam standing in for a mismatched (or absent) declaration, carrying `summary`.
    #[cfg(test)]
    pub fn forced_mismatch(summary: EncodingMismatchSummary) -> Self {
        Self { decision: LeafEncodingDecision::LeafEncodingMismatch(summary) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tz::{defender::verifier::record_leaf_hash, withdraw::types::WithdrawRecord};
    use alloy_primitives::{keccak256, B256, U256};
    use alloy_sol_types::{sol_data, SolType};

    /// The contract-side withdraw-hash leaf: `keccak256(abi.encode(...))` over the eight shared
    /// fields, WITHOUT the protocol-version field the Witness Builder prepends.
    fn contract_withdraw_leaf(record: &WithdrawRecord) -> B256 {
        type ContractAbi = (
            sol_data::Uint<64>,
            sol_data::FixedBytes<32>,
            sol_data::Uint<8>,
            sol_data::Address,
            sol_data::Array<sol_data::Uint<256>>,
            sol_data::Array<sol_data::Uint<256>>,
            sol_data::Address,
            sol_data::Address,
        );
        let encoded = ContractAbi::abi_encode_params(&(
            record.chain_id,
            record.transaction_hash,
            record.token_type,
            record.token_address,
            record.token_ids.as_slice(),
            record.amounts.as_slice(),
            record.from,
            record.to,
        ));
        keccak256(&encoded)
    }

    fn sample_record() -> WithdrawRecord {
        WithdrawRecord {
            version: 1,
            chain_id: 196,
            transaction_hash: B256::repeat_byte(0x42),
            token_type: 0,
            token_address: Address::repeat_byte(0xAA),
            token_ids: vec![U256::ZERO],
            amounts: vec![U256::from(7u64)],
            from: Address::repeat_byte(0x01),
            to: Address::repeat_byte(0x02),
        }
    }

    #[test]
    fn equality_fixed_vector_regression() {
        // REGRESSION check ONLY — never the gate release authority (that is the deployment-bound
        // compatibility declaration). One identical sample, both encodings, assert they differ:
        // the Witness Builder prepends a protocol-version field, so the keccak hashes cannot match
        // and an event leaf cannot locate a record-hash proof by equality.
        let record = sample_record();
        let contract = contract_withdraw_leaf(&record);
        let witness_builder = record_leaf_hash(&record).expect("valid record hashes");
        assert_ne!(
            contract, witness_builder,
            "the contract 8-field withdraw hash must differ from the WB 9-field record hash"
        );
    }

    #[test]
    fn production_gate_without_declaration_is_mismatch() {
        let target = DeploymentTarget { address: Address::repeat_byte(0x11), chain_id: 196 };
        let gate = LeafEncodingGate::new(target, None);
        assert!(matches!(gate.decision(), LeafEncodingDecision::LeafEncodingMismatch(_)));
    }

    #[test]
    fn declaration_opens_gate_only_when_bound_to_the_deployment() {
        let target = DeploymentTarget { address: Address::repeat_byte(0x11), chain_id: 196 };
        // A declaration bound to a DIFFERENT deployment does not open the gate.
        let wrong = CompatibilityDeclaration {
            address: Address::repeat_byte(0x22),
            chain_id: 196,
            encoding_version: 1,
        };
        assert!(matches!(
            LeafEncodingGate::new(target, Some(wrong)).decision(),
            LeafEncodingDecision::LeafEncodingMismatch(_)
        ));
        // A declaration bound to a different chain id does not open the gate.
        let wrong_chain = CompatibilityDeclaration {
            address: Address::repeat_byte(0x11),
            chain_id: 1,
            encoding_version: 1,
        };
        assert!(matches!(
            LeafEncodingGate::new(target, Some(wrong_chain)).decision(),
            LeafEncodingDecision::LeafEncodingMismatch(_)
        ));
        // Only a declaration bound to this exact deployment opens it.
        let matching = CompatibilityDeclaration {
            address: Address::repeat_byte(0x11),
            chain_id: 196,
            encoding_version: 1,
        };
        assert!(matches!(
            LeafEncodingGate::new(target, Some(matching)).decision(),
            LeafEncodingDecision::Proven
        ));
    }
}
