//! Multisig approval engine used by Grainlify upgrade flows.
//!
//! Proposal identifiers are allocated from a monotonic counter and are treated
//! as stable handles for subsequent approval and execution steps.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Vec};

/// =======================
/// Storage Keys
/// =======================
#[contracttype]
enum DataKey {
    Config,
    Proposal(u64),
    ProposalCounter,
    Paused,
}

/// =======================
/// Multisig Configuration
/// =======================
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiSigConfig {
    /// Ordered signer set authorized to create and approve proposals.
    pub signers: Vec<Address>,
    /// Minimum number of distinct signer approvals required for execution.
    pub threshold: u32,
}

/// =======================
/// Proposal Structure
/// =======================
#[contracttype]
#[derive(Clone)]
pub struct Proposal {
    /// Signers that have approved this proposal.
    pub approvals: Vec<Address>,
    /// Whether the proposal has already been consumed by execution.
    pub executed: bool,
}

/// =======================
/// Errors
/// =======================
#[derive(Debug)]
pub enum MultiSigError {
    NotSigner,
    AlreadyApproved,
    ProposalNotFound,
    ProposalAlreadyExists,
    AlreadyExecuted,
    ThresholdNotMet,
    InvalidThreshold,
    ContractPaused,
    StateInconsistent,
}

/// =======================
/// Public API
/// =======================
pub struct MultiSig;

impl MultiSig {
    /// Initializes the signer set and execution threshold.
    pub fn init(env: &Env, signers: Vec<Address>, threshold: u32) {
        if threshold == 0 || threshold > signers.len() {
            panic!("{:?}", MultiSigError::InvalidThreshold);
        }

        let config = MultiSigConfig { signers, threshold };
        env.storage().instance().set(&DataKey::Config, &config);
        env.storage()
            .instance()
            .set(&DataKey::ProposalCounter, &0u64);
    }

    /// Creates a new proposal and returns its stable identifier.
    pub fn propose(env: &Env, proposer: Address) -> u64 {
        proposer.require_auth();

        let config = Self::get_config(env);
        Self::assert_signer(&config, &proposer);

        let mut counter: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ProposalCounter)
            .unwrap_or(0);

        counter += 1;

        let proposal = Proposal {
            approvals: Vec::new(env),
            executed: false,
        };

        if env.storage().instance().has(&DataKey::Proposal(counter)) {
            panic!("{:?}", MultiSigError::ProposalAlreadyExists);
        }

        env.storage()
            .instance()
            .set(&DataKey::Proposal(counter), &proposal);
        env.storage()
            .instance()
            .set(&DataKey::ProposalCounter, &counter);

        env.events().publish((symbol_short!("proposal"),), counter);

        counter
    }

    /// Records a signer approval for an existing proposal.
    pub fn approve(env: &Env, proposal_id: u64, signer: Address) {
        signer.require_auth();

        let config = Self::get_config(env);
        Self::assert_signer(&config, &signer);

        let mut proposal = Self::get_proposal(env, proposal_id);

        if proposal.executed {
            panic!("{:?}", MultiSigError::AlreadyExecuted);
        }

        if proposal.approvals.contains(&signer) {
            panic!("{:?}", MultiSigError::AlreadyApproved);
        }

        proposal.approvals.push_back(signer.clone());

        env.storage()
            .instance()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        env.events()
            .publish((symbol_short!("approved"),), (proposal_id, signer));
    }

    /// Returns whether a proposal currently satisfies the execution threshold.
    pub fn can_execute(env: &Env, proposal_id: u64) -> bool {
        // First check if contract is in a healthy state
        if Self::is_contract_paused(env) || Self::is_state_inconsistent(env) {
            return false;
        }

        let config = Self::get_config(env);
        let proposal = Self::get_proposal(env, proposal_id);

        !proposal.executed && proposal.approvals.len() >= config.threshold
    }

    pub fn is_contract_paused(env: &Env) -> bool {
        env.storage().instance().get(&DataKey::Paused).unwrap_or(false)
    }

    pub fn pause(env: &Env, signer: Address) {
        signer.require_auth();
        let config = Self::get_config(env);
        Self::assert_signer(&config, &signer);
        env.storage().instance().set(&DataKey::Paused, &true);
        env.events().publish((symbol_short!("paused"),), signer);
    }

    pub fn unpause(env: &Env, signer: Address) {
        signer.require_auth();
        let config = Self::get_config(env);
        Self::assert_signer(&config, &signer);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.events().publish((symbol_short!("unpaused"),), signer);
    }

    pub fn is_state_inconsistent(_env: &Env) -> bool {
        false
    }

    /// Marks a proposal as executed after the guarded action succeeds.
    pub fn mark_executed(env: &Env, proposal_id: u64) {
        let mut proposal = Self::get_proposal(env, proposal_id);

        if proposal.executed {
            panic!("{:?}", MultiSigError::AlreadyExecuted);
        }

        if !Self::can_execute(env, proposal_id) {
            panic!("{:?}", MultiSigError::ThresholdNotMet);
        }

        proposal.executed = true;

        env.storage()
            .instance()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        env.events()
            .publish((symbol_short!("executed"),), proposal_id);
    }

    /// Returns the current multisig configuration, if initialized.
    pub fn get_config_opt(env: &Env) -> Option<MultiSigConfig> {
        env.storage().instance().get(&DataKey::Config)
    }

    /// Sets the multisig configuration directly for controlled restore flows.
    pub fn set_config(env: &Env, config: MultiSigConfig) {
        if config.threshold == 0 || config.threshold > config.signers.len() as u32 {
            panic!("{:?}", MultiSigError::InvalidThreshold);
        }
        env.storage().instance().set(&DataKey::Config, &config);
    }

    /// Clears the multisig configuration for controlled restore flows.
    pub fn clear_config(env: &Env) {
        env.storage().instance().remove(&DataKey::Config);
    }

    /// =======================
    /// Internal Helpers
    /// =======================
    fn get_config(env: &Env) -> MultiSigConfig {
        env.storage()
            .instance()
            .get(&DataKey::Config)
            .expect("multisig not initialized")
    }

    fn get_proposal(env: &Env, proposal_id: u64) -> Proposal {
        env.storage()
            .instance()
            .get(&DataKey::Proposal(proposal_id))
            .unwrap_or_else(|| panic!("{:?}", MultiSigError::ProposalNotFound))
    }

    fn assert_signer(config: &MultiSigConfig, signer: &Address) {
        if !config.signers.contains(signer) {
            panic!("{:?}", MultiSigError::NotSigner);
        }
    }
}
