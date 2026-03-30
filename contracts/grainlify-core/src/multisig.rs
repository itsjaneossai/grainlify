//! Multisig approval engine used by Grainlify upgrade flows.
//!
//! Proposal identifiers are allocated from a monotonic counter and are treated
//! as stable handles for subsequent approval and execution steps.
//!
//! # Proposal Lifecycle
//!
//! ```text
//! propose(expiry) → approve* → can_execute → mark_executed
//!                     └──────────────────────── cancel ──┘
//! ```
//!
//! - **Expiry**: An optional ledger timestamp (seconds). When `expiry > 0` and
//!   the current ledger time is `>= expiry`, the proposal is considered expired.
//!   Expired proposals cannot be approved or executed; the stale WASM hash is
//!   permanently blocked.
//!
//! - **Cancellation**: Any signer may explicitly cancel a pending proposal at
//!   any time before execution. Cancellation is irreversible and idempotent-safe
//!   (re-cancelling panics). An already-executed proposal cannot be cancelled.

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
    StateInconsistent,
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
    /// Expiry ledger timestamp (seconds). `0` means the proposal never expires.
    /// When `expiry > 0` and `ledger.timestamp() >= expiry`, the proposal is
    /// considered expired and cannot be approved or executed.
    pub expiry: u64,
    /// Whether the proposal has been explicitly cancelled by a signer.
    /// Cancelled proposals cannot be approved or executed.
    pub cancelled: bool,
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
    /// The proposal's expiry timestamp has passed; it can no longer be acted on.
    ProposalExpired,
    /// The proposal was explicitly cancelled and can no longer be acted on.
    ProposalCancelled,
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
    ///
    /// # Arguments
    /// * `proposer` - A signer who is creating the proposal (requires auth).
    /// * `expiry` - Ledger timestamp (seconds) after which the proposal expires.
    ///   Pass `0` for a proposal that never expires.
    pub fn propose(env: &Env, proposer: Address, expiry: u64) -> u64 {
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
            expiry,
            cancelled: false,
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
    ///
    /// Panics if the proposal is expired or cancelled.
    pub fn approve(env: &Env, proposal_id: u64, signer: Address) {
        signer.require_auth();

        let config = Self::get_config(env);
        Self::assert_signer(&config, &signer);

        let mut proposal = Self::get_proposal(env, proposal_id);

        if proposal.executed {
            panic!("{:?}", MultiSigError::AlreadyExecuted);
        }

        if proposal.cancelled {
            panic!("{:?}", MultiSigError::ProposalCancelled);
        }

        if Self::proposal_is_expired(env, &proposal) {
            panic!("{:?}", MultiSigError::ProposalExpired);
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

    /// Emergency pause: authorized multisig signer sets the paused flag.
    pub fn pause(env: &Env, signer: Address) {
        signer.require_auth();
        let config = Self::get_config(env);
        Self::assert_signer(&config, &signer);
        env.storage().instance().set(&DataKey::Paused, &true);
        env.events().publish((symbol_short!("paused"),), signer);
    }

    /// Clears the paused flag after signer authorization.
    pub fn unpause(env: &Env, signer: Address) {
        signer.require_auth();
        let config = Self::get_config(env);
        Self::assert_signer(&config, &signer);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.events().publish((symbol_short!("unpaused"),), signer);
    }

    /// Returns `true` when emergency pause is active.
    pub fn is_contract_paused(env: &Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    fn is_state_inconsistent(env: &Env) -> bool {
        let Some(config) = env.storage().instance().get::<DataKey, MultiSigConfig>(&DataKey::Config)
        else {
            return false;
        };
        config.threshold == 0 || config.threshold > config.signers.len()
    }

    /// Returns whether a proposal currently satisfies the execution threshold.
    ///
    /// Returns `false` (without panicking) when the proposal is expired or
    /// cancelled, allowing callers to surface a more specific error message.
    pub fn can_execute(env: &Env, proposal_id: u64) -> bool {
        // First check if contract is in a healthy state
        if Self::is_contract_paused(env) || Self::is_state_inconsistent(env) {
            return false;
        }

        let config = Self::get_config(env);
        let proposal = Self::get_proposal(env, proposal_id);

        if proposal.executed || proposal.cancelled {
            return false;
        }

        if Self::proposal_is_expired(env, &proposal) {
            return false;
        }

        proposal.approvals.len() >= config.threshold
    }

    /// Returns whether the given proposal has passed its expiry timestamp.
    ///
    /// Always returns `false` for proposals with `expiry == 0` (no expiry).
    pub fn is_expired(env: &Env, proposal_id: u64) -> bool {
        let proposal = Self::get_proposal(env, proposal_id);
        Self::proposal_is_expired(env, &proposal)
    }

    /// Returns whether the given proposal has been explicitly cancelled.
    pub fn is_cancelled(env: &Env, proposal_id: u64) -> bool {
        let proposal = Self::get_proposal(env, proposal_id);
        proposal.cancelled
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

    /// Returns `true` when `proposal.expiry > 0` and the current ledger
    /// timestamp is at or past the expiry deadline.
    fn proposal_is_expired(env: &Env, proposal: &Proposal) -> bool {
        proposal.expiry != 0 && env.ledger().timestamp() >= proposal.expiry
    }
}
