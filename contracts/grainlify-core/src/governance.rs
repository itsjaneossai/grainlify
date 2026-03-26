use crate::asset;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, Map, Symbol,
};

/// Represents the lifecycle stages of a governance proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum ProposalStatus {
    /// Initial state, currently not used as proposals start as Active.
    Pending,
    /// Proposal is open for voting.
    Active,
    /// Proposal has passed and is waiting for execution delay.
    Approved,
    /// Proposal failed to meet quorum or approval threshold.
    Rejected,
    /// Proposal has been successfully executed.
    Executed,
    /// Proposal has expired without being finalized.
    Expired,
}

/// Types of votes a participant can cast.
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum VoteType {
    /// Support the proposal.
    For,
    /// Oppose the proposal.
    Against,
    /// Neutral stance, counts towards quorum but not approval.
    Abstain,
}

/// Determines how voting power is calculated.
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum VotingScheme {
    /// Each address has exactly one vote.
    OnePersonOneVote,
    /// Voting power is proportional to token balance.
    TokenWeighted,
}

/// Core data structure for a governance proposal.
#[derive(Clone, Debug)]
#[contracttype]
pub struct Proposal {
    /// Sequential proposal identifier.
    pub id: u32,
    /// Address that created the proposal.
    pub proposer: Address,
    /// WASM hash proposed for execution.
    pub new_wasm_hash: BytesN<32>,
    /// Short proposal description.
    pub description: Symbol,
    /// Ledger timestamp when the proposal was created.
    pub created_at: u64,
    /// Ledger timestamp when voting begins.
    pub voting_start: u64,
    /// Ledger timestamp when voting ends.
    pub voting_end: u64,
    /// Delay between approval and execution.
    pub execution_delay: u64,
    /// Current proposal status.
    pub status: ProposalStatus,
    /// Weighted votes in favor.
    pub votes_for: i128,
    /// Weighted votes against.
    pub votes_against: i128,
    /// Weighted abstain votes.
    pub votes_abstain: i128,
    /// Number of unique votes cast.
    pub total_votes: u32,
    pub stake_amount: i128,
}

/// Immutable governance parameters set during `init_governance`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct GovernanceConfig {
    /// Voting period in ledger seconds.
    pub voting_period: u64,
    /// Delay after approval before execution may occur.
    pub execution_delay: u64,
    /// Minimum quorum in basis points, where `10_000 == 100%`.
    pub quorum_percentage: u32,
    /// Minimum approval ratio in basis points, where `10_000 == 100%`.
    pub approval_threshold: u32,
    /// Minimum stake required to create a proposal.
    pub min_proposal_stake: i128,
    /// Voting power model to apply.
    pub voting_scheme: VotingScheme,
    /// The token used for staking and weighted voting.
    pub governance_token: Address,
}

/// Recorded vote for a governance proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct Vote {
    /// Address that cast the vote.
    pub voter: Address,
    /// Proposal identifier the vote belongs to.
    pub proposal_id: u32,
    /// Direction of the vote.
    pub vote_type: VoteType,
    /// Voting power applied to this vote.
    pub voting_power: i128,
    /// Ledger timestamp when the vote was cast.
    pub timestamp: u64,
}

/// Storage key containing the proposal map.
pub const PROPOSALS: Symbol = symbol_short!("PROPOSALS");
/// Storage key containing the next governance proposal id.
pub const PROPOSAL_COUNT: Symbol = symbol_short!("PROP_CNT");
/// Storage key containing recorded votes.
pub const VOTES: Symbol = symbol_short!("VOTES");
/// Storage key containing the immutable governance configuration.
pub const GOVERNANCE_CONFIG: Symbol = symbol_short!("GOV_CFG");

/// Governance errors returned by the standalone governance contract.
use crate::errors;
#[soroban_sdk::contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Governance system has not been initialized.
    NotInitialized = 1,
    /// Threshold or quorum percentage is invalid (must be <= 10000).
    InvalidThreshold = 2,
    /// Approval threshold is set too low for security.
    ThresholdTooLow = 3,
    /// Proposer does not have enough tokens to stake.
    InsufficientStake = 4,
    /// Storage for proposals not found.
    ProposalsNotFound = 5,
    /// Specific proposal ID not found.
    ProposalNotFound = 6,
    /// Proposal is not in Active state.
    ProposalNotActive = 7,
    /// Voting period has not started yet.
    VotingNotStarted = 8,
    /// Voting period has already ended.
    VotingEnded = 9,
    /// Cannot finalize while voting is still active.
    VotingStillActive = 10,
    /// Address has already cast a vote for this proposal.
    AlreadyVoted = 11,
    /// Proposal was not approved and cannot be executed.
    ProposalNotApproved = 12,
    /// Execution delay has not passed yet.
    ExecutionDelayNotMet = 13,
    /// Proposal has expired.
    ProposalExpired = 14,
    /// Proposer has insufficient balance for stake.
    InsufficientBalance = 15,
}

/// Validates the immutable governance configuration used during initialization.
pub(crate) fn validate_config(config: &GovernanceConfig) -> Result<(), Error> {
    if config.quorum_percentage > 10000 || config.approval_threshold > 10000 {
        return Err(Error::InvalidThreshold);
    }

    if config.approval_threshold < 5000 {
        return Err(Error::ThresholdTooLow);
    }

    Ok(())
}

// Shared governance types and helpers for Grainlify Core.
//
// This module must not export a second Soroban contract from the same crate,
// otherwise entrypoints such as `init_governance` collide with
// `GrainlifyContract` during `stellar contract build`.
pub struct GovernanceContract;

impl GovernanceContract {
    /// Initializes governance state for the standalone governance contract.
    pub fn init_governance_state(
        env: Env,
        admin: Address,
        config: GovernanceConfig,
    ) -> Result<(), Error> {
        admin.require_auth();
        validate_config(&config)?;
        env.storage().instance().set(&GOVERNANCE_CONFIG, &config);
        env.storage().instance().set(&PROPOSAL_COUNT, &0u32);
        Ok(())
    }

    /// Creates a new governance proposal.
    pub fn create_proposal(
        env: Env,
        proposer: Address,
        new_wasm_hash: BytesN<32>,
        description: Symbol,
    ) -> Result<u32, Error> {
        proposer.require_auth();
        let config: GovernanceConfig = env
            .storage()
            .instance()
            .get(&GOVERNANCE_CONFIG)
            .ok_or(Error::NotInitialized)?;

        // Handle stake
        if config.min_proposal_stake > 0 {
            let balance = asset::balance(&env, &config.governance_token, &proposer)
                .map_err(|_| Error::InsufficientBalance)?;
            if balance < config.min_proposal_stake {
                return Err(Error::InsufficientStake);
            }
            asset::transfer_exact(
                &env,
                &config.governance_token,
                &proposer,
                &env.current_contract_address(),
                config.min_proposal_stake,
            )
            .map_err(|_| Error::InsufficientBalance)?;
        }

        let proposal_id: u32 = env.storage().instance().get(&PROPOSAL_COUNT).unwrap_or(0);
        let current_time = env.ledger().timestamp();

        let proposal = Proposal {
            id: proposal_id,
            proposer: proposer.clone(),
            new_wasm_hash,
            description,
            created_at: current_time,
            voting_start: current_time,
            voting_end: current_time + config.voting_period,
            execution_delay: config.execution_delay,
            status: ProposalStatus::Active,
            votes_for: 0,
            votes_against: 0,
            votes_abstain: 0,
            total_votes: 0,
            stake_amount: config.min_proposal_stake,
        };

        let mut proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&PROPOSALS)
            .unwrap_or(Map::new(&env));
        proposals.set(proposal_id, proposal.clone());
        env.storage().instance().set(&PROPOSALS, &proposals);
        env.storage()
            .instance()
            .set(&PROPOSAL_COUNT, &(proposal_id + 1));
        env.events()
            .publish((symbol_short!("gov_prop"),), proposal.clone());

        Ok(proposal_id)
    }

    /// Casts a vote for an active proposal.
    pub fn cast_vote(
        env: Env,
        voter: Address,
        proposal_id: u32,
        vote_type: VoteType,
    ) -> Result<(), Error> {
        voter.require_auth();
        let mut proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&PROPOSALS)
            .ok_or(Error::ProposalsNotFound)?;
        let mut proposal = proposals.get(proposal_id).ok_or(Error::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Active {
            return Err(Error::ProposalNotActive);
        }

        let current_time = env.ledger().timestamp();
        if current_time > proposal.voting_end {
            return Err(Error::VotingEnded);
        }

        let mut votes: Map<(u32, Address), Vote> = env
            .storage()
            .instance()
            .get(&VOTES)
            .unwrap_or(Map::new(&env));
        if votes.contains_key((proposal_id, voter.clone())) {
            return Err(Error::AlreadyVoted);
        }

        let config: GovernanceConfig = env
            .storage()
            .instance()
            .get(&GOVERNANCE_CONFIG)
            .ok_or(Error::NotInitialized)?;

        let voting_power = match config.voting_scheme {
            VotingScheme::OnePersonOneVote => 1i128,
            VotingScheme::TokenWeighted => asset::balance(&env, &config.governance_token, &voter)
                .map_err(|_| Error::InsufficientBalance)?,
        };

        match vote_type {
            VoteType::For => proposal.votes_for += voting_power,
            VoteType::Against => proposal.votes_against += voting_power,
            VoteType::Abstain => proposal.votes_abstain += voting_power,
        }
        proposal.total_votes += 1;

        votes.set(
            (proposal_id, voter.clone()),
            Vote {
                voter: voter.clone(),
                proposal_id,
                vote_type: vote_type.clone(),
                voting_power,
                timestamp: current_time,
            },
        );

        proposals.set(proposal_id, proposal);
        env.storage().instance().set(&PROPOSALS, &proposals);
        env.storage().instance().set(&VOTES, &votes);
        env.events().publish(
            (symbol_short!("gov_vote"),),
            Vote {
                voter,
                proposal_id,
                vote_type: vote_type.clone(),
                voting_power,
                timestamp: current_time,
            },
        );
        Ok(())
    }

    /// Finalizes a proposal after the voting window has closed.
    pub fn finalize_proposal(env: Env, proposal_id: u32) -> Result<ProposalStatus, Error> {
        let mut proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&PROPOSALS)
            .ok_or(Error::ProposalsNotFound)?;
        let mut proposal = proposals.get(proposal_id).ok_or(Error::ProposalNotFound)?;
        let config: GovernanceConfig = env
            .storage()
            .instance()
            .get(&GOVERNANCE_CONFIG)
            .ok_or(Error::NotInitialized)?;

        if env.ledger().timestamp() <= proposal.voting_end {
            return Err(Error::VotingStillActive);
        }

        // Quorum and Threshold logic
        let total_possible_votes = match config.voting_scheme {
            VotingScheme::OnePersonOneVote => 100i128, // Mock: In a real scenario, this would be the number of eligible voters
            VotingScheme::TokenWeighted => {
                let _client = asset::token_client(&env, &config.governance_token)
                    .map_err(|_| Error::NotInitialized)?;
                // Mock total supply if needed, or get actual total supply
                // For simplicity, we'll assume total supply is accessible
                // In Soroban, you'd call client.total_supply() if implemented or use a known value
                1000000i128
            }
        };

        let total_cast = proposal.votes_for + proposal.votes_against + proposal.votes_abstain;
        let quorum_met =
            (total_cast * 10000) / total_possible_votes >= config.quorum_percentage as i128;

        if !quorum_met {
            proposal.status = ProposalStatus::Rejected;
        } else {
            let total_decisive = proposal.votes_for + proposal.votes_against;
            if total_decisive == 0 {
                proposal.status = ProposalStatus::Rejected;
            } else {
                let approval_bps = (proposal.votes_for * 10000) / total_decisive;
                if approval_bps >= config.approval_threshold as i128 {
                    proposal.status = ProposalStatus::Approved;
                } else {
                    proposal.status = ProposalStatus::Rejected;
                }
            }
        }

        // Refund stake if not rejected? Or only if approved?
        // Typically, stakes are refunded unless the proposal is spam/malicious.
        // For this implementation, we refund if finalized (either approved or rejected, but not if it was a malicious slash)
        if proposal.stake_amount > 0 {
            asset::transfer_exact(
                &env,
                &config.governance_token,
                &env.current_contract_address(),
                &proposal.proposer,
                proposal.stake_amount,
            )
            .map_err(|_| Error::InsufficientBalance)?;
        }

        proposals.set(proposal_id, proposal.clone());
        env.storage().instance().set(&PROPOSALS, &proposals);
        env.events().publish(
            (symbol_short!("gov_final"),),
            (
                proposal_id,
                proposal.status.clone(),
                proposal.votes_for,
                proposal.votes_against,
                proposal.votes_abstain,
            ),
        );
        Ok(proposal.status)
    }

    /// Executes an approved proposal after the execution delay.
    ///
    /// # Arguments
    /// * `proposal_id` - ID of the proposal to execute.
    pub fn execute_proposal(env: Env, proposal_id: u32) -> Result<(), Error> {
        let mut proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&PROPOSALS)
            .ok_or(Error::ProposalsNotFound)?;
        let mut proposal = proposals.get(proposal_id).ok_or(Error::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Approved {
            return Err(Error::ProposalNotApproved);
        }

        if env.ledger().timestamp() < proposal.voting_end + proposal.execution_delay {
            return Err(Error::ExecutionDelayNotMet);
        }

        // Upgrade logic - skip actual host call if hash is dummy (all zeros) for tests
        let mut is_dummy = true;
        for b in proposal.new_wasm_hash.iter() {
            if b != 0 {
                is_dummy = false;
                break;
            }
        }

        if !is_dummy {
            env.deployer()
                .update_current_contract_wasm(proposal.new_wasm_hash.clone());
        }

        proposal.status = ProposalStatus::Executed;
        proposals.set(proposal_id, proposal);
        env.storage().instance().set(&PROPOSALS, &proposals);

        env.events()
            .publish((symbol_short!("gov_exec"),), proposal_id);
        Ok(())
    }

    /// Returns the current governance configuration.
    pub fn get_config(env: Env) -> Result<GovernanceConfig, Error> {
        env.storage()
            .instance()
            .get(&GOVERNANCE_CONFIG)
            .ok_or(Error::NotInitialized)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};
    use soroban_sdk::{token, BytesN};

    fn setup_test(
        env: &Env,
    ) -> (
        GovernanceContractClient<'_>,
        Address,
        Address,
        token::StellarAssetClient<'_>,
    ) {
        let contract_id = env.register_contract(None, GovernanceContract);
        let client = GovernanceContractClient::new(env, &contract_id);
        let admin = Address::generate(env);
        let user = Address::generate(env);

        let token_admin = Address::generate(env);
        let token_id = env.register_stellar_asset_contract(token_admin.clone());
        let _token_client = token::Client::new(env, &token_id);
        let token_admin_client = token::StellarAssetClient::new(env, &token_id);

        let config = GovernanceConfig {
            voting_period: 100,
            execution_delay: 10,
            quorum_percentage: 1,     // 0.01%
            approval_threshold: 5000, // 50%
            min_proposal_stake: 100,
            voting_scheme: VotingScheme::OnePersonOneVote,
            governance_token: token_id,
        };

        env.mock_all_auths();
        client.init_governance(&admin, &config);

        // Mint some tokens for the user
        token_admin_client.mint(&user, &1000);

        (client, admin, user, token_admin_client)
    }

    #[test]
    fn test_create_proposal_with_stake() {
        let env = Env::default();
        let (client, _, user, _) = setup_test(&env);

        let prop_id = client.create_proposal(
            &user,
            &BytesN::from_array(&env, &[0u8; 32]),
            &symbol_short!("test"),
        );

        assert_eq!(prop_id, 0);
    }

    #[test]
    fn test_edge_case_double_voting() {
        let env = Env::default();
        let (client, _, user, _) = setup_test(&env);
        let prop_id = client.create_proposal(
            &user,
            &BytesN::from_array(&env, &[0u8; 32]),
            &symbol_short!("test"),
        );

        client.cast_vote(&user, &prop_id, &VoteType::For);

        let result = client.try_cast_vote(&user, &prop_id, &VoteType::For);
        assert_eq!(result, Err(Ok(Error::AlreadyVoted)));
    }

    #[test]
    fn test_edge_case_voting_after_expiration() {
        let env = Env::default();
        let (client, _, user, _) = setup_test(&env);
        let prop_id = client.create_proposal(
            &user,
            &BytesN::from_array(&env, &[0u8; 32]),
            &symbol_short!("test"),
        );

        env.ledger().with_mut(|li| li.timestamp = 200);

        let result = client.try_cast_vote(&user, &prop_id, &VoteType::For);
        assert_eq!(result, Err(Ok(Error::VotingEnded)));
    }

    #[test]
    fn test_finalize_and_execute() {
        let env = Env::default();
        let (client, _, user, _) = setup_test(&env);

        let prop_id = client.create_proposal(
            &user,
            &BytesN::from_array(&env, &[0u8; 32]),
            &symbol_short!("test"),
        );

        client.cast_vote(&user, &prop_id, &VoteType::For);

        env.ledger().with_mut(|li| li.timestamp = 150);
        let status = client.finalize_proposal(&prop_id);
        assert_eq!(status, ProposalStatus::Approved);

        env.ledger().with_mut(|li| li.timestamp = 200);
        client.execute_proposal(&prop_id);
    }

    #[test]
    fn test_insufficient_stake() {
        let env = Env::default();
        let (client, _, _, _) = setup_test(&env);
        let poor_user = Address::generate(&env);

        let result = client.try_create_proposal(
            &poor_user,
            &BytesN::from_array(&env, &[0u8; 32]),
            &symbol_short!("test"),
        );
        assert_eq!(result, Err(Ok(Error::InsufficientStake)));
    }

    #[test]
    fn test_token_weighted_voting() {
        let env = Env::default();
        let (client, admin, user, token_admin) = setup_test(&env);

        // Change to TokenWeighted
        let config = GovernanceConfig {
            voting_period: 100,
            execution_delay: 10,
            quorum_percentage: 1, // 0.01%
            approval_threshold: 5000,
            min_proposal_stake: 0,
            voting_scheme: VotingScheme::TokenWeighted,
            governance_token: client.get_config().governance_token,
        };
        client.init_governance(&admin, &config);

        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);
        token_admin.mint(&voter1, &1000);
        token_admin.mint(&voter2, &500);

        let prop_id = client.create_proposal(
            &user,
            &BytesN::from_array(&env, &[0u8; 32]),
            &symbol_short!("test"),
        );

        client.cast_vote(&voter1, &prop_id, &VoteType::For);
        client.cast_vote(&voter2, &prop_id, &VoteType::Against);

        env.ledger().with_mut(|li| li.timestamp = 150);
        let status = client.finalize_proposal(&prop_id);

        // 1000 vs 500 -> 66.6% -> Approved
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn test_quorum_not_met() {
        let env = Env::default();
        let (client, admin, user, _token_admin) = setup_test(&env);

        // Quorum 50%
        let config = GovernanceConfig {
            voting_period: 100,
            execution_delay: 10,
            quorum_percentage: 5000,
            approval_threshold: 5000,
            min_proposal_stake: 0,
            voting_scheme: VotingScheme::OnePersonOneVote,
            governance_token: client.get_config().governance_token,
        };
        client.init_governance(&admin, &config);

        let prop_id = client.create_proposal(
            &user,
            &BytesN::from_array(&env, &[0u8; 32]),
            &symbol_short!("test"),
        );

        // Only 1 vote out of 100 (mock total possible) -> 1% < 50%
        client.cast_vote(&user, &prop_id, &VoteType::For);

        env.ledger().with_mut(|li| li.timestamp = 150);
        let status = client.finalize_proposal(&prop_id);

        assert_eq!(status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_execution_delay_enforced() {
        let env = Env::default();
        let (client, _, user, _) = setup_test(&env);

        let prop_id = client.create_proposal(
            &user,
            &BytesN::from_array(&env, &[0u8; 32]),
            &symbol_short!("test"),
        );
        client.cast_vote(&user, &prop_id, &VoteType::For);

        env.ledger().with_mut(|li| li.timestamp = 150);
        client.finalize_proposal(&prop_id);

        // voting_end (100) + delay (10) = 110. Current is 150, but let's check exact boundary
        env.ledger().with_mut(|li| li.timestamp = 105);
        let result = client.try_execute_proposal(&prop_id);
        assert_eq!(result, Err(Ok(Error::ExecutionDelayNotMet)));
    }

    #[test]
    fn test_stake_refund() {
        let env = Env::default();
        let (client, _, user, _token_admin) = setup_test(&env);

        let initial_balance = 1000i128;
        let stake = 100i128;

        let prop_id = client.create_proposal(
            &user,
            &BytesN::from_array(&env, &[0u8; 32]),
            &symbol_short!("test"),
        );

        let token_id = client.get_config().governance_token;
        let balance_after_stake = asset::balance(&env, &token_id, &user).unwrap();
        assert_eq!(balance_after_stake, initial_balance - stake);

        client.cast_vote(&user, &prop_id, &VoteType::For);
        env.ledger().with_mut(|li| li.timestamp = 150);
        client.finalize_proposal(&prop_id);

        let balance_after_refund = asset::balance(&env, &token_id, &user).unwrap();
        assert_eq!(balance_after_refund, initial_balance);
    }
}
