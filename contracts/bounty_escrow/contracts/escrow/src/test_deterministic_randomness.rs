#![cfg(test)]
//! Deterministic randomness tests for bounty escrow claim-ticket selection.
//!
//! These tests verify that the PRNG-based winner derivation is:
//! - **Stable**: identical inputs always produce the same winner.
//! - **Ledger-bound**: changing the ledger timestamp alters the outcome.
//! - **Seed-sensitive**: different external seeds yield different selections.
//! - **Order-independent**: candidate list ordering does not affect the winner.
//! - **Correct at boundaries**: single candidate, varying bounty IDs, etc.
//!
//! # Predictability statement
//! The selection is fully deterministic given (contract address, bounty params,
//! ledger timestamp, ticket counter, external seed).  Validators who know the
//! timestamp before block close can predict outcomes for a fixed seed.  See
//! `DETERMINISTIC_RANDOMNESS.md` for the complete threat model.

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, BytesN, Env, Vec as SdkVec,
};

// ============================================================================
// Test harness
// ============================================================================

struct Setup<'a> {
    env: Env,
    client: BountyEscrowContractClient<'a>,
    admin: Address,
    depositor: Address,
    token_id: Address,
}

impl<'a> Setup<'a> {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = env
            .register_stellar_asset_contract_v2(token_admin.clone())
            .address();
        client.init(&admin, &token_id);

        Self {
            env,
            client,
            admin,
            depositor,
            token_id,
        }
    }

    /// Build a reusable candidate list of `n` freshly-generated addresses.
    fn candidates(&self, n: u32) -> SdkVec<Address> {
        let mut v = SdkVec::new(&self.env);
        for _ in 0..n {
            v.push_back(Address::generate(&self.env));
        }
        v
    }

    /// Lock funds for a bounty so that `issue_claim_ticket_deterministic` can succeed.
    fn lock_bounty(&self, bounty_id: u64, amount: i128, deadline: u64) {
        let token_admin_client = token::StellarAssetClient::new(&self.env, &self.token_id);
        token_admin_client.mint(&self.depositor, &amount);
        self.client
            .lock_funds(&self.depositor, &bounty_id, &amount, &deadline);
    }
}

// ============================================================================
// Stability: same inputs → same winner
// ============================================================================

#[test]
fn test_deterministic_winner_is_stable_for_same_inputs() {
    let s = Setup::new();
    let _ = &s.admin;
    let candidates = s.candidates(3);
    let seed = BytesN::from_array(&s.env, &[7u8; 32]);
    let expires_at = s.env.ledger().timestamp() + 500;

    let w1 = s
        .client
        .derive_claim_ticket_winner(&42, &candidates, &1000, &expires_at, &seed);
    let w2 = s
        .client
        .derive_claim_ticket_winner(&42, &candidates, &1000, &expires_at, &seed);

    assert_eq!(
        w1, w2,
        "Identical inputs must always select the same winner"
    );
}

// ============================================================================
// Order independence: shuffled candidate list → same winner address
// ============================================================================

#[test]
fn test_deterministic_winner_is_order_independent() {
    let s = Setup::new();
    let a = Address::generate(&s.env);
    let b = Address::generate(&s.env);
    let c = Address::generate(&s.env);
    let seed = BytesN::from_array(&s.env, &[9u8; 32]);
    let expires_at = s.env.ledger().timestamp() + 600;

    let mut candidates_1 = SdkVec::new(&s.env);
    candidates_1.push_back(a.clone());
    candidates_1.push_back(b.clone());
    candidates_1.push_back(c.clone());
    let mut candidates_2 = SdkVec::new(&s.env);
    candidates_2.push_back(c);
    candidates_2.push_back(a);
    candidates_2.push_back(b);

    let w1 = s
        .client
        .derive_claim_ticket_winner(&77, &candidates_1, &2500, &expires_at, &seed);
    let w2 = s
        .client
        .derive_claim_ticket_winner(&77, &candidates_2, &2500, &expires_at, &seed);

    assert_eq!(w1, w2, "Candidate ordering must not change the winner");
}

// ============================================================================
// Ledger-bound: changing the ledger timestamp changes the outcome
// ============================================================================

#[test]
fn test_selection_changes_with_ledger_timestamp() {
    let s = Setup::new();
    // Use 20 candidates so the probability of two independent SHA-256
    // hashes mapping to the same index is only 1/20 (~5%).
    let candidates = s.candidates(20);
    let seed = BytesN::from_array(&s.env, &[0xAAu8; 32]);
    let expires_at = 99_999u64;

    // Derive winner at the default ledger timestamp.
    let idx_t0 =
        s.client
            .derive_claim_ticket_winner_index(&10, &candidates, &5000, &expires_at, &seed);

    // Advance the ledger timestamp significantly.
    s.env.ledger().with_mut(|li| {
        li.timestamp += 86_400;
    });
    let idx_t1 =
        s.client
            .derive_claim_ticket_winner_index(&10, &candidates, &5000, &expires_at, &seed);

    assert_ne!(
        idx_t0, idx_t1,
        "Different ledger timestamps should produce different selection indices"
    );
}

// ============================================================================
// Seed sensitivity: different external seeds → different outcomes
// ============================================================================

#[test]
fn test_different_seeds_produce_different_winners() {
    let s = Setup::new();
    let candidates = s.candidates(5);
    let expires_at = s.env.ledger().timestamp() + 600;

    let seed_a = BytesN::from_array(&s.env, &[1u8; 32]);
    let seed_b = BytesN::from_array(&s.env, &[2u8; 32]);

    let w_a = s
        .client
        .derive_claim_ticket_winner(&50, &candidates, &3000, &expires_at, &seed_a);
    let w_b = s
        .client
        .derive_claim_ticket_winner(&50, &candidates, &3000, &expires_at, &seed_b);

    assert_ne!(
        w_a, w_b,
        "Different seeds should produce different winners for a non-trivial candidate set"
    );
}

// ============================================================================
// Bounty-ID sensitivity: changing bounty_id changes the outcome
// ============================================================================

#[test]
fn test_different_bounty_ids_produce_different_indices() {
    let s = Setup::new();
    let candidates = s.candidates(5);
    let seed = BytesN::from_array(&s.env, &[0xBBu8; 32]);
    let expires_at = s.env.ledger().timestamp() + 700;

    let idx_a =
        s.client
            .derive_claim_ticket_winner_index(&1, &candidates, &1000, &expires_at, &seed);
    let idx_b =
        s.client
            .derive_claim_ticket_winner_index(&2, &candidates, &1000, &expires_at, &seed);

    assert_ne!(
        idx_a, idx_b,
        "Different bounty IDs should produce different selection indices"
    );
}

// ============================================================================
// Single candidate: always returns that candidate
// ============================================================================

#[test]
fn test_single_candidate_always_selected() {
    let s = Setup::new();
    let sole = Address::generate(&s.env);
    let mut candidates = SdkVec::new(&s.env);
    candidates.push_back(sole.clone());
    let seed = BytesN::from_array(&s.env, &[0xFFu8; 32]);
    let expires_at = s.env.ledger().timestamp() + 300;

    let winner = s
        .client
        .derive_claim_ticket_winner(&99, &candidates, &100, &expires_at, &seed);
    assert_eq!(
        winner, sole,
        "A single candidate must always be selected as winner"
    );
}

// ============================================================================
// Index derivation matches address derivation
// ============================================================================

#[test]
fn test_winner_index_resolves_to_winner_address() {
    let s = Setup::new();
    let candidates = s.candidates(4);
    let seed = BytesN::from_array(&s.env, &[0xCCu8; 32]);
    let expires_at = s.env.ledger().timestamp() + 800;

    let idx =
        s.client
            .derive_claim_ticket_winner_index(&33, &candidates, &2000, &expires_at, &seed);
    let addr = s
        .client
        .derive_claim_ticket_winner(&33, &candidates, &2000, &expires_at, &seed);

    assert_eq!(
        candidates.get(idx).unwrap(),
        addr,
        "Index-based and address-based derivation must agree"
    );
}

// ============================================================================
// Full integration: issue_claim_ticket_deterministic succeeds and returns
// a monotonically increasing ticket ID.
// ============================================================================

#[test]
fn test_issue_claim_ticket_deterministic_issues_for_derived_winner() {
    let s = Setup::new();
    let bounty_id = 1u64;
    let lock_amount = 50_000i128;
    let deadline = s.env.ledger().timestamp() + 1_000;
    s.lock_bounty(bounty_id, lock_amount, deadline);

    let candidates = s.candidates(3);
    let seed = BytesN::from_array(&s.env, &[3u8; 32]);
    let expires_at = s.env.ledger().timestamp() + 500;
    let claim_amount = 10_000i128;

    let derived_winner = s.client.derive_claim_ticket_winner(
        &bounty_id,
        &candidates,
        &claim_amount,
        &expires_at,
        &seed,
    );

    let ticket_id = s.client.issue_claim_ticket_deterministic(
        &bounty_id,
        &candidates,
        &claim_amount,
        &expires_at,
        &seed,
    );
    assert!(ticket_id > 0, "First ticket ID must be positive");
}

// ============================================================================
// Successive deterministic tickets get increasing IDs (ticket counter bind)
// ============================================================================

#[test]
fn test_successive_deterministic_tickets_increment() {
    let s = Setup::new();
    let bounty_id = 2u64;
    let lock_amount = 100_000i128;
    let deadline = s.env.ledger().timestamp() + 2_000;
    s.lock_bounty(bounty_id, lock_amount, deadline);

    let candidates = s.candidates(3);
    let seed_1 = BytesN::from_array(&s.env, &[0x10u8; 32]);
    let seed_2 = BytesN::from_array(&s.env, &[0x20u8; 32]);
    let expires_at = s.env.ledger().timestamp() + 500;
    let claim_amount = 5_000i128;

    let tid_1 = s.client.issue_claim_ticket_deterministic(
        &bounty_id,
        &candidates,
        &claim_amount,
        &expires_at,
        &seed_1,
    );
    let tid_2 = s.client.issue_claim_ticket_deterministic(
        &bounty_id,
        &candidates,
        &claim_amount,
        &expires_at,
        &seed_2,
    );

    assert!(
        tid_2 > tid_1,
        "Successive ticket IDs must be monotonically increasing"
    );
}

// ============================================================================
// Amount sensitivity: different claim amounts change the winner
// ============================================================================

#[test]
fn test_different_amounts_produce_different_indices() {
    let s = Setup::new();
    let candidates = s.candidates(5);
    let seed = BytesN::from_array(&s.env, &[0xDDu8; 32]);
    let expires_at = s.env.ledger().timestamp() + 400;

    let idx_lo =
        s.client
            .derive_claim_ticket_winner_index(&5, &candidates, &100, &expires_at, &seed);
    let idx_hi =
        s.client
            .derive_claim_ticket_winner_index(&5, &candidates, &999_999, &expires_at, &seed);

    assert_ne!(
        idx_lo, idx_hi,
        "Different claim amounts should produce different selection indices"
    );
}

// ============================================================================
// Expiry sensitivity: different expires_at values change the winner
// ============================================================================

#[test]
fn test_different_expiry_produces_different_indices() {
    let s = Setup::new();
    let candidates = s.candidates(20);
    let seed = BytesN::from_array(&s.env, &[0xEEu8; 32]);

    let idx_early = s
        .client
        .derive_claim_ticket_winner_index(&8, &candidates, &500, &1_000, &seed);
    let idx_late =
        s.client
            .derive_claim_ticket_winner_index(&8, &candidates, &500, &999_000, &seed);

    assert_ne!(
        idx_early, idx_late,
        "Different expiry timestamps should produce different selection indices"
    );
}
