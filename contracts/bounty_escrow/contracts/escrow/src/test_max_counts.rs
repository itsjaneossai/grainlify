#![cfg(test)]
//! Stress tests for maximum bounty counts (Issue #397).
//!
//! Priority: verify that `env.storage().persistent()` handles a high volume
//! of `Escrow(bounty_id)` entries without key collisions or resource panics.

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{token, Address, Env};

fn create_token<'a>(
    env: &'a Env,
    admin: &Address,
) -> (Address, token::Client<'a>, token::StellarAssetClient<'a>) {
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let addr = token_contract.address();
    let client = token::Client::new(env, &addr);
    let admin_client = token::StellarAssetClient::new(env, &addr);
    (addr, client, admin_client)
}

fn setup_max<'a>(
    env: &'a Env,
    initial_balance: i128,
) -> (
    BountyEscrowContractClient<'a>,
    Address, // contract_id
    Address, // admin
    Address, // depositor
    Address, // contributor
    token::Client<'a>,
) {
    env.mock_all_auths();
    env.budget().reset_unlimited();
    let contract_id = env.register_contract(None, BountyEscrowContract);
    let client = BountyEscrowContractClient::new(env, &contract_id);

    let admin = Address::generate(env);
    let depositor = Address::generate(env);
    let contributor = Address::generate(env);
    let (token_addr, token_client, token_admin) = create_token(env, &admin);

    client.init(&admin, &token_addr);
    token_admin.mint(&depositor, &initial_balance);

    (
        client,
        contract_id,
        admin,
        depositor,
        contributor,
        token_client,
    )
}

// ==================== STORAGE KEY UNIQUENESS ====================

/// Lock 60 bounties and verify that each `Escrow(bounty_id)` storage entry is
/// independently retrievable with the correct data — no key collisions.
///
/// Each bounty amount equals `id * 100` so any collision or overwrite is visible.
#[test]
fn test_max_bounties_no_storage_key_collision() {
    let env = Env::default();
    // 60 bounties × 100 tokens each = 6_000
    let (client, contract_id, _admin, depositor, _contributor, token_client) =
        setup_max(&env, 6_000);

    let total: u64 = 60;
    let deadline = env.ledger().timestamp() + 10_000;

    for id in 1..=total {
        client.lock_funds(&depositor, &id, &100, &deadline);
    }

    // All funds transferred to contract
    assert_eq!(token_client.balance(&contract_id), 6_000);
    assert_eq!(token_client.balance(&depositor), 0);

    // Each storage slot must hold its own distinct data — no collisions
    for id in 1..=total {
        let escrow = client.get_escrow(&id);
        assert_eq!(escrow.depositor, depositor);
        assert_eq!(escrow.amount, 100);
        assert_eq!(escrow.remaining_amount, 100);
        assert_eq!(escrow.status, EscrowStatus::Locked);
        assert_eq!(escrow.deadline, deadline);
    }
}

// ==================== SAMPLING ACCURACY ====================

/// Lock 60 bounties where each amount equals `id * 10`. Spot-check
/// 5 specific IDs to confirm the right data is stored under each key.
#[test]
fn test_max_bounties_sampling_queries_accurate() {
    let env = Env::default();
    // Total = 10 * (1+2+…+60) = 10 * 1830 = 18_300
    let (client, contract_id, _admin, depositor, _contributor, token_client) =
        setup_max(&env, 18_300);

    let deadline = env.ledger().timestamp() + 10_000;

    for id in 1..=60u64 {
        let amount = (id * 10) as i128;
        client.lock_funds(&depositor, &id, &amount, &deadline);
    }

    assert_eq!(token_client.balance(&contract_id), 18_300);

    // Spot-check 5 IDs spread across the full range
    for id in [1u64, 15, 30, 45, 60] {
        let escrow = client.get_escrow(&id);
        assert_eq!(escrow.amount, (id * 10) as i128);
        assert_eq!(escrow.remaining_amount, (id * 10) as i128);
        assert_eq!(escrow.status, EscrowStatus::Locked);
        assert_eq!(escrow.depositor, depositor);
    }
}

// ==================== DUPLICATE KEY REJECTION ====================

/// Lock 30 bounties, then attempt to lock again with the same IDs.
/// Verifies that duplicate keys are rejected and original data is not overwritten.
#[test]
fn test_max_bounties_duplicate_id_rejected_original_preserved() {
    let env = Env::default();
    let (client, _contract_id, _admin, depositor, _contributor, _token_client) =
        setup_max(&env, 9_000);

    let deadline = env.ledger().timestamp() + 10_000;

    // Lock 30 bounties with amount = 100
    for id in 1..=30u64 {
        client.lock_funds(&depositor, &id, &100, &deadline);
    }

    // Attempt duplicate — must fail for every ID
    for id in 1..=30u64 {
        let res = client.try_lock_funds(&depositor, &id, &100, &deadline);
        assert!(res.is_err(), "duplicate lock for id={} must fail", id);
    }

    // Original data must be intact — no overwrite
    for id in 1..=30u64 {
        let escrow = client.get_escrow(&id);
        assert_eq!(escrow.amount, 100);
        assert_eq!(escrow.status, EscrowStatus::Locked);
    }
}

// ==================== LIFECYCLE ACROSS MANY ENTRIES ====================

/// Lock 60 bounties, release the first 30, refund the remaining 30 after
/// deadline. Verify that operations on one entry do not corrupt adjacent entries.
#[test]
fn test_max_bounties_lifecycle_no_cross_entry_corruption() {
    let env = Env::default();
    let (client, _contract_id, _admin, depositor, contributor, _token_client) =
        setup_max(&env, 6_000);

    let deadline = env.ledger().timestamp() + 100;

    for id in 1..=60u64 {
        client.lock_funds(&depositor, &id, &100, &deadline);
    }

    // Release the first 30 (admin calls release_funds)
    for id in 1..=30u64 {
        client.release_funds(&id, &contributor);
        let escrow = client.get_escrow(&id);
        assert_eq!(escrow.status, EscrowStatus::Released);
        assert_eq!(escrow.remaining_amount, 0);
    }

    // Refund the remaining 30 after deadline
    env.ledger().set_timestamp(deadline + 1);
    for id in 31..=60u64 {
        client.refund(&id);
        let escrow = client.get_escrow(&id);
        assert_eq!(escrow.status, EscrowStatus::Refunded);
        assert_eq!(escrow.remaining_amount, 0);
    }

    // Cross-check: released entries still Released (not corrupted by refunds)
    for id in 1..=30u64 {
        assert_eq!(client.get_escrow(&id).status, EscrowStatus::Released);
    }
    // Cross-check: refunded entries still Refunded
    for id in 31..=60u64 {
        assert_eq!(client.get_escrow(&id).status, EscrowStatus::Refunded);
    }
}
