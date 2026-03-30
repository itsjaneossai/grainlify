#![cfg(test)]
//! Parity tests: lock, release, refund, and edge cases (double release, double refund).
//! Behavior aligned with main contracts/bounty_escrow where applicable.

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{testutils::Events, token, Address, Env, String, Symbol, TryFromVal};

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

fn setup<'a>(
    env: &'a Env,
    initial_balance: i128,
) -> (
    EscrowContractClient<'a>,
    Address, // contract_id
    Address,
    Address,
    Address,
    token::Client<'a>,
) {
    env.mock_all_auths();
    let contract_id = env.register(EscrowContract, ());
    let client = EscrowContractClient::new(env, &contract_id);

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

fn has_event_topic(env: &Env, topic_name: &str) -> bool {
    let topic_symbol = Symbol::new(env, topic_name);
    for event in env.events().all().iter() {
        for topic in event.1.iter() {
            if let Ok(symbol) = Symbol::try_from_val(env, &topic) {
                if symbol == topic_symbol {
                    return true;
                }
            }
        }
    }
    false
}

// --- Parity: lock flow ---
#[test]
fn parity_lock_flow() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, contract_id, _admin, depositor, _contributor, token_client) = setup(&env, amount);

    let bounty_id = 1u64;
    let deadline = env.ledger().timestamp() + 1000;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    let escrow = client.get_escrow(&bounty_id);
    assert_eq!(escrow.depositor, depositor);
    assert_eq!(escrow.amount, amount);
    assert_eq!(escrow.remaining_amount, amount);
    assert_eq!(escrow.status, EscrowStatus::Locked);
    assert_eq!(token_client.balance(&contract_id), amount);
}

// --- Parity: release flow ---
#[test]
fn parity_release_flow() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, contract_id, _admin, depositor, contributor, token_client) = setup(&env, amount);

    let bounty_id = 1u64;
    let deadline = env.ledger().timestamp() + 1000;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);
    client.release_funds(&bounty_id, &contributor);

    assert_eq!(token_client.balance(&contributor), amount);
    assert_eq!(token_client.balance(&contract_id), 0);
    let escrow = client.get_escrow(&bounty_id);
    assert_eq!(escrow.status, EscrowStatus::Released);
    assert_eq!(escrow.remaining_amount, 0);
}

// --- Parity: refund flow ---
#[test]
fn parity_refund_flow() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, contract_id, _admin, depositor, _contributor, token_client) = setup(&env, amount);

    let bounty_id = 1u64;
    let deadline = env.ledger().timestamp() + 10;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    env.ledger().set_timestamp(deadline + 1);
    client.refund(&bounty_id);

    assert_eq!(token_client.balance(&depositor), amount);
    assert_eq!(token_client.balance(&contract_id), 0);
    let escrow = client.get_escrow(&bounty_id);
    assert_eq!(escrow.status, EscrowStatus::Refunded);
    assert_eq!(escrow.remaining_amount, 0);
}

// --- Edge case: double release (must fail) ---
#[test]
fn parity_double_release_fails() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _cid, _admin, depositor, contributor, _token_client) = setup(&env, amount);

    let bounty_id = 1u64;
    let deadline = env.ledger().timestamp() + 1000;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);
    client.release_funds(&bounty_id, &contributor);

    let res = client.try_release_funds(&bounty_id, &contributor);
    assert!(res.is_err());
}

// --- Edge case: double refund (must fail) ---
#[test]
fn parity_double_refund_fails() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _cid, _admin, depositor, _contributor, _token_client) = setup(&env, amount);

    let bounty_id = 1u64;
    let deadline = env.ledger().timestamp() + 10;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);
    env.ledger().set_timestamp(deadline + 1);
    client.refund(&bounty_id);

    let res = client.try_refund(&bounty_id);
    assert!(res.is_err());
}

// --- Refund before deadline fails ---
#[test]
fn parity_refund_before_deadline_fails() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _cid, _admin, depositor, _contributor, _token_client) = setup(&env, amount);

    let bounty_id = 1u64;
    let deadline = env.ledger().timestamp() + 1000;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    let res = client.try_refund(&bounty_id);
    assert!(res.is_err());
}

#[test]
fn test_generic_escrow_still_enforces_identity_limits() {
    let env = Env::default();
    let amount = 2_000_0000000i128; // above default unverified limit
    let (client, _cid, _admin, depositor, _contributor, _token_client) = setup(&env, amount);

    let bounty_id = 52u64;
    let deadline = env.ledger().timestamp() + 1000;
    let res = client.try_lock_funds(&depositor, &bounty_id, &amount, &deadline);
    assert!(res.is_err());
}

#[test]
fn test_jurisdiction_lock_pause_blocks_new_locks() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _cid, _admin, depositor, _contributor, _token_client) = setup(&env, amount);

    let bounty_id = 53u64;
    let deadline = env.ledger().timestamp() + 1000;
    let cfg = EscrowJurisdictionConfig {
        tag: Some(String::from_str(&env, "EU-only")),
        requires_kyc: false,
        enforce_identity_limits: true,
        lock_paused: true,
        release_paused: false,
        refund_paused: false,
        max_lock_amount: Some(20_000),
    };

    let res = client.try_lock_funds_with_jurisdiction(
        &depositor,
        &bounty_id,
        &amount,
        &deadline,
        &OptionalJurisdiction::Some(cfg),
    );
    assert!(res.is_err());
}

#[test]
fn test_jurisdiction_events_emitted() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _cid, _admin, depositor, contributor, _token_client) = setup(&env, amount);

    let bounty_id = 54u64;
    let deadline = env.ledger().timestamp() + 1000;
    let cfg = EscrowJurisdictionConfig {
        tag: Some(String::from_str(&env, "pilot-zone")),
        requires_kyc: false,
        enforce_identity_limits: false,
        lock_paused: false,
        release_paused: false,
        refund_paused: false,
        max_lock_amount: Some(100_000),
    };

    client.lock_funds_with_jurisdiction(
        &depositor,
        &bounty_id,
        &amount,
        &deadline,
        &OptionalJurisdiction::Some(cfg),
    );
    client.release_funds(&bounty_id, &contributor);

    assert!(has_event_topic(&env, "juris"));
}

// --- Parity: Jurisdiction Release Paused Fails ---
#[test]
fn parity_jurisdiction_release_paused_fails() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _cid, _admin, depositor, contributor, _token_client) = setup(&env, amount);

    let bounty_id = 100u64;
    let deadline = env.ledger().timestamp() + 1000;

    let cfg = EscrowJurisdictionConfig {
        tag: Some(String::from_str(&env, "paused-release")),
        requires_kyc: false,
        enforce_identity_limits: false,
        lock_paused: false,
        release_paused: true, // PAUSED
        refund_paused: false,
        max_lock_amount: None,
    };

    client.lock_funds_with_jurisdiction(
        &depositor,
        &bounty_id,
        &amount,
        &deadline,
        &OptionalJurisdiction::Some(cfg),
    );

    let res = client.try_release_funds(&bounty_id, &contributor);
    assert!(res.is_err());
}

// --- Parity: Jurisdiction Refund Paused Fails ---
#[test]
fn parity_jurisdiction_refund_paused_fails() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _cid, _admin, depositor, _contributor, _token_client) = setup(&env, amount);

    let bounty_id = 101u64;
    let deadline = env.ledger().timestamp() + 10;

    let cfg = EscrowJurisdictionConfig {
        tag: Some(String::from_str(&env, "paused-refund")),
        requires_kyc: false,
        enforce_identity_limits: false,
        lock_paused: false,
        release_paused: false,
        refund_paused: true, // PAUSED
        max_lock_amount: None,
    };

    client.lock_funds_with_jurisdiction(
        &depositor,
        &bounty_id,
        &amount,
        &deadline,
        &OptionalJurisdiction::Some(cfg),
    );

    env.ledger().set_timestamp(deadline + 1);
    let res = client.try_refund(&bounty_id);
    assert!(res.is_err());
}

// --- Refund Failure Snapshots: Comprehensive Edge Case Coverage ---

/// Refund on nonexistent bounty fails with BountyNotFound error
#[test]
fn parity_refund_nonexistent_bounty_fails() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _cid, _admin, _depositor, _contributor, _token_client) = setup(&env, amount);

    let nonexistent_bounty_id = 9999u64;
    let res = client.try_refund(&nonexistent_bounty_id);
    assert!(res.is_err());
}

/// Refund after release fails (escrow no longer locked)
#[test]
fn parity_refund_after_release_fails() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _cid, _admin, depositor, contributor, _token_client) = setup(&env, amount);

    let bounty_id = 102u64;
    let deadline = env.ledger().timestamp() + 100;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    // Release first
    client.release_funds(&bounty_id, &contributor);

    // Advance past deadline and try to refund
    env.ledger().set_timestamp(deadline + 1);
    let res = client.try_refund(&bounty_id);
    assert!(res.is_err());
}

/// Refund at exact deadline timestamp (boundary condition) - SHOULD SUCCEED
#[test]
fn parity_refund_at_exact_deadline_fails() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _cid, _admin, depositor, _contributor, _token_client) = setup(&env, amount);

    let bounty_id = 105u64;
    let deadline = env.ledger().timestamp() + 1000;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    // Set timestamp to exactly deadline (should SUCCEED - allows >= deadline)
    env.ledger().set_timestamp(deadline);
    // This refund SHOULD succeed because deadline enforcement is now >= deadline
    client.refund(&bounty_id);
}

/// Refund one block after deadline succeeds
#[test]
fn parity_refund_one_block_after_deadline_succeeds() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, contract_id, _admin, depositor, _contributor, token_client) = setup(&env, amount);

    let bounty_id = 106u64;
    let deadline = env.ledger().timestamp() + 1000;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    // Set timestamp to exactly deadline + 1
    env.ledger().set_timestamp(deadline + 1);
    client.refund(&bounty_id);

    // Verify funds returned
    assert_eq!(token_client.balance(&depositor), amount);
    assert_eq!(token_client.balance(&contract_id), 0);
    let escrow = client.get_escrow(&bounty_id);
    assert_eq!(escrow.status, EscrowStatus::Refunded);
}

/// Symmetric test: verify release + refund mutual exclusivity on state
#[test]
fn parity_release_vs_refund_mutual_exclusion() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _cid, _admin, depositor, contributor, _token_client) = setup(&env, amount);

    let bounty_id = 108u64;
    let deadline = env.ledger().timestamp() + 10;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    // Release as success path
    client.release_funds(&bounty_id, &contributor);

    // Verify escrow is Released
    let escrow_after_release = client.get_escrow(&bounty_id);
    assert_eq!(escrow_after_release.status, EscrowStatus::Released);

    // Refund must fail (already released)
    env.ledger().set_timestamp(deadline + 1);
    let refund_res = client.try_refund(&bounty_id);
    assert!(refund_res.is_err());
}

/// Triple-refund attempt fails (idempotency check)
#[test]
fn parity_triple_refund_fails() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _cid, _admin, depositor, _contributor, _token_client) = setup(&env, amount);

    let bounty_id = 109u64;
    let deadline = env.ledger().timestamp() + 10;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    env.ledger().set_timestamp(deadline + 1);
    // First refund succeeds
    client.refund(&bounty_id);

    // Second refund fails
    let res2 = client.try_refund(&bounty_id);
    assert!(res2.is_err());

    // Third refund fails too
    let res3 = client.try_refund(&bounty_id);
    assert!(res3.is_err());
}

/// Refund attempts at multiple time points (deadline progression)
#[test]
fn parity_refund_timing_progression() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _cid, _admin, depositor, _contributor, _token_client) = setup(&env, amount);

    let bounty_id = 110u64;
    let deadline = env.ledger().timestamp() + 100;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    // Before deadline: must fail
    env.ledger().set_timestamp(deadline - 1);
    let res_before = client.try_refund(&bounty_id);
    assert!(res_before.is_err());

    // At deadline: SHOULD SUCCEED (>= deadline check)
    env.ledger().set_timestamp(deadline);
    client.refund(&bounty_id);

    // Verify state is now Refunded
    let escrow = client.get_escrow(&bounty_id);
    assert_eq!(escrow.status, EscrowStatus::Refunded);
}
