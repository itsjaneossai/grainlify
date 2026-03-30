//! # Recurring (Subscription) Lock Tests
//!
//! Validates period boundaries, cap enforcement, cancellation, and end conditions
//! for the recurring lock feature.
#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, Env,
};

fn create_token_contract<'a>(
    e: &Env,
    admin: &Address,
) -> (token::Client<'a>, token::StellarAssetClient<'a>) {
    let contract_address = e
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    (
        token::Client::new(e, &contract_address),
        token::StellarAssetClient::new(e, &contract_address),
    )
}

fn create_escrow_contract<'a>(e: &Env) -> BountyEscrowContractClient<'a> {
    let contract_id = e.register_contract(None, BountyEscrowContract);
    BountyEscrowContractClient::new(e, &contract_id)
}

/// Helper: set up a fully initialized contract with a funded depositor.
fn setup(
    initial_balance: i128,
) -> (
    Env,
    BountyEscrowContractClient<'static>,
    token::Client<'static>,
    Address,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);

    let (token_client, token_admin) = create_token_contract(&env, &admin);
    let escrow_client = create_escrow_contract(&env);

    escrow_client.init(&admin, &token_client.address);
    token_admin.mint(&depositor, &initial_balance);

    // Leak lifetimes for test convenience (safe in tests)
    let token_client: token::Client<'static> = unsafe { core::mem::transmute(token_client) };
    let escrow_client: BountyEscrowContractClient<'static> =
        unsafe { core::mem::transmute(escrow_client) };

    (env, escrow_client, token_client, admin, depositor)
}

// ─── Creation ────────────────────────────────────────────────────────────────

#[test]
fn test_create_recurring_lock_success() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let recurring_id = client.create_recurring_lock(
        &depositor,
        &1u64,                                  // bounty_id
        &1000i128,                              // amount_per_period
        &3600u64,                               // period: 1 hour
        &RecurringEndCondition::MaxTotal(5000), // cap at 5000
        &(env.ledger().timestamp() + 86400),    // escrow_deadline
    );

    assert_eq!(recurring_id, 1);

    let (config, state) = client.get_recurring_lock(&recurring_id);
    assert_eq!(config.bounty_id, 1);
    assert_eq!(config.amount_per_period, 1000);
    assert_eq!(config.period, 3600);
    assert_eq!(state.cumulative_locked, 0);
    assert_eq!(state.execution_count, 0);
    assert!(!state.cancelled);
}

#[test]
fn test_create_recurring_lock_invalid_zero_amount() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let result = client.try_create_recurring_lock(
        &depositor,
        &1u64,
        &0i128, // invalid
        &3600u64,
        &RecurringEndCondition::MaxTotal(5000),
        &(env.ledger().timestamp() + 86400),
    );

    assert!(result.is_err());
}

#[test]
fn test_create_recurring_lock_invalid_short_period() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let result = client.try_create_recurring_lock(
        &depositor,
        &1u64,
        &1000i128,
        &30u64, // too short, minimum 60s
        &RecurringEndCondition::MaxTotal(5000),
        &(env.ledger().timestamp() + 86400),
    );

    assert!(result.is_err());
}

#[test]
fn test_create_recurring_lock_invalid_zero_cap() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let result = client.try_create_recurring_lock(
        &depositor,
        &1u64,
        &1000i128,
        &3600u64,
        &RecurringEndCondition::MaxTotal(0), // invalid
        &(env.ledger().timestamp() + 86400),
    );

    assert!(result.is_err());
}

#[test]
fn test_create_recurring_lock_invalid_past_end_time() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let result = client.try_create_recurring_lock(
        &depositor,
        &1u64,
        &1000i128,
        &3600u64,
        &RecurringEndCondition::EndTime(0), // in the past
        &(env.ledger().timestamp() + 86400),
    );

    assert!(result.is_err());
}

// ─── Execution & Period Boundaries ───────────────────────────────────────────

#[test]
fn test_execute_recurring_lock_period_not_elapsed() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let recurring_id = client.create_recurring_lock(
        &depositor,
        &1u64,
        &1000i128,
        &3600u64,
        &RecurringEndCondition::MaxTotal(10_000),
        &(env.ledger().timestamp() + 86400),
    );

    // Try to execute immediately (period not elapsed)
    let result = client.try_execute_recurring_lock(&recurring_id);
    assert!(result.is_err());
}

#[test]
fn test_execute_recurring_lock_after_period() {
    let (env, client, token, _admin, depositor) = setup(100_000);

    let deadline = env.ledger().timestamp() + 86400;
    let recurring_id = client.create_recurring_lock(
        &depositor,
        &1u64,
        &1000i128,
        &3600u64,
        &RecurringEndCondition::MaxTotal(10_000),
        &deadline,
    );

    // Advance time past the period
    env.ledger().set_timestamp(env.ledger().timestamp() + 3601);

    client.execute_recurring_lock(&recurring_id);

    let (_config, state) = client.get_recurring_lock(&recurring_id);
    assert_eq!(state.execution_count, 1);
    assert_eq!(state.cumulative_locked, 1000);

    // Verify tokens were transferred
    assert_eq!(token.balance(&depositor), 99_000);
}

#[test]
fn test_execute_multiple_periods() {
    let (env, client, token, _admin, depositor) = setup(100_000);

    let start = env.ledger().timestamp();
    let deadline = start + 86400;
    let recurring_id = client.create_recurring_lock(
        &depositor,
        &1u64,
        &1000i128,
        &3600u64,
        &RecurringEndCondition::MaxTotal(10_000),
        &deadline,
    );

    // Execute 3 periods
    for i in 1..=3u64 {
        env.ledger().set_timestamp(start + 3600 * i + 1);
        client.execute_recurring_lock(&recurring_id);

        let (_config, state) = client.get_recurring_lock(&recurring_id);
        assert_eq!(state.execution_count, i as u32);
        assert_eq!(state.cumulative_locked, 1000 * i as i128);
    }

    assert_eq!(token.balance(&depositor), 97_000);
}

#[test]
fn test_cannot_execute_twice_in_same_period() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let start = env.ledger().timestamp();
    let recurring_id = client.create_recurring_lock(
        &depositor,
        &1u64,
        &1000i128,
        &3600u64,
        &RecurringEndCondition::MaxTotal(10_000),
        &(start + 86400),
    );

    env.ledger().set_timestamp(start + 3601);
    client.execute_recurring_lock(&recurring_id);

    // Try executing again without advancing time enough
    let result = client.try_execute_recurring_lock(&recurring_id);
    assert!(result.is_err());
}

// ─── Cap Enforcement ─────────────────────────────────────────────────────────

#[test]
fn test_cap_enforcement_max_total() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let start = env.ledger().timestamp();
    let recurring_id = client.create_recurring_lock(
        &depositor,
        &1u64,
        &1000i128,
        &60u64,
        &RecurringEndCondition::MaxTotal(2500), // cap at 2500
        &(start + 86400),
    );

    // First two executions should succeed (total: 2000)
    env.ledger().set_timestamp(start + 61);
    client.execute_recurring_lock(&recurring_id);

    env.ledger().set_timestamp(start + 122);
    client.execute_recurring_lock(&recurring_id);

    let (_config, state) = client.get_recurring_lock(&recurring_id);
    assert_eq!(state.cumulative_locked, 2000);

    // Third execution would push to 3000, exceeding cap of 2500
    env.ledger().set_timestamp(start + 183);
    let result = client.try_execute_recurring_lock(&recurring_id);
    assert!(result.is_err());
}

#[test]
fn test_end_time_enforcement() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let start = env.ledger().timestamp();
    let end_time = start + 7200; // 2 hours
    let recurring_id = client.create_recurring_lock(
        &depositor,
        &1u64,
        &1000i128,
        &3600u64,
        &RecurringEndCondition::EndTime(end_time),
        &(start + 86400),
    );

    // First execution at 1h should succeed
    env.ledger().set_timestamp(start + 3601);
    client.execute_recurring_lock(&recurring_id);

    // Second execution at 3h (past end_time) should fail
    env.ledger().set_timestamp(start + 10800);
    let result = client.try_execute_recurring_lock(&recurring_id);
    assert!(result.is_err());
}

#[test]
fn test_both_end_condition_cap_triggers_first() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let start = env.ledger().timestamp();
    let recurring_id = client.create_recurring_lock(
        &depositor,
        &1u64,
        &1000i128,
        &60u64,
        &RecurringEndCondition::Both(1500, start + 86400), // cap hits first
        &(start + 86400),
    );

    env.ledger().set_timestamp(start + 61);
    client.execute_recurring_lock(&recurring_id);

    // Second would push to 2000, exceeding cap of 1500
    env.ledger().set_timestamp(start + 122);
    let result = client.try_execute_recurring_lock(&recurring_id);
    assert!(result.is_err());
}

#[test]
fn test_both_end_condition_time_triggers_first() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let start = env.ledger().timestamp();
    let recurring_id = client.create_recurring_lock(
        &depositor,
        &1u64,
        &1000i128,
        &3600u64,
        &RecurringEndCondition::Both(100_000, start + 5000), // time hits first
        &(start + 86400),
    );

    env.ledger().set_timestamp(start + 3601);
    client.execute_recurring_lock(&recurring_id);

    // Time expired
    env.ledger().set_timestamp(start + 7201);
    let result = client.try_execute_recurring_lock(&recurring_id);
    assert!(result.is_err());
}

// ─── Cancellation ────────────────────────────────────────────────────────────

#[test]
fn test_cancel_recurring_lock() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let recurring_id = client.create_recurring_lock(
        &depositor,
        &1u64,
        &1000i128,
        &3600u64,
        &RecurringEndCondition::MaxTotal(10_000),
        &(env.ledger().timestamp() + 86400),
    );

    client.cancel_recurring_lock(&recurring_id);

    let (_config, state) = client.get_recurring_lock(&recurring_id);
    assert!(state.cancelled);

    // Cannot execute after cancellation
    env.ledger().set_timestamp(env.ledger().timestamp() + 3601);
    let result = client.try_execute_recurring_lock(&recurring_id);
    assert!(result.is_err());
}

#[test]
fn test_cancel_already_cancelled_fails() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let recurring_id = client.create_recurring_lock(
        &depositor,
        &1u64,
        &1000i128,
        &3600u64,
        &RecurringEndCondition::MaxTotal(10_000),
        &(env.ledger().timestamp() + 86400),
    );

    client.cancel_recurring_lock(&recurring_id);

    // Second cancellation should fail
    let result = client.try_cancel_recurring_lock(&recurring_id);
    assert!(result.is_err());
}

// ─── Query / Index ───────────────────────────────────────────────────────────

#[test]
fn test_depositor_recurring_lock_index() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let deadline = env.ledger().timestamp() + 86400;
    let id1 = client.create_recurring_lock(
        &depositor,
        &1u64,
        &500i128,
        &3600u64,
        &RecurringEndCondition::MaxTotal(5000),
        &deadline,
    );

    let id2 = client.create_recurring_lock(
        &depositor,
        &2u64,
        &1000i128,
        &7200u64,
        &RecurringEndCondition::MaxTotal(10_000),
        &deadline,
    );

    let ids = client.get_depositor_recurring_locks(&depositor);
    assert_eq!(ids.len(), 2);
    assert_eq!(ids.get(0).unwrap(), id1);
    assert_eq!(ids.get(1).unwrap(), id2);
}

#[test]
fn test_get_nonexistent_recurring_lock_fails() {
    let (_env, client, _token, _admin, _depositor) = setup(100_000);

    let result = client.try_get_recurring_lock(&999u64);
    assert!(result.is_err());
}

// ─── Escrow Sub-ID Uniqueness ────────────────────────────────────────────────

#[test]
fn test_escrow_sub_ids_are_unique_across_executions() {
    let (env, client, _token, _admin, depositor) = setup(100_000);

    let start = env.ledger().timestamp();
    let recurring_id = client.create_recurring_lock(
        &depositor,
        &1u64,
        &500i128,
        &60u64,
        &RecurringEndCondition::MaxTotal(5000),
        &(start + 86400),
    );

    // Execute twice and verify different escrow sub-IDs were created
    env.ledger().set_timestamp(start + 61);
    client.execute_recurring_lock(&recurring_id);

    env.ledger().set_timestamp(start + 122);
    client.execute_recurring_lock(&recurring_id);

    // Sub-bounty IDs: 1*1_000_000 + 1 = 1_000_001 and 1*1_000_000 + 2 = 1_000_002
    let info1 = client.get_escrow_info(&1_000_001u64);
    let info2 = client.get_escrow_info(&1_000_002u64);

    assert_eq!(info1.amount, 500);
    assert_eq!(info2.amount, 500);
}
