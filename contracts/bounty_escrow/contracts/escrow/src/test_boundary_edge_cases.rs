//! Boundary tests for amount policy, deadlines, fee configuration, batch/query limits, and escrow cardinality.
//!
//! # Related contract limits
//! - [`crate::BountyEscrowContract::set_amount_policy`] — inclusive `[min_amount, max_amount]`; invalid
//!   ordering (`min > max`) panics.
//! - [`crate::MAX_FEE_RATE`] — fee basis points cap (5000 = 50%).
//! - [`crate::MAX_BATCH_SIZE`] — batch lock/release size (see `test_batch_failure_modes`).
//! - Deadlines: `u64::MAX` is accepted as a sentinel for “no expiry” style locking; past timestamps are allowed at lock time.

#![cfg(test)]

use crate::{BountyEscrowContract, BountyEscrowContractClient, Error, EscrowStatus};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, Address, Env};

#[test]
fn test_focused_amount_and_deadline_boundaries() {
    let e = Env::default();
    let admin = Address::generate(&e);
    let depositor = Address::generate(&e);
    let recipient = Address::generate(&e);

    let contract_id = e.register_contract(None, BountyEscrowContract);
    let client = BountyEscrowContractClient::new(&e, &contract_id);

    let token_admin = Address::generate(&e);
    let token_id = e.register_stellar_asset_contract_v2(token_admin.clone());
    let token = token_id.address();
    let token_admin_client = token::StellarAssetClient::new(&e, &token);

    e.mock_all_auths();
    client.init(&admin, &token);

    token_admin_client.mint(&depositor, &1_000_000_000i128);

    let min_amount = 100i128;
    let max_amount = 10_000i128;
    client.set_amount_policy(&admin, &min_amount, &max_amount);

    let now = e.ledger().timestamp();
    let future_deadline = now + 1_000;

    client.lock_funds(&depositor, &101u64, &min_amount, &future_deadline);
    let info = client.get_escrow_info(&101u64);
    assert_eq!(
        info.amount, min_amount,
        "stored amount should match minimum"
    );

    client.lock_funds(&depositor, &102u64, &(min_amount + 1), &future_deadline);
    client.lock_funds(&depositor, &103u64, &(max_amount - 1), &future_deadline);
    client.lock_funds(&depositor, &104u64, &max_amount, &future_deadline);
    let info = client.get_escrow_info(&104u64);
    assert_eq!(
        info.amount, max_amount,
        "stored amount should match maximum"
    );

    let past_deadline = now.saturating_sub(1);
    client.lock_funds(&depositor, &200u64, &(min_amount + 10), &past_deadline);
    client.refund(&200u64);

    client.lock_funds(&depositor, &201u64, &(min_amount + 10), &now);

    let far_future = now + 1_000_000;
    client.lock_funds(&depositor, &202u64, &(min_amount + 10), &far_future);
    let info = client.get_escrow_info(&202u64);
    assert_eq!(
        info.deadline, far_future,
        "stored deadline should match far future"
    );

    let no_deadline = u64::MAX;
    client.lock_funds(&depositor, &203u64, &(min_amount + 10), &no_deadline);
    let info = client.get_escrow_info(&203u64);
    assert_eq!(
        info.deadline, no_deadline,
        "stored deadline should be NO_DEADLINE"
    );

    let ok_zero_fee = client.try_update_fee_config(&Some(0), &Some(0), &None, &None, &None, &None);
    assert!(ok_zero_fee.is_ok(), "zero fee rate should be allowed");

    let ok_max_fee =
        client.try_update_fee_config(&Some(5_000), &Some(5_000), &None, &None, &None, &None);
    assert!(ok_max_fee.is_ok(), "MAX_FEE_RATE (5000) should be allowed");

    let err_over_max =
        client.try_update_fee_config(&Some(5_001), &None, &None, &None, &None, &None);
    assert!(
        err_over_max.is_err(),
        "fee rate above maximum should be rejected"
    );

    let err_overflow =
        client.try_update_fee_config(&Some(i128::MAX), &None, &None, &None, &None, &None);
    assert!(
        err_overflow.is_err(),
        "overflow fee rate should be rejected"
    );

    let count = client.get_escrow_count();
    assert!(
        count > 0,
        "escrow count should be greater than zero after creating escrows"
    );

    let _ = recipient;
}

/// One below minimum and one above maximum must fail with explicit contract errors (not panic).
#[test]
fn test_amount_policy_rejects_out_of_range() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let depositor = Address::generate(&e);
    let contract_id = e.register_contract(None, BountyEscrowContract);
    let client = BountyEscrowContractClient::new(&e, &contract_id);
    let token_admin = Address::generate(&e);
    let token = e
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let sac = token::StellarAssetClient::new(&e, &token);
    client.init(&admin, &token);
    sac.mint(&depositor, &1_000_000i128);

    let min_amount = 500i128;
    let max_amount = 600i128;
    client.set_amount_policy(&admin, &min_amount, &max_amount);
    let deadline = e.ledger().timestamp() + 10_000;

    assert_eq!(
        client
            .try_lock_funds(&depositor, &1u64, &(min_amount - 1), &deadline)
            .unwrap_err()
            .unwrap(),
        Error::InvalidAmount
    );
    assert_eq!(
        client
            .try_lock_funds(&depositor, &2u64, &(max_amount + 1), &deadline)
            .unwrap_err()
            .unwrap(),
        Error::InvalidAmount
    );

    assert!(client
        .try_lock_funds(&depositor, &3u64, &min_amount, &deadline)
        .is_ok());
}

/// `min_amount > max_amount` is a programmer error; the contract panics with a clear message.
#[test]
#[should_panic(expected = "invalid policy: min_amount cannot exceed max_amount")]
fn test_set_amount_policy_rejects_inverted_range() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let contract_id = e.register_contract(None, BountyEscrowContract);
    let client = BountyEscrowContractClient::new(&e, &contract_id);
    let token = e
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    client.init(&admin, &token);
    client.set_amount_policy(&admin, &100i128, &50i128);
}

/// Query APIs with `limit == 0` yield no rows (pagination edge).
#[test]
fn test_escrow_status_query_limit_zero_returns_empty() {
    let e = Env::default();
    e.mock_all_auths();
    let admin = Address::generate(&e);
    let depositor = Address::generate(&e);
    let contract_id = e.register_contract(None, BountyEscrowContract);
    let client = BountyEscrowContractClient::new(&e, &contract_id);
    let token_admin = Address::generate(&e);
    let token = e
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let sac = token::StellarAssetClient::new(&e, &token);
    client.init(&admin, &token);
    sac.mint(&depositor, &10_000i128);
    let deadline = e.ledger().timestamp() + 86_400;
    client.lock_funds(&depositor, &50u64, &1_000i128, &deadline);

    let empty = client.get_escrow_ids_by_status(&EscrowStatus::Locked, &0u32, &0u32);
    assert_eq!(empty.len(), 0);
}
