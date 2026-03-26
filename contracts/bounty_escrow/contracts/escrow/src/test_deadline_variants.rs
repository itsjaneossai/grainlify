#![cfg(test)]
//! # Bounty Escrow Deadline Variant Tests
//!
//! Closes #763
//!
//! This module validates the three deadline configurations supported by the
//! bounty escrow contract and documents the time semantics used with the
//! Soroban ledger timestamp.
//!
//! ## Deadline Variants
//!
//! | Variant          | Value          | Refund Behavior                                |
//! |------------------|----------------|------------------------------------------------|
//! | Zero deadline    | `0`            | Immediately refundable (no waiting period)     |
//! | Future deadline  | `now + n`      | Blocked until `ledger_timestamp >= deadline`   |
//! | No deadline      | `u64::MAX`     | Permanently blocked without admin approval     |
//!
//! ## Time Semantics
//!
//! All deadline comparisons use the **Soroban ledger timestamp** (`env.ledger().timestamp()`),
//! which represents the close time of the current ledger in **Unix epoch seconds** (u64).
//!
//! - The refund check is: `ledger_timestamp >= deadline` → eligible for refund.
//! - When `deadline == 0`, the condition `now >= 0` is always true for u64, so
//!   refunds are allowed immediately.
//! - When `deadline == u64::MAX`, the condition `now >= u64::MAX` is never true
//!   under normal operation (even 100+ years from epoch), so refunds are
//!   permanently blocked unless an admin approval overrides the check.
//! - `release_funds` is **not gated by deadline** — releases can happen at any time
//!   regardless of the deadline value.
//!
//! ## Security Notes
//!
//! - Deadline values are stored as-is and never normalized, ensuring the depositor's
//!   intent is faithfully preserved.
//! - The `u64::MAX` sentinel is safe because the Soroban ledger timestamp will not
//!   reach this value within any practical timeframe.
//! - Admin-approved refunds bypass the deadline check entirely, providing an escape
//!   hatch for all deadline configurations.
//! - Partial refunds via `approve_refund` with `RefundMode::Partial` correctly
//!   preserve the remaining balance and transition to `PartiallyRefunded` status.

use crate::{BountyEscrowContract, BountyEscrowContractClient, Error, EscrowStatus, RefundMode};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, Env,
};

/// Creates a Stellar asset token contract for testing.
fn create_token_contract<'a>(
    e: &Env,
    admin: &Address,
) -> (token::Client<'a>, token::StellarAssetClient<'a>) {
    let contract = e.register_stellar_asset_contract_v2(admin.clone());
    let addr = contract.address();
    (
        token::Client::new(e, &addr),
        token::StellarAssetClient::new(e, &addr),
    )
}

/// Registers a new bounty escrow contract instance.
fn create_escrow_contract<'a>(e: &Env) -> BountyEscrowContractClient<'a> {
    let id = e.register_contract(None, BountyEscrowContract);
    BountyEscrowContractClient::new(e, &id)
}
const NO_DEADLINE: u64 = u64::MAX;

/// Shared test setup providing an initialized escrow contract with a funded depositor.
///
/// - Admin: contract administrator
/// - Depositor: funded with 10,000,000 tokens
/// - Contributor: recipient for released funds
struct Setup<'a> {
    env: Env,
    _admin: Address,
    depositor: Address,
    contributor: Address,
    token: token::Client<'a>,
    escrow: BountyEscrowContractClient<'a>,
}

impl<'a> Setup<'a> {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        let escrow = create_escrow_contract(&env);

        escrow.init(&admin, &token.address);
        token_admin.mint(&depositor, &10_000_000);

        Self {
            env,
            _admin: admin,
            depositor,
            contributor,
            token,
            escrow,
        }
    }
}


#[test]
fn test_future_deadline_refund_blocked_before_expiry() {
    let s = Setup::new();
    let deadline = s.env.ledger().timestamp() + 10_000;
    s.escrow.lock_funds(&s.depositor, &11, &1_000, &deadline);

    let result = s.escrow.try_refund(&11);
    assert_eq!(result.unwrap_err().unwrap(), Error::DeadlineNotPassed);

    let info = s.escrow.get_escrow_info(&11);
    assert_eq!(info.status, EscrowStatus::Locked);
    assert_eq!(s.token.balance(&s.escrow.address), 1_000);
}

#[test]
fn test_future_deadline_refund_succeeds_after_expiry() {
    let s = Setup::new();
    let now = s.env.ledger().timestamp();
    let deadline = now + 500;
    s.escrow.lock_funds(&s.depositor, &12, &1_200, &deadline);

    s.env.ledger().set_timestamp(deadline + 1);

    let before = s.token.balance(&s.depositor);
    s.escrow.refund(&12);

    let info = s.escrow.get_escrow_info(&12);
    assert_eq!(info.status, EscrowStatus::Refunded);
    assert_eq!(s.token.balance(&s.depositor), before + 1_200);
    assert_eq!(s.token.balance(&s.escrow.address), 0);
}

#[test]
fn test_future_deadline_early_refund_with_admin_approval() {
    let s = Setup::new();
    let deadline = s.env.ledger().timestamp() + 86_400;
    s.escrow.lock_funds(&s.depositor, &13, &2_000, &deadline);

    s.escrow
        .approve_refund(&13, &2_000, &s.depositor, &RefundMode::Full);

    let before = s.token.balance(&s.depositor);
    s.escrow.refund(&13);

    let info = s.escrow.get_escrow_info(&13);
    assert_eq!(info.status, EscrowStatus::Refunded);
    assert_eq!(s.token.balance(&s.depositor), before + 2_000);
}

#[test]
fn test_future_deadline_release_unaffected_by_deadline() {
    let s = Setup::new();
    let deadline = s.env.ledger().timestamp() + 86_400;
    s.escrow.lock_funds(&s.depositor, &14, &3_000, &deadline);

    s.escrow.release_funds(&14, &s.contributor);

    let info = s.escrow.get_escrow_info(&14);
    assert_eq!(info.status, EscrowStatus::Released);
    assert_eq!(s.token.balance(&s.contributor), 3_000);
}


#[test]
fn test_no_deadline_refund_blocked_without_approval() {
    let s = Setup::new();
    s.escrow.lock_funds(&s.depositor, &21, &1_000, &NO_DEADLINE);

    let result = s.escrow.try_refund(&21);
    assert_eq!(result.unwrap_err().unwrap(), Error::DeadlineNotPassed);

    let info = s.escrow.get_escrow_info(&21);
    assert_eq!(info.status, EscrowStatus::Locked);
    assert_eq!(s.token.balance(&s.escrow.address), 1_000);
}

#[test]
fn test_no_deadline_refund_blocked_even_after_large_time_advance() {
    let s = Setup::new();
    s.escrow.lock_funds(&s.depositor, &22, &1_000, &NO_DEADLINE);

    // Advance the clock by 100 years worth of seconds — still less than u64::MAX
    s.env.ledger().set_timestamp(100 * 365 * 24 * 3600);

    let result = s.escrow.try_refund(&22);
    assert_eq!(result.unwrap_err().unwrap(), Error::DeadlineNotPassed);
}

#[test]
fn test_no_deadline_refund_succeeds_with_admin_approval() {
    let s = Setup::new();
    s.escrow.lock_funds(&s.depositor, &23, &1_500, &NO_DEADLINE);

    s.escrow
        .approve_refund(&23, &1_500, &s.depositor, &RefundMode::Full);

    let before = s.token.balance(&s.depositor);
    s.escrow.refund(&23);

    let info = s.escrow.get_escrow_info(&23);
    assert_eq!(info.status, EscrowStatus::Refunded);
    assert_eq!(s.token.balance(&s.depositor), before + 1_500);
    assert_eq!(s.token.balance(&s.escrow.address), 0);
}

#[test]
fn test_no_deadline_partial_refund_with_admin_approval() {
    let s = Setup::new();
    s.escrow.lock_funds(&s.depositor, &24, &2_000, &NO_DEADLINE);

    s.escrow
        .approve_refund(&24, &800, &s.depositor, &RefundMode::Partial);

    s.escrow.refund(&24);

    let info = s.escrow.get_escrow_info(&24);
    assert_eq!(info.status, EscrowStatus::PartiallyRefunded);
    assert_eq!(info.remaining_amount, 1_200);
    assert_eq!(s.token.balance(&s.escrow.address), 1_200);
}

#[test]
fn test_no_deadline_release_succeeds() {
    let s = Setup::new();
    s.escrow.lock_funds(&s.depositor, &25, &2_500, &NO_DEADLINE);

    s.escrow.release_funds(&25, &s.contributor);

    let info = s.escrow.get_escrow_info(&25);
    assert_eq!(info.status, EscrowStatus::Released);
    assert_eq!(s.token.balance(&s.contributor), 2_500);
    assert_eq!(s.token.balance(&s.escrow.address), 0);
}


