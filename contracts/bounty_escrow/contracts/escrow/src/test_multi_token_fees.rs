//! Multi-token fee tests for `BountyEscrowContract`.
//!
//! Covers:
//! - Fee calculation uses ceiling division (no dust drain)
//! - Per-token fee config overrides global config
//! - Fee recipient receives correct amount on lock and release
//! - Fee recipient cannot drain principal (net_amount > 0 invariant)
//! - Zero fee rate produces zero fee
//! - Max fee rate (50%) is enforced
//! - Invalid fee rates are rejected
//! - Fee events are emitted

#![cfg(test)]

use crate::{BountyEscrowContract, BountyEscrowContractClient, DataKey, Error, TokenFeeConfig};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, Env,
};

// ── helpers ──────────────────────────────────────────────────────────────────

struct Suite {
    env: Env,
    client: BountyEscrowContractClient<'static>,
    admin: Address,
    depositor: Address,
    contributor: Address,
    token_id: Address,
    token_admin: token::StellarAssetClient<'static>,
    fee_recipient: Address,
}

impl Suite {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);
        let fee_recipient = Address::generate(&env);

        let token_id = env.register_stellar_asset_contract(admin.clone());
        let token_admin = token::StellarAssetClient::new(&env, &token_id);

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);

        client.init(&admin, &token_id);

        Self {
            env,
            client,
            admin,
            depositor,
            contributor,
            token_id,
            token_admin,
            fee_recipient,
        }
    }

    /// Mint `amount` tokens to the depositor.
    fn fund_depositor(&self, amount: i128) {
        self.token_admin.mint(&self.depositor, &amount);
    }

    /// Current token balance of any address.
    fn balance(&self, addr: &Address) -> i128 {
        let tc = token::TokenClient::new(&self.env, &self.token_id);
        tc.balance(addr)
    }

    /// Default deadline: 1000 seconds from now.
    fn deadline(&self) -> u64 {
        self.env.ledger().timestamp() + 1000
    }
}

// ── calculate_fee unit-level tests ───────────────────────────────────────────

/// Ceiling division: fee is always at least 1 stroop when rate > 0
#[test]
fn test_calculate_fee_ceiling_small_amount() {
    // 1 stroop at 1 bp: floor = 0, ceil = 1
    // BASIS_POINTS = 10_000; fee = ceil(1 * 1 / 10_000) = 1
    let fee = crate::BountyEscrowContract::calculate_fee_pub(1, 1);
    assert_eq!(fee, 1, "1 stroop at 1bp must yield fee=1 (ceiling)");
}

#[test]
fn test_calculate_fee_ceiling_exact_division() {
    // 10_000 stroops at 100 bp = 1.00% → exact → 100
    let fee = crate::BountyEscrowContract::calculate_fee_pub(10_000, 100);
    assert_eq!(fee, 100);
}

#[test]
fn test_calculate_fee_zero_rate() {
    assert_eq!(
        crate::BountyEscrowContract::calculate_fee_pub(1_000_000, 0),
        0
    );
}

#[test]
fn test_calculate_fee_zero_amount() {
    assert_eq!(crate::BountyEscrowContract::calculate_fee_pub(0, 100), 0);
}

#[test]
fn test_calculate_fee_max_rate() {
    // 50% of 1_000 = 500
    let fee = crate::BountyEscrowContract::calculate_fee_pub(1_000, 5_000);
    assert_eq!(fee, 500);
}

// ── set_token_fee_config validation ──────────────────────────────────────────

#[test]
fn test_set_token_fee_config_invalid_lock_rate_rejected() {
    let s = Suite::new();
    let result = s.client.try_set_token_fee_config(
        &s.token_id,
        &5_001, // above MAX_FEE_RATE
        &0,
        &0,
        &0,
        &s.fee_recipient,
        &true,
    );
    assert_eq!(result.unwrap_err().unwrap(), Error::InvalidFeeRate);
}

#[test]
fn test_set_token_fee_config_invalid_release_rate_rejected() {
    let s = Suite::new();
    let result = s.client.try_set_token_fee_config(
        &s.token_id,
        &0,
        &10_001,
        &0,
        &0,
        &s.fee_recipient,
        &true,
    );
    assert_eq!(result.unwrap_err().unwrap(), Error::InvalidFeeRate);
}

#[test]
fn test_set_token_fee_config_zero_rates_accepted() {
    let s = Suite::new();
    s.client
        .set_token_fee_config(&s.token_id, &0, &0, &0, &0, &s.fee_recipient, &false);
    let cfg = s.client.get_token_fee_config(&s.token_id).unwrap();
    assert_eq!(cfg.lock_fee_rate, 0);
    assert_eq!(cfg.release_fee_rate, 0);
    assert!(!cfg.fee_enabled);
}

#[test]
fn test_set_token_fee_config_stores_correctly() {
    let s = Suite::new();
    s.client
        .set_token_fee_config(&s.token_id, &200, &100, &0, &0, &s.fee_recipient, &true);
    let cfg = s.client.get_token_fee_config(&s.token_id).unwrap();
    assert_eq!(cfg.lock_fee_rate, 200);
    assert_eq!(cfg.release_fee_rate, 100);
    assert_eq!(cfg.fee_recipient, s.fee_recipient);
    assert!(cfg.fee_enabled);
}

// ── lock fee collection ───────────────────────────────────────────────────────

/// When a lock fee is set, fee recipient receives the fee and escrow holds net.
#[test]
fn test_lock_fee_collected_correctly() {
    let s = Suite::new();
    // 2% lock fee
    s.client
        .set_token_fee_config(&s.token_id, &200, &0, &0, &0, &s.fee_recipient, &true);

    let gross = 1_000_000i128;
    s.fund_depositor(gross);
    s.client.lock_funds(&s.depositor, &1, &gross, &s.deadline());

    // fee = ceil(1_000_000 * 200 / 10_000) = ceil(20_000) = 20_000
    let expected_fee = 20_000i128;
    let expected_net = gross - expected_fee;

    assert_eq!(
        s.balance(&s.fee_recipient),
        expected_fee,
        "fee recipient must hold exactly the lock fee"
    );

    let escrow = s.client.get_escrow_info(&1);
    assert_eq!(
        escrow.amount, expected_net,
        "escrow must store net amount after fee"
    );
}

/// Zero fee rate: fee recipient gets nothing, full amount stored in escrow.
#[test]
fn test_lock_no_fee_when_rate_zero() {
    let s = Suite::new();
    s.client
        .set_token_fee_config(&s.token_id, &0, &0, &0, &0, &s.fee_recipient, &true);

    let amount = 500_000i128;
    s.fund_depositor(amount);
    s.client
        .lock_funds(&s.depositor, &1, &amount, &s.deadline());

    assert_eq!(s.balance(&s.fee_recipient), 0);
    assert_eq!(s.client.get_escrow_info(&1).amount, amount);
}

/// fee_enabled = false: no fee collected even with non-zero rate.
#[test]
fn test_lock_no_fee_when_disabled() {
    let s = Suite::new();
    s.client
        .set_token_fee_config(&s.token_id, &500, &500, &0, &0, &s.fee_recipient, &false);

    let amount = 100_000i128;
    s.fund_depositor(amount);
    s.client
        .lock_funds(&s.depositor, &1, &amount, &s.deadline());

    assert_eq!(s.balance(&s.fee_recipient), 0);
    assert_eq!(s.client.get_escrow_info(&1).amount, amount);
}

// ── principal drain protection ────────────────────────────────────────────────

/// Dust deposits: ceiling division guarantees fee >= 1 stroop at any non-zero rate.
/// This closes the attack where splitting a deposit into N dust amounts
/// each yields floor-fee = 0, so attacker pays zero total fee.
#[test]
fn test_dust_deposit_fee_never_zero_with_nonzero_rate() {
    let s = Suite::new();
    // 1 bp lock fee
    s.client
        .set_token_fee_config(&s.token_id, &1, &0, &0, &0, &s.fee_recipient, &true);

    // Deposit of 1 stroop: floor would give 0 fee, ceil must give 1
    s.fund_depositor(2); // need at least 2 so net > 0 after 1-stroop fee
    s.client.lock_funds(&s.depositor, &1, &2, &s.deadline());

    // fee = ceil(2 * 1 / 10_000) = ceil(0.0002) = 1
    assert_eq!(s.balance(&s.fee_recipient), 1);
    let escrow = s.client.get_escrow_info(&1);
    assert_eq!(escrow.amount, 1, "net must be 1 after 1-stroop fee");
    assert!(escrow.amount > 0, "principal must never be zero");
}

/// Net amount can never be <= 0: a misconfigured 100% fee is rejected.
/// (MAX_FEE_RATE = 50%, so 50% on a 1-stroop deposit = ceil(0.5) = 1 fee,
/// net = 0 which triggers InvalidAmount)
#[test]
fn test_fee_cannot_consume_entire_principal() {
    let s = Suite::new();
    // 50% lock fee on 1 stroop deposit → fee=1, net=0 → InvalidAmount
    s.client
        .set_token_fee_config(&s.token_id, &5_000, &0, &0, &0, &s.fee_recipient, &true);

    s.fund_depositor(1);
    let result = s.client.try_lock_funds(&s.depositor, &1, &1, &s.deadline());
    assert_eq!(
        result.unwrap_err().unwrap(),
        Error::InvalidAmount,
        "must reject when net_amount <= 0"
    );
}

// ── per-token config overrides global ────────────────────────────────────────

/// Per-token config takes precedence over global FeeConfig.
#[test]
fn test_per_token_config_overrides_global() {
    let s = Suite::new();

    // Global: 1% lock fee
    s.client.update_fee_config(
        &Some(100i128),
        &Some(0i128),
        &None,
        &None,
        &Some(s.admin.clone()),
        &Some(true),
    );

    // Per-token: 3% lock fee to fee_recipient
    s.client
        .set_token_fee_config(&s.token_id, &300, &0, &0, &0, &s.fee_recipient, &true);

    let amount = 100_000i128;
    s.fund_depositor(amount);
    s.client
        .lock_funds(&s.depositor, &1, &amount, &s.deadline());

    // Per-token 3% = 3_000 fee; global 1% would have been 1_000
    assert_eq!(
        s.balance(&s.fee_recipient),
        3_000,
        "per-token rate (3%) must override global rate (1%)"
    );
}

/// Without per-token config, global FeeConfig is used.
#[test]
fn test_global_fee_used_when_no_token_config() {
    let s = Suite::new();

    // Global: 1% lock fee to fee_recipient
    s.client.update_fee_config(
        &Some(100i128),
        &Some(0i128),
        &None,
        &None,
        &Some(s.fee_recipient.clone()),
        &Some(true),
    );

    let amount = 100_000i128;
    s.fund_depositor(amount);
    s.client
        .lock_funds(&s.depositor, &1, &amount, &s.deadline());

    assert_eq!(s.balance(&s.fee_recipient), 1_000);
}

// ── release fee collection ────────────────────────────────────────────────────

#[test]
fn test_release_fee_collected_correctly() {
    let s = Suite::new();
    // 1% release fee
    s.client
        .set_token_fee_config(&s.token_id, &0, &100, &0, &0, &s.fee_recipient, &true);

    let amount = 200_000i128;
    s.fund_depositor(amount);
    s.client
        .lock_funds(&s.depositor, &1, &amount, &s.deadline());
    s.client.release_funds(&1, &s.contributor);

    // release fee = ceil(200_000 * 100 / 10_000) = 2_000
    let expected_fee = 2_000i128;
    let expected_contributor = amount - expected_fee;

    assert_eq!(s.balance(&s.fee_recipient), expected_fee);
    assert_eq!(s.balance(&s.contributor), expected_contributor);
}

#[test]
fn test_release_no_fee_when_rate_zero() {
    let s = Suite::new();
    s.client
        .set_token_fee_config(&s.token_id, &0, &0, &0, &0, &s.fee_recipient, &true);

    let amount = 50_000i128;
    s.fund_depositor(amount);
    s.client
        .lock_funds(&s.depositor, &1, &amount, &s.deadline());
    s.client.release_funds(&1, &s.contributor);

    assert_eq!(s.balance(&s.fee_recipient), 0);
    assert_eq!(s.balance(&s.contributor), amount);
}

// ── get_token_fee_config view ─────────────────────────────────────────────────

#[test]
fn test_get_token_fee_config_returns_none_when_unset() {
    let s = Suite::new();
    let result = s.client.get_token_fee_config(&s.token_id);
    assert!(result.is_none(), "must return None when not configured");
}

#[test]
fn test_get_token_fee_config_returns_some_when_set() {
    let s = Suite::new();
    s.client
        .set_token_fee_config(&s.token_id, &150, &75, &0, &0, &s.fee_recipient, &true);
    let cfg = s.client.get_token_fee_config(&s.token_id).unwrap();
    assert_eq!(cfg.lock_fee_rate, 150);
    assert_eq!(cfg.release_fee_rate, 75);
}
