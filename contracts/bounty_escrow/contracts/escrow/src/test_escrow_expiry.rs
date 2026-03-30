//! # Escrow Lock Expiry & Auto-Cleanup Tests
//!
//! Validates:
//! - Expiry config CRUD
//! - Escrows receive creation_timestamp and expiry on lock
//! - query_expired_escrows identifies stale escrows
//! - mark_escrow_expired transitions status
//! - cleanup_expired_escrow removes storage
//! - batch_cleanup_expired_escrows handles multiple
//! - Safety: cannot expire/clean escrows with remaining funds
#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    token, Address, Env,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

struct Setup {
    env: Env,
    client: BountyEscrowContractClient<'static>,
    token_client: token::Client<'static>,
    token_admin: token::StellarAssetClient<'static>,
    admin: Address,
    depositor: Address,
}

impl Setup {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let (token_client, token_admin) = create_token_contract(&env, &admin);
        let client = create_escrow_contract(&env);

        client.init(&admin, &token_client.address);
        token_admin.mint(&depositor, &100_000);

        Setup {
            env,
            client,
            token_client,
            token_admin,
            admin,
            depositor,
        }
    }

    /// Lock a bounty and return the bounty_id used.
    fn lock(&self, bounty_id: u64, amount: i128) -> u64 {
        let deadline = self.env.ledger().timestamp() + 86_400;
        self.client
            .lock_funds(&self.depositor, &bounty_id, &amount, &deadline);
        bounty_id
    }
}

// ===========================================================================
// Expiry Config
// ===========================================================================

#[test]
fn test_set_and_get_expiry_config() {
    let s = Setup::new();

    // Initially no config
    assert!(s.client.get_expiry_config().is_none());

    // Set config
    s.client.set_expiry_config(&86_400_u64, &true);

    let cfg = s.client.get_expiry_config().unwrap();
    assert_eq!(cfg.default_expiry_duration, 86_400);
    assert!(cfg.auto_cleanup_enabled);
}

#[test]
fn test_update_expiry_config() {
    let s = Setup::new();

    s.client.set_expiry_config(&3600_u64, &false);
    let cfg = s.client.get_expiry_config().unwrap();
    assert_eq!(cfg.default_expiry_duration, 3600);
    assert!(!cfg.auto_cleanup_enabled);

    // Update
    s.client.set_expiry_config(&7200_u64, &true);
    let cfg2 = s.client.get_expiry_config().unwrap();
    assert_eq!(cfg2.default_expiry_duration, 7200);
    assert!(cfg2.auto_cleanup_enabled);
}

// ===========================================================================
// Escrow creation stores creation_timestamp and expiry
// ===========================================================================

#[test]
fn test_lock_funds_stores_creation_timestamp_and_expiry() {
    let s = Setup::new();

    // Set expiry config: 1 day
    s.client.set_expiry_config(&86_400_u64, &true);

    let now = s.env.ledger().timestamp();
    let bounty_id = s.lock(1, 1000);

    let escrow = s.client.get_escrow_info(&bounty_id);
    assert_eq!(escrow.creation_timestamp, now);
    assert_eq!(escrow.expiry, now + 86_400);
}

#[test]
fn test_lock_funds_without_expiry_config_sets_zero() {
    let s = Setup::new();
    // No expiry config set

    let bounty_id = s.lock(1, 1000);
    let escrow = s.client.get_escrow_info(&bounty_id);
    assert_eq!(escrow.creation_timestamp, s.env.ledger().timestamp());
    assert_eq!(escrow.expiry, 0);
}

// ===========================================================================
// query_expired_escrows
// ===========================================================================

#[test]
fn test_query_expired_escrows_returns_past_expiry() {
    let s = Setup::new();

    // Set expiry to 100 seconds
    s.client.set_expiry_config(&100_u64, &true);

    // Lock at current time
    s.lock(1, 1000);

    // Before expiry: no results
    let results = s.client.query_expired_escrows(&0_u32, &10_u32);
    assert_eq!(results.len(), 0);

    // Advance time past expiry
    s.env.ledger().with_mut(|li| {
        li.timestamp += 200;
    });

    let results = s.client.query_expired_escrows(&0_u32, &10_u32);
    assert_eq!(results.len(), 1);
    assert_eq!(results.get(0).unwrap().bounty_id, 1);
}

#[test]
fn test_query_expired_escrows_ignores_no_expiry() {
    let s = Setup::new();
    // No expiry config — escrows get expiry=0

    s.lock(1, 1000);

    s.env.ledger().with_mut(|li| {
        li.timestamp += 999_999;
    });

    // expiry=0 means no expiry, should not appear
    let results = s.client.query_expired_escrows(&0_u32, &10_u32);
    assert_eq!(results.len(), 0);
}

// ===========================================================================
// mark_escrow_expired
// ===========================================================================

#[test]
fn test_mark_escrow_expired_zero_balance() {
    let s = Setup::new();

    s.client.set_expiry_config(&100_u64, &true);
    s.lock(1, 1000);

    // Release funds so remaining_amount becomes 0
    let contributor = Address::generate(&s.env);
    s.client.release_funds(&1_u64, &contributor);

    // Advance past expiry
    s.env.ledger().with_mut(|li| {
        li.timestamp += 200;
    });

    s.client.mark_escrow_expired(&1_u64);

    let escrow = s.client.get_escrow_info(&1_u64);
    assert_eq!(escrow.status, EscrowStatus::Expired);
}

#[test]
#[should_panic(expected = "Error(Contract, #45)")] // EscrowNotExpired
fn test_mark_escrow_expired_before_expiry_fails() {
    let s = Setup::new();

    s.client.set_expiry_config(&100_u64, &true);
    s.lock(1, 1000);

    // Release funds
    let contributor = Address::generate(&s.env);
    s.client.release_funds(&1_u64, &contributor);

    // Do NOT advance time — still before expiry
    s.client.mark_escrow_expired(&1_u64);
}

#[test]
#[should_panic(expected = "Error(Contract, #44)")] // EscrowNotEmpty
fn test_mark_escrow_expired_with_funds_fails() {
    let s = Setup::new();

    s.client.set_expiry_config(&100_u64, &true);
    s.lock(1, 1000);

    // Advance past expiry but DO NOT release funds
    s.env.ledger().with_mut(|li| {
        li.timestamp += 200;
    });

    // Should fail because remaining_amount > 0
    s.client.mark_escrow_expired(&1_u64);
}

#[test]
#[should_panic(expected = "Error(Contract, #46)")] // EscrowAlreadyExpired
fn test_mark_escrow_expired_twice_fails() {
    let s = Setup::new();

    s.client.set_expiry_config(&100_u64, &true);
    s.lock(1, 1000);

    let contributor = Address::generate(&s.env);
    s.client.release_funds(&1_u64, &contributor);

    s.env.ledger().with_mut(|li| {
        li.timestamp += 200;
    });

    s.client.mark_escrow_expired(&1_u64);
    // Second call should fail
    s.client.mark_escrow_expired(&1_u64);
}

// ===========================================================================
// cleanup_expired_escrow
// ===========================================================================

#[test]
fn test_cleanup_expired_escrow_removes_storage() {
    let s = Setup::new();

    s.client.set_expiry_config(&100_u64, &true);
    s.lock(1, 1000);

    let contributor = Address::generate(&s.env);
    s.client.release_funds(&1_u64, &contributor);

    s.env.ledger().with_mut(|li| {
        li.timestamp += 200;
    });

    s.client.mark_escrow_expired(&1_u64);
    s.client.cleanup_expired_escrow(&1_u64);

    // Escrow should no longer exist
    let result = s.client.try_get_escrow_info(&1_u64);
    assert!(result.is_err());

    // Count should be 0
    assert_eq!(s.client.get_escrow_count(), 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #45)")] // EscrowNotExpired
fn test_cleanup_non_expired_escrow_fails() {
    let s = Setup::new();

    s.client.set_expiry_config(&100_u64, &true);
    s.lock(1, 1000);

    // Not expired, not marked — should fail
    s.client.cleanup_expired_escrow(&1_u64);
}

// ===========================================================================
// batch_cleanup_expired_escrows
// ===========================================================================

#[test]
fn test_batch_cleanup_multiple_expired_escrows() {
    let s = Setup::new();

    s.client.set_expiry_config(&100_u64, &true);

    // Lock 3 escrows
    s.lock(1, 1000);
    s.lock(2, 2000);
    s.lock(3, 3000);

    // Release all
    let contributor = Address::generate(&s.env);
    s.client.release_funds(&1_u64, &contributor);
    s.client.release_funds(&2_u64, &contributor);
    s.client.release_funds(&3_u64, &contributor);

    // Advance past expiry
    s.env.ledger().with_mut(|li| {
        li.timestamp += 200;
    });

    // Mark all as expired
    s.client.mark_escrow_expired(&1_u64);
    s.client.mark_escrow_expired(&2_u64);
    s.client.mark_escrow_expired(&3_u64);

    // Batch cleanup
    let cleaned = s.client.batch_cleanup_expired_escrows(&10_u32);
    assert_eq!(cleaned, 3);
    assert_eq!(s.client.get_escrow_count(), 0);
}

#[test]
fn test_batch_cleanup_respects_limit() {
    let s = Setup::new();

    s.client.set_expiry_config(&100_u64, &true);

    s.lock(1, 1000);
    s.lock(2, 2000);

    let contributor = Address::generate(&s.env);
    s.client.release_funds(&1_u64, &contributor);
    s.client.release_funds(&2_u64, &contributor);

    s.env.ledger().with_mut(|li| {
        li.timestamp += 200;
    });

    s.client.mark_escrow_expired(&1_u64);
    s.client.mark_escrow_expired(&2_u64);

    // Only clean 1
    let cleaned = s.client.batch_cleanup_expired_escrows(&1_u32);
    assert_eq!(cleaned, 1);
    assert_eq!(s.client.get_escrow_count(), 1);
}

#[test]
fn test_batch_cleanup_skips_active_escrows() {
    let s = Setup::new();

    s.client.set_expiry_config(&100_u64, &true);

    s.lock(1, 1000);
    s.lock(2, 2000);

    // Only release and expire bounty 1
    let contributor = Address::generate(&s.env);
    s.client.release_funds(&1_u64, &contributor);

    s.env.ledger().with_mut(|li| {
        li.timestamp += 200;
    });

    s.client.mark_escrow_expired(&1_u64);

    // Batch cleanup should only clean 1 (bounty 2 is still Locked with funds)
    let cleaned = s.client.batch_cleanup_expired_escrows(&10_u32);
    assert_eq!(cleaned, 1);
    assert_eq!(s.client.get_escrow_count(), 1);

    // Bounty 2 still accessible
    let escrow2 = s.client.get_escrow_info(&2_u64);
    assert_eq!(escrow2.status, EscrowStatus::Locked);
}
