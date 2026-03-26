use super::*;
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{
    testutils::{Address as _, LedgerInfo},
    token, Address, Env,
};

/// Race-model tests for front-running-sensitive escrow actions.
///
/// # Assumptions
/// - Soroban executes contract calls atomically within a transaction.
/// - Contention is modeled as multiple transactions touching the same bounty in sequence.
/// - Determinism requirement: once the first state transition succeeds, later conflicting
///   transitions must fail with a stable error and must not move additional funds.

fn create_token_contract<'a>(
    env: &Env,
    admin: &Address,
) -> (token::Client<'a>, token::StellarAssetClient<'a>) {
    // register_stellar_asset_contract_v2 returns StellarAssetContract
    let contract = env.register_stellar_asset_contract_v2(admin.clone());
    // Get the Address from the contract object
    let addr = contract.address();
    (
        token::Client::new(env, &addr),
        token::StellarAssetClient::new(env, &addr),
    )
}

fn create_escrow_contract<'a>(env: &Env) -> BountyEscrowContractClient<'a> {
    let contract_id = env.register_contract(None, BountyEscrowContract);
    BountyEscrowContractClient::new(env, &contract_id)
}

struct TestSetup<'a> {
    env: Env,
    _admin: Address,
    depositor: Address,
    token: token::Client<'a>,
    _token_admin: token::StellarAssetClient<'a>,
    escrow: BountyEscrowContractClient<'a>,
}

impl<'a> TestSetup<'a> {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        let escrow = create_escrow_contract(&env);
        escrow.init(&admin, &token.address);
        token_admin.mint(&depositor, &1_000_000);

        Self {
            env,
            _admin: admin,
            depositor,
            token,
            _token_admin: token_admin,
            escrow,
        }
    }
}

fn set_ledger_timestamp(env: &Env, timestamp: u64) {
    env.ledger().set(LedgerInfo {
        timestamp,
        protocol_version: 20,
        sequence_number: 0,
        network_id: Default::default(),
        base_reserve: 0,
        min_temp_entry_ttl: 0,
        min_persistent_entry_ttl: 0,
        max_entry_ttl: 0,
    });
}

#[test]
fn test_release_race_first_recipient_wins_order_ab() {
    let setup = TestSetup::new();
    let bounty_id = 9101_u64;
    let amount = 80_000_i128;
    let deadline = setup.env.ledger().timestamp() + 1_000;
    let recipient_a = Address::generate(&setup.env);
    let recipient_b = Address::generate(&setup.env);

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);

    setup.escrow.release_funds(&bounty_id, &recipient_a);
    let second_release = setup.escrow.try_release_funds(&bounty_id, &recipient_b);

    assert_eq!(second_release, Err(Ok(Error::FundsNotLocked)));
    assert_eq!(setup.token.balance(&recipient_a), amount);
    assert_eq!(setup.token.balance(&recipient_b), 0);

    let escrow = setup.escrow.get_escrow_info(&bounty_id);
    assert_eq!(escrow.status, EscrowStatus::Released);
}

#[test]
fn test_release_race_first_recipient_wins_order_ba() {
    let setup = TestSetup::new();
    let bounty_id = 9102_u64;
    let amount = 80_000_i128;
    let deadline = setup.env.ledger().timestamp() + 1_000;
    let recipient_a = Address::generate(&setup.env);
    let recipient_b = Address::generate(&setup.env);

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);

    setup.escrow.release_funds(&bounty_id, &recipient_b);
    let second_release = setup.escrow.try_release_funds(&bounty_id, &recipient_a);

    assert_eq!(second_release, Err(Ok(Error::FundsNotLocked)));
    assert_eq!(setup.token.balance(&recipient_b), amount);
    assert_eq!(setup.token.balance(&recipient_a), 0);

    let escrow = setup.escrow.get_escrow_info(&bounty_id);
    assert_eq!(escrow.status, EscrowStatus::Released);
}

#[test]
fn test_authorize_claim_race_last_authorization_wins() {
    let setup = TestSetup::new();
    let bounty_id = 9103_u64;
    let amount = 90_000_i128;
    let deadline = setup.env.ledger().timestamp() + 2_000;
    let claimant_a = Address::generate(&setup.env);
    let claimant_b = Address::generate(&setup.env);

    setup.escrow.set_claim_window(&500);
    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);

    setup
        .escrow
        .authorize_claim(&bounty_id, &claimant_a, &DisputeReason::Other);
    setup
        .escrow
        .authorize_claim(&bounty_id, &claimant_b, &DisputeReason::Other);

    let pending = setup.escrow.get_pending_claim(&bounty_id);
    assert_eq!(pending.recipient, claimant_b);
    assert_eq!(pending.amount, amount);

    setup.escrow.claim(&bounty_id);

    assert_eq!(setup.token.balance(&claimant_a), 0);
    assert_eq!(setup.token.balance(&claimant_b), amount);
    assert_eq!(setup.token.balance(&setup.escrow.address), 0);

    let second_claim = setup.escrow.try_claim(&bounty_id);
    assert_eq!(second_claim, Err(Ok(Error::FundsNotLocked)));
}

// Auto-refund race: multiple parties try to trigger refund after deadline
#[test]
fn test_auto_refund_race_first_caller_wins() {
    let setup = TestSetup::new();
    let bounty_id = 9104_u64;
    let amount = 50_000_i128;
    let deadline = setup.env.ledger().timestamp() + 100;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);

    setup.env.ledger().set_timestamp(deadline + 1);

    let caller_a = Address::generate(&setup.env);
    let caller_b = Address::generate(&setup.env);

    setup.escrow.refund(&bounty_id);
    let second_refund = setup.escrow.try_refund(&bounty_id);

    assert_eq!(second_refund, Err(Ok(Error::FundsNotLocked)));
    assert_eq!(setup.token.balance(&setup.depositor), 1_000_000);
    assert_eq!(setup.token.balance(&caller_a), 0);
    assert_eq!(setup.token.balance(&caller_b), 0);

    let escrow = setup.escrow.get_escrow_info(&bounty_id);
    assert_eq!(escrow.status, EscrowStatus::Refunded);
}

// Partial release race: ensure remaining_amount is consistent
#[test]
fn test_partial_release_race_prevents_double_spend() {
    let setup = TestSetup::new();
    let bounty_id = 9105_u64;
    let amount = 100_000_i128;
    let deadline = setup.env.ledger().timestamp() + 1_000;
    let recipient = Address::generate(&setup.env);

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);

    setup
        .escrow
        .partial_release(&bounty_id, &recipient, &60_000);

    let escrow = setup.escrow.get_escrow_info(&bounty_id);
    assert_eq!(escrow.remaining_amount, 40_000);
    assert_eq!(setup.token.balance(&recipient), 60_000);

    let second_partial = setup
        .escrow
        .try_partial_release(&bounty_id, &recipient, &50_000);
    assert_eq!(second_partial, Err(Ok(Error::InsufficientFunds)));

    assert_eq!(setup.token.balance(&recipient), 60_000);
}

// Batch release race: ensure atomicity
#[test]
fn test_batch_release_prevents_double_release() {
    let setup = TestSetup::new();
    let deadline = setup.env.ledger().timestamp() + 1_000;
    let recipient_a = Address::generate(&setup.env);
    let recipient_b = Address::generate(&setup.env);

    setup
        .escrow
        .lock_funds(&setup.depositor, &1, &10_000, &deadline);
    setup
        .escrow
        .lock_funds(&setup.depositor, &2, &20_000, &deadline);

    let items = vec![
        &setup.env,
        ReleaseFundsItem {
            bounty_id: 1,
            contributor: recipient_a.clone(),
        },
        ReleaseFundsItem {
            bounty_id: 2,
            contributor: recipient_b.clone(),
        },
    ];

    setup.escrow.batch_release_funds(&items);

    assert_eq!(setup.token.balance(&recipient_a), 10_000);
    assert_eq!(setup.token.balance(&recipient_b), 20_000);

    let second_batch = setup.escrow.try_batch_release_funds(&items);
    assert_eq!(second_batch, Err(Ok(Error::FundsNotLocked)));

    assert_eq!(setup.token.balance(&recipient_a), 10_000);
    assert_eq!(setup.token.balance(&recipient_b), 20_000);
}

// Refund vs Release race: first operation wins
#[test]
fn test_refund_vs_release_race_first_wins() {
    let setup = TestSetup::new();
    let bounty_id = 9106_u64;
    let amount = 75_000_i128;
    let deadline = setup.env.ledger().timestamp() + 100;
    let recipient = Address::generate(&setup.env);

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);

    setup.env.ledger().set_timestamp(deadline + 1);

    setup.escrow.refund(&bounty_id);

    let release_attempt = setup.escrow.try_release_funds(&bounty_id, &recipient);
    assert_eq!(release_attempt, Err(Ok(Error::FundsNotLocked)));

    assert_eq!(setup.token.balance(&setup.depositor), 1_000_000);
    assert_eq!(setup.token.balance(&recipient), 0);

    let escrow = setup.escrow.get_escrow_info(&bounty_id);
    assert_eq!(escrow.status, EscrowStatus::Refunded);
}

// Claim race: only authorized claimant can claim
#[test]
fn test_claim_race_unauthorized_fails() {
    let setup = TestSetup::new();
    let bounty_id = 9107_u64;
    let amount = 60_000_i128;
    let deadline = setup.env.ledger().timestamp() + 2_000;
    let authorized = Address::generate(&setup.env);
    let unauthorized = Address::generate(&setup.env);

    setup.escrow.set_claim_window(&500);
    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);

    setup
        .escrow
        .authorize_claim(&bounty_id, &authorized, &DisputeReason::Other);

    setup.escrow.claim(&bounty_id);

    assert_eq!(setup.token.balance(&authorized), amount);
    assert_eq!(setup.token.balance(&unauthorized), 0);

    let escrow = setup.escrow.get_escrow_info(&bounty_id);
    assert_eq!(escrow.status, EscrowStatus::Released);
}

#[test]
fn test_authorize_claim_after_release_fails_deterministically() {
    let setup = TestSetup::new();
    let bounty_id = 9108_u64;
    let amount = 44_000_i128;
    let deadline = setup.env.ledger().timestamp() + 2_000;
    let released_recipient = Address::generate(&setup.env);
    let late_claimant = Address::generate(&setup.env);

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);

    setup.escrow.release_funds(&bounty_id, &released_recipient);

    let late_authorize =
        setup
            .escrow
            .try_authorize_claim(&bounty_id, &late_claimant, &DisputeReason::Other);

    assert_eq!(late_authorize, Err(Ok(Error::FundsNotLocked)));
    assert_eq!(setup.token.balance(&released_recipient), amount);
    assert_eq!(setup.token.balance(&late_claimant), 0);
}
