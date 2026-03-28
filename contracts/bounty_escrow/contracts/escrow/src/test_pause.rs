use super::*;
use crate::PauseStateChanged;
use soroban_sdk::{
    testutils::{Address as _, Events, Ledger},
    token, Address, Env, IntoVal, Symbol, TryIntoVal,
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

fn create_escrow_contract<'a>(e: &Env) -> (BountyEscrowContractClient<'a>, Address) {
    let contract_id = e.register_contract(None, BountyEscrowContract);
    let client = BountyEscrowContractClient::new(e, &contract_id);
    (client, contract_id)
}

#[test]
fn test_granular_pause_lock() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let token_admin = Address::generate(&env);

    let (token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    let (escrow_client, _escrow_address) = create_escrow_contract(&env);

    escrow_client.init(&admin, &token_client.address);

    let flags = escrow_client.get_pause_flags();
    assert!(!flags.lock_paused);
    assert!(!flags.release_paused);
    assert!(!flags.refund_paused);

    token_admin_client.mint(&depositor, &1000);

    let bounty_id_1: u64 = 1;
    let deadline = env.ledger().timestamp() + 1000;
    escrow_client.lock_funds(&depositor, &bounty_id_1, &100, &deadline);

    escrow_client.set_paused(&Some(true), &None, &None, &None);
    let flags = escrow_client.get_pause_flags();
    assert!(flags.lock_paused);

    let bounty_id_2: u64 = 2;
    let res = escrow_client.try_lock_funds(&depositor, &bounty_id_2, &100, &deadline);
    assert!(res.is_err());

    escrow_client.set_paused(&Some(false), &None, &None, &None);
    let flags = escrow_client.get_pause_flags();
    assert!(!flags.lock_paused);

    escrow_client.lock_funds(&depositor, &bounty_id_2, &100, &deadline);
}

#[test]
fn test_granular_pause_release() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let token_admin = Address::generate(&env);

    let (token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    let (escrow_client, _) = create_escrow_contract(&env);

    escrow_client.init(&admin, &token_client.address);
    token_admin_client.mint(&depositor, &1000);

    let bounty_id: u64 = 1;
    let deadline = env.ledger().timestamp() + 1000;
    escrow_client.lock_funds(&depositor, &bounty_id, &100, &deadline);

    escrow_client.set_paused(&None, &Some(true), &None, &None);
    let flags = escrow_client.get_pause_flags();
    assert!(flags.release_paused);

    let res = escrow_client.try_release_funds(&bounty_id, &contributor);
    assert!(res.is_err());

    escrow_client.set_paused(&None, &Some(false), &None, &None);
    let flags = escrow_client.get_pause_flags();
    assert!(!flags.release_paused);

    escrow_client.release_funds(&bounty_id, &contributor);
}

#[test]
fn test_granular_pause_refund() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let token_admin = Address::generate(&env);

    let (token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    let (escrow_client, _) = create_escrow_contract(&env);

    escrow_client.init(&admin, &token_client.address);
    token_admin_client.mint(&depositor, &1000);

    let bounty_id: u64 = 1;
    let deadline = env.ledger().timestamp() + 1000;

    escrow_client.lock_funds(&depositor, &bounty_id, &100, &deadline);

    env.ledger().set_timestamp(deadline + 1);

    escrow_client.set_paused(&None, &None, &Some(true), &None);
    let flags = escrow_client.get_pause_flags();
    assert!(flags.refund_paused);

    let res = escrow_client.try_refund(&bounty_id);
    assert!(res.is_err());

    escrow_client.set_paused(&None, &None, &Some(false), &None);
    let flags = escrow_client.get_pause_flags();
    assert!(!flags.refund_paused);

    escrow_client.refund(&bounty_id);
}

#[test]
fn test_mixed_pause_states() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (token_client, _) = create_token_contract(&env, &admin);
    let (escrow_client, _) = create_escrow_contract(&env);

    escrow_client.init(&admin, &token_client.address);

    escrow_client.set_paused(&Some(true), &Some(true), &Some(false), &None);
    let flags = escrow_client.get_pause_flags();
    assert!(flags.lock_paused);
    assert!(flags.release_paused);
    assert!(!flags.refund_paused);

    escrow_client.set_paused(&None, &Some(false), &None, &None);
    let flags = escrow_client.get_pause_flags();
    assert!(flags.lock_paused);
    assert!(!flags.release_paused);
    assert!(!flags.refund_paused);
}

#[test]
fn test_batch_lock_funds_while_paused_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let token_admin = Address::generate(&env);

    let (token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    let (escrow_client, _) = create_escrow_contract(&env);

    escrow_client.init(&admin, &token_client.address);
    token_admin_client.mint(&depositor, &1000);

    // Pause locks
    escrow_client.set_paused(&Some(true), &None, &None, &None);

    let deadline = env.ledger().timestamp() + 1000;
    let items = soroban_sdk::vec![
        &env,
        LockFundsItem {
            bounty_id: 1,
            amount: 100,
            depositor: depositor.clone(),
            deadline,
        },
        LockFundsItem {
            bounty_id: 2,
            amount: 100,
            depositor: depositor.clone(),
            deadline,
        }
    ];

    let res = escrow_client.try_batch_lock_funds(&items);
    assert!(res.is_err());
}

#[test]
fn test_batch_release_funds_while_paused_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let token_admin = Address::generate(&env);

    let (token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    let (escrow_client, _) = create_escrow_contract(&env);

    escrow_client.init(&admin, &token_client.address);
    token_admin_client.mint(&depositor, &1000);

    let deadline = env.ledger().timestamp() + 1000;
    escrow_client.lock_funds(&depositor, &1u64, &100, &deadline);

    // Pause release
    escrow_client.set_paused(&None, &Some(true), &None, &None);

    let items = soroban_sdk::vec![
        &env,
        ReleaseFundsItem {
            bounty_id: 1,
            contributor: contributor.clone()
        }
    ];

    let res = escrow_client.try_batch_release_funds(&items);
    assert!(res.is_err());
}

#[test]
fn test_operations_resume_after_unpause() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let token_admin = Address::generate(&env);

    let (token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    let (escrow_client, _) = create_escrow_contract(&env);

    escrow_client.init(&admin, &token_client.address);
    token_admin_client.mint(&depositor, &1000);

    // Pause everything
    escrow_client.set_paused(&Some(true), &Some(true), &Some(true), &None);

    let deadline = env.ledger().timestamp() + 1000;
    let res_lock = escrow_client.try_lock_funds(&depositor, &1u64, &100, &deadline);
    assert!(res_lock.is_err());

    // Unpause lock
    escrow_client.set_paused(&Some(false), &None, &None, &None);

    // Now it works
    escrow_client.lock_funds(&depositor, &1u64, &100, &deadline);

    // Release still paused though
    let contributor = Address::generate(&env);
    let res_release = escrow_client.try_release_funds(&1u64, &contributor);
    assert!(res_release.is_err());

    // Unpause release
    escrow_client.set_paused(&None, &Some(false), &None, &None);

    // Now release works
    escrow_client.release_funds(&1u64, &contributor);
}

#[test]
fn test_lock_funds_while_paused_no_state_change() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let token_admin = Address::generate(&env);

    let (token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    let (escrow_client, _) = create_escrow_contract(&env);

    escrow_client.init(&admin, &token_client.address);
    token_admin_client.mint(&depositor, &1000);

    escrow_client.set_paused(&Some(true), &None, &None, &None);

    let deadline = env.ledger().timestamp() + 1000;
    let _ = escrow_client.try_lock_funds(&depositor, &1u64, &100, &deadline);

    // Verify token balance didn't change and escrow wasn't created
    assert_eq!(token_client.balance(&depositor), 1000);
    assert!(escrow_client.try_get_escrow_info(&1u64).is_err());
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn test_emergency_withdraw_non_admin_fails() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let (token_client, _) = create_token_contract(&env, &admin);
    let (escrow_client, _) = create_escrow_contract(&env);

    let target = Address::generate(&env);
    escrow_client.init(&admin, &token_client.address);
    escrow_client.emergency_withdraw(&target);
}

#[test]
#[should_panic(expected = "Error(Contract, #21)")]
fn test_emergency_withdraw_unpaused_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let (token_client, _) = create_token_contract(&env, &admin);
    let (escrow_client, _) = create_escrow_contract(&env);
    let target = Address::generate(&env);

    escrow_client.init(&admin, &token_client.address);
    escrow_client.emergency_withdraw(&target);
}

#[test]
fn test_emergency_withdraw_succeeds() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let (token_client, token_admin_client) = create_token_contract(&env, &admin);
    let (escrow_client, _) = create_escrow_contract(&env);
    let target = Address::generate(&env);

    escrow_client.init(&admin, &token_client.address);
    token_admin_client.mint(&depositor, &1000);

    let deadline = env.ledger().timestamp() + 1000;
    escrow_client.lock_funds(&depositor, &1u64, &500i128, &deadline);

    assert_eq!(token_client.balance(&escrow_client.address), 500);

    let reason = soroban_sdk::String::from_str(&env, "Hacked");
    escrow_client.set_paused(&Some(true), &None, &None, &Some(reason));

    escrow_client.emergency_withdraw(&target);

    assert_eq!(token_client.balance(&escrow_client.address), 0);
    assert_eq!(token_client.balance(&target), 500);
}

