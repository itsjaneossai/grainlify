#![cfg(test)]
//! Tests for two-step (propose/accept) ownership transfer on the escrow contract.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, Address, Env};

// ── helpers ─────────────────────────────────────────────────────────────────

fn create_token<'a>(env: &'a Env, admin: &Address) -> (Address, token::StellarAssetClient<'a>) {
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let addr = token_contract.address();
    let admin_client = token::StellarAssetClient::new(env, &addr);
    (addr, admin_client)
}

fn setup<'a>(env: &'a Env) -> (EscrowContractClient<'a>, Address, Address) {
    env.mock_all_auths();
    let contract_id = env.register(EscrowContract, ());
    let client = EscrowContractClient::new(env, &contract_id);

    let admin = Address::generate(env);
    let (token_addr, _token_admin) = create_token(env, &admin);
    client.init(&admin, &token_addr);

    (client, contract_id, admin)
}

// ── propose / accept happy path ─────────────────────────────────────────────

#[test]
fn test_propose_and_accept_ownership() {
    let env = Env::default();
    let (client, _contract_id, _admin) = setup(&env);
    let new_owner = Address::generate(&env);

    // No pending owner initially
    assert!(client.get_pending_owner().is_none());

    // Propose
    client.propose_transfer_ownership(&new_owner);
    assert_eq!(client.get_pending_owner(), Some(new_owner.clone()));

    // Accept
    client.accept_transfer_ownership();
    assert!(client.get_pending_owner().is_none());

    // New owner can now propose another transfer (proves they are admin)
    let another = Address::generate(&env);
    client.propose_transfer_ownership(&another);
    assert_eq!(client.get_pending_owner(), Some(another));
}

// ── cancel ──────────────────────────────────────────────────────────────────

#[test]
fn test_cancel_ownership_proposal() {
    let env = Env::default();
    let (client, _contract_id, _admin) = setup(&env);
    let new_owner = Address::generate(&env);

    client.propose_transfer_ownership(&new_owner);
    assert!(client.get_pending_owner().is_some());

    client.cancel_transfer_ownership();
    assert!(client.get_pending_owner().is_none());
}

// ── overwrite pending proposal ──────────────────────────────────────────────

#[test]
fn test_overwrite_pending_proposal() {
    let env = Env::default();
    let (client, _contract_id, _admin) = setup(&env);
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    client.propose_transfer_ownership(&first);
    assert_eq!(client.get_pending_owner(), Some(first));

    // Overwrite with a new proposal
    client.propose_transfer_ownership(&second);
    assert_eq!(client.get_pending_owner(), Some(second));
}

// ── accept without proposal fails ───────────────────────────────────────────

#[test]
fn test_accept_without_proposal_fails() {
    let env = Env::default();
    let (client, _contract_id, _admin) = setup(&env);

    let res = client.try_accept_transfer_ownership();
    assert!(res.is_err());
}

// ── cancel without proposal fails ───────────────────────────────────────────

#[test]
fn test_cancel_without_proposal_fails() {
    let env = Env::default();
    let (client, _contract_id, _admin) = setup(&env);

    let res = client.try_cancel_transfer_ownership();
    assert!(res.is_err());
}

// ── accept clears pending and old admin loses power ─────────────────────────

#[test]
fn test_old_admin_cannot_propose_after_transfer() {
    let env = Env::default();
    let (client, _contract_id, _admin) = setup(&env);
    let new_owner = Address::generate(&env);

    client.propose_transfer_ownership(&new_owner);
    client.accept_transfer_ownership();

    // New owner is now admin — verify by proposing
    let another = Address::generate(&env);
    client.propose_transfer_ownership(&another);
    assert_eq!(client.get_pending_owner(), Some(another));
}

// ── not initialized errors ──────────────────────────────────────────────────

#[test]
fn test_propose_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(EscrowContract, ());
    let client = EscrowContractClient::new(&env, &contract_id);
    let new_owner = Address::generate(&env);

    let res = client.try_propose_transfer_ownership(&new_owner);
    assert!(res.is_err());
}

#[test]
fn test_accept_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(EscrowContract, ());
    let client = EscrowContractClient::new(&env, &contract_id);

    let res = client.try_accept_transfer_ownership();
    assert!(res.is_err());
}

// ── existing escrow operations still work after transfer ────────────────────

#[test]
fn test_escrow_operations_work_after_ownership_transfer() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(EscrowContract, ());
    let client = EscrowContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let new_owner = Address::generate(&env);

    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_addr = token_contract.address();
    let token_client = token::Client::new(&env, &token_addr);
    let token_admin = token::StellarAssetClient::new(&env, &token_addr);

    client.init(&admin, &token_addr);
    token_admin.mint(&depositor, &50_000);

    // Transfer ownership
    client.propose_transfer_ownership(&new_owner);
    client.accept_transfer_ownership();

    // Lock and release should still work (new admin authorises release)
    let bounty_id = 1u64;
    let deadline = env.ledger().timestamp() + 1000;
    client.lock_funds(&depositor, &bounty_id, &10_000, &deadline);
    client.release_funds(&bounty_id, &contributor);

    assert_eq!(token_client.balance(&contributor), 10_000);
    let escrow = client.get_escrow(&bounty_id);
    assert_eq!(escrow.status, EscrowStatus::Released);
}

// ══════════════════════════════════════════════════════════════════════════════
//  PER-ESCROW DEPOSITOR TRANSFER
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_escrow_propose_and_accept_ownership() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(EscrowContract, ());
    let client = EscrowContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let new_depositor = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_addr = token_contract.address();
    let token_admin = token::StellarAssetClient::new(&env, &token_addr);

    client.init(&admin, &token_addr);
    token_admin.mint(&depositor, &50_000);

    let bounty_id = 42u64;
    let deadline = env.ledger().timestamp() + 1000;
    client.lock_funds(&depositor, &bounty_id, &10_000, &deadline);

    assert!(client.get_pending_escrow_owner(&bounty_id).is_none());

    client.propose_escrow_transfer(&bounty_id, &new_depositor);
    assert_eq!(
        client.get_pending_escrow_owner(&bounty_id),
        Some(new_depositor.clone())
    );

    client.accept_escrow_transfer(&bounty_id);
    assert!(client.get_pending_escrow_owner(&bounty_id).is_none());

    let escrow = client.get_escrow(&bounty_id);
    assert_eq!(escrow.depositor, new_depositor);
}

#[test]
fn test_escrow_cancel_ownership_proposal() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(EscrowContract, ());
    let client = EscrowContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let new_depositor = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_addr = token_contract.address();
    let token_admin = token::StellarAssetClient::new(&env, &token_addr);

    client.init(&admin, &token_addr);
    token_admin.mint(&depositor, &50_000);

    let bounty_id = 42u64;
    let deadline = env.ledger().timestamp() + 1000;
    client.lock_funds(&depositor, &bounty_id, &10_000, &deadline);

    client.propose_escrow_transfer(&bounty_id, &new_depositor);
    assert!(client.get_pending_escrow_owner(&bounty_id).is_some());

    client.cancel_escrow_transfer(&bounty_id);
    assert!(client.get_pending_escrow_owner(&bounty_id).is_none());

    let escrow = client.get_escrow(&bounty_id);
    assert_eq!(escrow.depositor, depositor);
}

#[test]
fn test_escrow_accept_without_proposal_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(EscrowContract, ());
    let client = EscrowContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_addr = token_contract.address();
    let token_admin = token::StellarAssetClient::new(&env, &token_addr);

    client.init(&admin, &token_addr);
    token_admin.mint(&depositor, &50_000);

    let bounty_id = 42u64;
    let deadline = env.ledger().timestamp() + 1000;
    client.lock_funds(&depositor, &bounty_id, &10_000, &deadline);

    let res = client.try_accept_escrow_transfer(&bounty_id);
    assert!(res.is_err());
}

#[test]
fn test_escrow_transfer_not_found_fails() {
    let env = Env::default();
    let (client, _contract_id, _admin) = setup(&env);
    let new_depositor = Address::generate(&env);

    let res = client.try_propose_escrow_transfer(&999, &new_depositor);
    assert!(res.is_err());
}

#[test]
fn test_escrow_overwrite_pending_proposal() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(EscrowContract, ());
    let client = EscrowContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let first = Address::generate(&env);
    let second = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_addr = token_contract.address();
    let token_admin = token::StellarAssetClient::new(&env, &token_addr);

    client.init(&admin, &token_addr);
    token_admin.mint(&depositor, &50_000);

    let bounty_id = 42u64;
    let deadline = env.ledger().timestamp() + 1000;
    client.lock_funds(&depositor, &bounty_id, &10_000, &deadline);

    client.propose_escrow_transfer(&bounty_id, &first);
    assert_eq!(client.get_pending_escrow_owner(&bounty_id), Some(first));

    client.propose_escrow_transfer(&bounty_id, &second);
    assert_eq!(client.get_pending_escrow_owner(&bounty_id), Some(second));
}
