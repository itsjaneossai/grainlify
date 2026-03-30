#![cfg(test)]
//! Tests for two-step (propose/accept) ownership transfer on the program-escrow contract.
//! Covers both contract-level admin transfer and per-program admin transfer.

extern crate std;
use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, Address, Env, String};

// ── helpers ─────────────────────────────────────────────────────────────────

macro_rules! setup_ownership {
    ($env:ident, $client:ident, $admin:ident, $program_admin:ident,
     $token_admin:ident, $initial_balance:expr) => {
        let $env = Env::default();
        $env.mock_all_auths();

        let contract_id = $env.register(ProgramEscrowContract, ());
        let $client = ProgramEscrowContractClient::new(&$env, &contract_id);

        let $admin = Address::generate(&$env);
        let $program_admin = Address::generate(&$env);

        let token_contract = $env.register_stellar_asset_contract_v2($admin.clone());
        let token_addr = token_contract.address();
        let $token_admin = token::StellarAssetClient::new(&$env, &token_addr);

        let _ = $client.init(&$admin, &token_addr);
        $token_admin.mint(&$program_admin, &$initial_balance);
    };
}

// ══════════════════════════════════════════════════════════════════════════════
//  CONTRACT-LEVEL ADMIN TRANSFER
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_contract_propose_and_accept_ownership() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 10_000i128);
    let new_owner = Address::generate(&env);

    assert!(client.get_pending_owner().is_none());

    client.propose_transfer_ownership(&new_owner);
    assert_eq!(client.get_pending_owner(), Some(new_owner.clone()));

    client.accept_transfer_ownership();
    assert!(client.get_pending_owner().is_none());

    // Verify new owner has admin powers by proposing another transfer
    let another = Address::generate(&env);
    client.propose_transfer_ownership(&another);
    assert_eq!(client.get_pending_owner(), Some(another));
}

#[test]
fn test_contract_cancel_ownership_proposal() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 10_000i128);
    let new_owner = Address::generate(&env);

    client.propose_transfer_ownership(&new_owner);
    assert!(client.get_pending_owner().is_some());

    client.cancel_transfer_ownership();
    assert!(client.get_pending_owner().is_none());
}

#[test]
fn test_contract_overwrite_pending_proposal() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 10_000i128);
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    client.propose_transfer_ownership(&first);
    assert_eq!(client.get_pending_owner(), Some(first));

    client.propose_transfer_ownership(&second);
    assert_eq!(client.get_pending_owner(), Some(second));
}

#[test]
fn test_contract_accept_without_proposal_fails() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 10_000i128);
    let res = client.try_accept_transfer_ownership();
    assert!(res.is_err());
}

#[test]
fn test_contract_cancel_without_proposal_fails() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 10_000i128);
    let res = client.try_cancel_transfer_ownership();
    assert!(res.is_err());
}

// ══════════════════════════════════════════════════════════════════════════════
//  PER-PROGRAM ADMIN TRANSFER
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_program_propose_and_accept_ownership() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 50_000i128);
    let name = String::from_str(&env, "Grant Round");
    client.register_program(&1, &program_admin, &name, &5_000);

    let new_admin = Address::generate(&env);

    assert!(client.get_pending_program_admin(&1).is_none());

    client.propose_program_transfer(&1, &new_admin);
    assert_eq!(
        client.get_pending_program_admin(&1),
        Some(new_admin.clone())
    );

    client.accept_program_transfer(&1);
    assert!(client.get_pending_program_admin(&1).is_none());

    // Verify the program admin was updated
    let program = client.get_program(&1);
    assert_eq!(program.admin, new_admin);
}

#[test]
fn test_program_cancel_ownership_proposal() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 50_000i128);
    let name = String::from_str(&env, "Grant Round");
    client.register_program(&1, &program_admin, &name, &5_000);

    let new_admin = Address::generate(&env);
    client.propose_program_transfer(&1, &new_admin);
    assert!(client.get_pending_program_admin(&1).is_some());

    client.cancel_program_transfer(&1);
    assert!(client.get_pending_program_admin(&1).is_none());

    // Program admin unchanged
    let program = client.get_program(&1);
    assert_eq!(program.admin, program_admin);
}

#[test]
fn test_program_accept_without_proposal_fails() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 50_000i128);
    let name = String::from_str(&env, "Grant Round");
    client.register_program(&1, &program_admin, &name, &5_000);

    let res = client.try_accept_program_transfer(&1);
    assert!(res.is_err());
}

#[test]
fn test_program_cancel_without_proposal_fails() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 50_000i128);
    let name = String::from_str(&env, "Grant Round");
    client.register_program(&1, &program_admin, &name, &5_000);

    let res = client.try_cancel_program_transfer(&1);
    assert!(res.is_err());
}

#[test]
fn test_program_transfer_not_found_fails() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 50_000i128);

    let new_admin = Address::generate(&env);
    let res = client.try_propose_program_transfer(&999, &new_admin);
    assert!(res.is_err());
}

#[test]
fn test_program_overwrite_pending_proposal() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 50_000i128);
    let name = String::from_str(&env, "Grant Round");
    client.register_program(&1, &program_admin, &name, &5_000);

    let first = Address::generate(&env);
    let second = Address::generate(&env);

    client.propose_program_transfer(&1, &first);
    assert_eq!(client.get_pending_program_admin(&1), Some(first));

    client.propose_program_transfer(&1, &second);
    assert_eq!(client.get_pending_program_admin(&1), Some(second));
}

// ══════════════════════════════════════════════════════════════════════════════
//  ISOLATION: per-program transfers are independent
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_program_transfers_independent_across_programs() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 100_000i128);
    let name_a = String::from_str(&env, "Program A");
    let name_b = String::from_str(&env, "Program B");
    client.register_program(&1, &program_admin, &name_a, &5_000);
    client.register_program(&2, &program_admin, &name_b, &5_000);

    let new_admin_a = Address::generate(&env);
    let new_admin_b = Address::generate(&env);

    // Propose for program 1 only
    client.propose_program_transfer(&1, &new_admin_a);
    assert!(client.get_pending_program_admin(&1).is_some());
    assert!(client.get_pending_program_admin(&2).is_none());

    // Propose for program 2 separately
    client.propose_program_transfer(&2, &new_admin_b);

    // Accept program 1 — program 2 still pending
    client.accept_program_transfer(&1);
    assert!(client.get_pending_program_admin(&1).is_none());
    assert!(client.get_pending_program_admin(&2).is_some());

    // Verify admins
    assert_eq!(client.get_program(&1).admin, new_admin_a);
    assert_eq!(client.get_program(&2).admin, program_admin); // still original

    // Accept program 2
    client.accept_program_transfer(&2);
    assert_eq!(client.get_program(&2).admin, new_admin_b);
}

// ══════════════════════════════════════════════════════════════════════════════
//  EXISTING OPERATIONS AFTER TRANSFER
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_new_program_admin_can_update_labels() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 50_000i128);
    let name = String::from_str(&env, "Grant Round");
    client.register_program(&1, &program_admin, &name, &5_000);

    let new_admin = Address::generate(&env);
    client.propose_program_transfer(&1, &new_admin);
    client.accept_program_transfer(&1);

    // New admin should be able to update labels
    let labels = soroban_sdk::vec![&env, String::from_str(&env, "defi")];
    let updated = client.update_program_labels(&new_admin, &1, &labels);
    assert_eq!(updated.labels.len(), 1);
}

#[test]
fn test_contract_operations_work_after_admin_transfer() {
    setup_ownership!(env, client, admin, program_admin, token_admin, 100_000i128);

    // Transfer contract-level admin
    let new_contract_admin = Address::generate(&env);
    client.propose_transfer_ownership(&new_contract_admin);
    client.accept_transfer_ownership();

    // New contract admin can register programs
    let new_program_admin = Address::generate(&env);
    token_admin.mint(&new_program_admin, &50_000);
    let name = String::from_str(&env, "Post-Transfer Program");
    client.register_program(&42, &new_program_admin, &name, &5_000);

    let program = client.get_program(&42);
    assert_eq!(program.admin, new_program_admin);
    assert_eq!(program.status, ProgramStatus::Active);
}
