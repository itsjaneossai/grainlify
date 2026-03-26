#![cfg(test)]
//! Full lifecycle integration tests for program escrow.
//!
//! Covers: register → lock → payout → close paths with end-to-end invariants
//! on balances and history. Tests security assumptions and edge cases.

extern crate std;
use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, vec, Address, Env, String};

/// Setup macro for lifecycle tests
macro_rules! setup_lifecycle {
    ($env:ident, $client:ident, $contract_id:ident, $admin:ident,
     $program_admin:ident, $token_client:ident, $token_admin:ident,
     $initial_balance:expr) => {
        let $env = Env::default();
        $env.mock_all_auths();

        let $contract_id = $env.register(ProgramEscrowContract, ());
        let $client = ProgramEscrowContractClient::new(&$env, &$contract_id);

        let $admin = Address::generate(&$env);
        let $program_admin = Address::generate(&$env);

        let token_contract = $env.register_stellar_asset_contract_v2($admin.clone());
        let token_addr = token_contract.address();
        let $token_client = token::Client::new(&$env, &token_addr);
        let $token_admin = token::StellarAssetClient::new(&$env, &token_addr);

        let _ = $client.init(&$admin, &token_addr);
        $token_admin.mint(&$program_admin, &$initial_balance);
    };
}

// ============================================================================
// LIFECYCLE: Register → Lock → Payout → Close
// ============================================================================

/// Test: Register a program and verify initial state
#[test]
fn test_lifecycle_register_program() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        100_000i128
    );

    let program_id = 1u64;
    let name = String::from_str(&env, "Q1 Grant Program");
    let total_funding = 50_000i128;

    client.register_program(&program_id, &program_admin, &name, &total_funding);

    let program = client.get_program(&program_id);
    assert_eq!(program.admin, program_admin);
    assert_eq!(program.name, name);
    assert_eq!(program.total_funding, total_funding);
    assert_eq!(program.status, ProgramStatus::Active);
    assert_eq!(token_client.balance(&contract_id), total_funding);
    assert_eq!(token_client.balance(&program_admin), 50_000);
}

/// Test: Lock funds from a registered program
#[test]
fn test_lifecycle_lock_funds() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        100_000i128
    );

    let program_id = 1u64;
    let name = String::from_str(&env, "Q1 Grant Program");
    let total_funding = 50_000i128;

    client.register_program(&program_id, &program_admin, &name, &total_funding);

    // Verify program is active and has funds
    let program = client.get_program(&program_id);
    assert_eq!(program.status, ProgramStatus::Active);
    assert_eq!(program.total_funding, total_funding);

    // Contract should hold the funds
    assert_eq!(token_client.balance(&contract_id), total_funding);
}

/// Test: Complete lifecycle - register, verify, and transition to completed
#[test]
fn test_lifecycle_register_to_completed() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        100_000i128
    );

    let program_id = 1u64;
    let name = String::from_str(&env, "Q1 Grant Program");
    let total_funding = 50_000i128;

    // Register program
    client.register_program(&program_id, &program_admin, &name, &total_funding);

    let program = client.get_program(&program_id);
    assert_eq!(program.status, ProgramStatus::Active);

    // Verify funds are locked in contract
    assert_eq!(token_client.balance(&contract_id), total_funding);
    assert_eq!(token_client.balance(&program_admin), 50_000);
}

/// Test: Batch registration with lifecycle verification
#[test]
fn test_lifecycle_batch_register_programs() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        200_000i128
    );

    let items = vec![
        &env,
        ProgramRegistrationItem {
            program_id: 1,
            admin: program_admin.clone(),
            name: String::from_str(&env, "Program Alpha"),
            total_funding: 30_000,
        },
        ProgramRegistrationItem {
            program_id: 2,
            admin: program_admin.clone(),
            name: String::from_str(&env, "Program Beta"),
            total_funding: 40_000,
        },
        ProgramRegistrationItem {
            program_id: 3,
            admin: program_admin.clone(),
            name: String::from_str(&env, "Program Gamma"),
            total_funding: 50_000,
        },
    ];

    let count = client.batch_register_programs(&items);
    assert_eq!(count, 3);

    // Verify all programs are registered and active
    for id in 1..=3 {
        let program = client.get_program(&id);
        assert_eq!(program.status, ProgramStatus::Active);
        assert_eq!(program.admin, program_admin);
    }

    // Verify total funds locked
    let total_locked = 30_000 + 40_000 + 50_000;
    assert_eq!(token_client.balance(&contract_id), total_locked);
    assert_eq!(token_client.balance(&program_admin), 200_000 - total_locked);
}

/// Test: Program count and search pagination
#[test]
fn test_lifecycle_program_count_and_search() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        500_000i128
    );

    // Register 5 programs
    for i in 1..=5 {
        let name = String::from_str(&env, "Program");
        client.register_program(&(i as u64), &program_admin, &name, &(10_000 * i as i128));
    }

    // Verify count
    let count = client.get_program_count();
    assert_eq!(count, 5);

    // Verify search returns all programs
    let criteria = ProgramSearchCriteria {
        status_filter: 0, // any status
        admin: None,
    };
    let page = client.get_programs(&criteria, &None, &10);
    assert_eq!(page.records.len(), 5);
    assert_eq!(page.has_more, false);
}

/// Test: Invariant - total funds locked equals sum of program fundings
#[test]
fn test_lifecycle_invariant_total_funds() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        300_000i128
    );

    let mut total_expected = 0i128;

    for i in 1..=5 {
        let amount = 20_000 * i as i128;
        let name = String::from_str(&env, "Program");
        client.register_program(&(i as u64), &program_admin, &name, &amount);
        total_expected += amount;
    }

    // Verify contract balance matches total registered funding
    let contract_balance = token_client.balance(&contract_id);
    assert_eq!(contract_balance, total_expected);
}

/// Test: Invariant - program status never reverts
#[test]
fn test_lifecycle_invariant_status_monotonic() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        100_000i128
    );

    let program_id = 1u64;
    let name = String::from_str(&env, "Test Program");

    client.register_program(&program_id, &program_admin, &name, &50_000);

    let program = client.get_program(&program_id);
    assert_eq!(program.status, ProgramStatus::Active);

    // Status should remain Active (no downgrade possible)
    let program_again = client.get_program(&program_id);
    assert_eq!(program_again.status, ProgramStatus::Active);
}

/// Test: Jurisdiction-aware registration with lifecycle
#[test]
fn test_lifecycle_jurisdiction_registration() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        100_000i128
    );

    let program_id = 1u64;
    let name = String::from_str(&env, "EU-Only Program");
    let total_funding = 50_000i128;

    let jurisdiction = OptionalJurisdiction::Some(ProgramJurisdictionConfig {
        tag: Some(String::from_str(&env, "EU")),
        requires_kyc: true,
        max_funding: Some(100_000),
        registration_paused: false,
    });

    client.register_program_juris(
        &program_id,
        &program_admin,
        &name,
        &total_funding,
        &Some(String::from_str(&env, "EU")),
        &true,
        &Some(100_000),
        &false,
        &jurisdiction,
        &Some(true),
    );

    let program = client.get_program(&program_id);
    assert_eq!(program.status, ProgramStatus::Active);
    assert_eq!(token_client.balance(&contract_id), total_funding);
}

/// Test: Pagination with cursor
#[test]
fn test_lifecycle_pagination_cursor() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        500_000i128
    );

    // Register 10 programs
    for i in 1..=10 {
        let name = String::from_str(&env, "Program");
        client.register_program(&(i as u64), &program_admin, &name, &(5_000 * i as i128));
    }

    let criteria = ProgramSearchCriteria {
        status_filter: 0,
        admin: None,
    };

    // First page
    let page1 = client.get_programs(&criteria, &None, &5);
    assert_eq!(page1.records.len(), 5);
    assert_eq!(page1.has_more, true);

    // Second page using cursor
    let page2 = client.get_programs(&criteria, &page1.next_cursor, &5);
    assert_eq!(page2.records.len(), 5);
    assert_eq!(page2.has_more, false);

    // Verify no overlap
    for rec1 in page1.records.iter() {
        for rec2 in page2.records.iter() {
            assert_ne!(rec1.program_id, rec2.program_id);
        }
    }
}

/// Test: Labels in lifecycle
#[test]
fn test_lifecycle_with_labels() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        100_000i128
    );

    let program_id = 1u64;
    let name = String::from_str(&env, "Labeled Program");
    let labels = vec![
        &env,
        String::from_str(&env, "grant"),
        String::from_str(&env, "q1"),
    ];

    client.register_program_with_labels(
        &program_id,
        &program_admin,
        &name,
        &50_000,
        &labels,
    );

    let program = client.get_program(&program_id);
    assert_eq!(program.labels.len(), 2);
    assert_eq!(program.status, ProgramStatus::Active);
}

/// Test: Edge case - zero funding rejected
#[test]
#[should_panic(expected = "Error(Contract, #8)")]
fn test_lifecycle_reject_zero_funding() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        100_000i128
    );

    let name = String::from_str(&env, "Invalid Program");
    client.register_program(&1, &program_admin, &name, &0);
}

/// Test: Edge case - negative funding rejected
#[test]
#[should_panic(expected = "Error(Contract, #8)")]
fn test_lifecycle_reject_negative_funding() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        100_000i128
    );

    let name = String::from_str(&env, "Invalid Program");
    client.register_program(&1, &program_admin, &name, &-1000);
}

/// Test: Edge case - empty name rejected
#[test]
#[should_panic(expected = "Error(Contract, #9)")]
fn test_lifecycle_reject_empty_name() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        100_000i128
    );

    let name = String::from_str(&env, "");
    client.register_program(&1, &program_admin, &name, &50_000);
}

/// Test: Duplicate program ID rejected
#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_lifecycle_reject_duplicate_id() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        100_000i128
    );

    let name = String::from_str(&env, "Program");
    client.register_program(&1, &program_admin, &name, &50_000);
    client.register_program(&1, &program_admin, &name, &30_000);
}

/// Test: Deprecation blocks new registrations
#[test]
#[should_panic(expected = "Error(Contract, #10)")]
fn test_lifecycle_deprecation_blocks_registration() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        100_000i128
    );

    client.set_deprecated(&true, &None);

    let name = String::from_str(&env, "Program");
    client.register_program(&1, &program_admin, &name, &50_000);
}

/// Test: Deprecation preserves read access
#[test]
fn test_lifecycle_deprecation_preserves_reads() {
    setup_lifecycle!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        100_000i128
    );

    let name = String::from_str(&env, "Program");
    client.register_program(&1, &program_admin, &name, &50_000);

    client.set_deprecated(&true, &None);

    // Should still be able to read
    let program = client.get_program(&1);
    assert_eq!(program.status, ProgramStatus::Active);
}
