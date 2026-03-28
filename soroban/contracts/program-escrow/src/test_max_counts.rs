#![cfg(test)]
//! Stress tests for maximum program counts.
//!
//! Ensures that `get_program_count()`, `get_program()`, and `get_programs()`
//! remain accurate without index or key collisions as many programs are
//! registered across sequential batches, up to practical CI limits.

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, Address, Env, String};

macro_rules! setup_max {
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

// ==================== COUNT ACCURACY ====================

/// Register 5 batches of 20 programs each (100 total, the practical CI limit).
/// After each batch, assert that `get_program_count()` equals the running total.
/// After all batches, spot-check that a sample of programs are retrievable
/// with the correct status, and verify the token balance transferred matches.
#[test]
fn test_max_programs_count_across_sequential_batches() {
    // 100 programs × 100 tokens each = 10_000 total
    setup_max!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        10_000i128
    );

    let batches: u64 = 5;
    let batch_size: u64 = 20;

    for batch in 0..batches {
        let mut items = Vec::new(&env);
        for i in 0..batch_size {
            let program_id = batch * batch_size + i + 1;
            items.push_back(ProgramRegistrationItem {
                program_id,
                admin: program_admin.clone(),
                name: String::from_str(&env, "Max Program"),
                total_funding: 100,
            });
        }
        let registered = client.batch_register_programs(&items);
        assert_eq!(registered, batch_size as u32);

        let expected_total = ((batch + 1) * batch_size) as u32;
        assert_eq!(client.get_program_count(), expected_total);
    }

    // Final count must equal all 100 programs
    assert_eq!(client.get_program_count(), 100);

    // Spot-check a spread of program IDs
    for id in [1u64, 20, 21, 50, 80, 100] {
        let p = client.get_program(&id);
        assert_eq!(p.status, ProgramStatus::Active);
        assert_eq!(p.admin, program_admin);
        assert_eq!(p.total_funding, 100);
    }

    // All tokens transferred: 100 programs × 100 = 10_000
    assert_eq!(token_client.balance(&contract_id), 10_000);
    assert_eq!(token_client.balance(&program_admin), 0);
}

// ==================== PAGINATION WITHOUT COLLISION ====================

/// Register 60 programs across 3 batches of 20, then paginate exhaustively
/// through all results using `get_programs` with a page size of 20.
///
/// Verifies:
/// - Exactly 3 pages are produced.
/// - All 60 program IDs appear across the pages (none missing).
/// - No program ID appears more than once (no index/key collision).
/// - `has_more` and `next_cursor` are consistent across pages.
#[test]
fn test_max_programs_paginate_exhaustively() {
    // 60 programs × 100 tokens each = 6_000 total
    setup_max!(
        env,
        client,
        _contract_id,
        admin,
        program_admin,
        _token_client,
        token_admin,
        6_000i128
    );

    let total: u64 = 60;
    let batch_size: u64 = 20;

    for batch in 0..(total / batch_size) {
        let mut items = Vec::new(&env);
        for i in 0..batch_size {
            let program_id = batch * batch_size + i + 1;
            items.push_back(ProgramRegistrationItem {
                program_id,
                admin: program_admin.clone(),
                name: String::from_str(&env, "Paginate Program"),
                total_funding: 100,
            });
        }
        client.batch_register_programs(&items);
    }

    assert_eq!(client.get_program_count(), total as u32);

    let criteria = ProgramSearchCriteria {
        status_filter: 0,
        admin: None,
    };

    // Paginate through all records and collect every program_id seen
    let mut seen_ids: Vec<u64> = Vec::new(&env);
    let mut cursor: Option<u64> = None;
    let mut pages: u32 = 0;

    loop {
        let page = client.get_programs(&criteria, &cursor, &20);
        pages += 1;

        for record in page.records.iter() {
            seen_ids.push_back(record.program_id);
        }

        if page.has_more {
            assert!(page.next_cursor.is_some());
            cursor = page.next_cursor;
        } else {
            assert_eq!(page.next_cursor, None);
            break;
        }
    }

    // Exactly 3 full pages of 20 programs each
    assert_eq!(pages, 3);

    // All 60 programs were returned by pagination
    assert_eq!(seen_ids.len(), total as u32);

    // Each ID from 1..=60 appears exactly once — no collisions
    for expected_id in 1u64..=total {
        let mut count = 0u32;
        for id in seen_ids.iter() {
            if id == expected_id {
                count += 1;
            }
        }
        assert_eq!(count, 1);
    }
}

// ==================== SAMPLING QUERIES ====================

/// Register 60 programs where each program's `total_funding` equals its
/// `program_id * 10`. Then retrieve 5 spot-sampled programs directly via
/// `get_program()` and verify the stored data is intact.
///
/// This guards against key collisions corrupting individual program records.
#[test]
fn test_max_programs_sampling_queries() {
    // Total funding: sum(id * 10 for id in 1..=60)
    // = 10 * (1+2+...+60) = 10 * 1830 = 18_300
    setup_max!(
        env,
        client,
        contract_id,
        admin,
        program_admin,
        token_client,
        token_admin,
        18_300i128
    );

    let batch_size: u64 = 20;
    for batch in 0..3u64 {
        let mut items = Vec::new(&env);
        for i in 0..batch_size {
            let program_id = batch * batch_size + i + 1;
            let funding = (program_id * 10) as i128;
            items.push_back(ProgramRegistrationItem {
                program_id,
                admin: program_admin.clone(),
                name: String::from_str(&env, "Sampled"),
                total_funding: funding,
            });
        }
        client.batch_register_programs(&items);
    }

    assert_eq!(client.get_program_count(), 60);

    // Spot-check 5 programs spread across all 3 batches
    for id in [1u64, 15, 30, 45, 60] {
        let p = client.get_program(&id);
        assert_eq!(p.admin, program_admin);
        assert_eq!(p.total_funding, (id * 10) as i128);
        assert_eq!(p.status, ProgramStatus::Active);
        assert_eq!(p.name, String::from_str(&env, "Sampled"));
    }

    // Total tokens held by contract = 10 * 1830 = 18_300
    assert_eq!(token_client.balance(&contract_id), 18_300);
}

// ==================== COUNT STABILITY UNDER FAILURE ====================

/// Verify that a failed batch registration does not corrupt the program count.
///
/// Steps:
/// 1. Register 20 programs successfully — count = 20.
/// 2. Attempt a batch that contains a duplicate program_id — must fail.
/// 3. Count must still be 20 and the new program_id must not exist.
#[test]
fn test_max_programs_count_unaffected_by_failed_batch() {
    setup_max!(
        env,
        client,
        _contract_id,
        admin,
        program_admin,
        _token_client,
        token_admin,
        10_000i128
    );

    // First: register 20 programs cleanly
    let mut good_items = Vec::new(&env);
    for id in 1..=20u64 {
        good_items.push_back(ProgramRegistrationItem {
            program_id: id,
            admin: program_admin.clone(),
            name: String::from_str(&env, "Good Program"),
            total_funding: 100,
        });
    }
    let registered = client.batch_register_programs(&good_items);
    assert_eq!(registered, 20);
    assert_eq!(client.get_program_count(), 20);

    // Attempt a batch that includes program_id 1 (already registered)
    let mut bad_items = Vec::new(&env);
    bad_items.push_back(ProgramRegistrationItem {
        program_id: 21,
        admin: program_admin.clone(),
        name: String::from_str(&env, "New"),
        total_funding: 100,
    });
    bad_items.push_back(ProgramRegistrationItem {
        program_id: 1, // collision with existing
        admin: program_admin.clone(),
        name: String::from_str(&env, "Collision"),
        total_funding: 100,
    });

    let res = client.try_batch_register_programs(&bad_items);
    assert!(res.is_err());

    // Count must remain exactly 20
    assert_eq!(client.get_program_count(), 20);

    // program_id 21 must not exist (atomicity)
    let lookup = client.try_get_program(&21);
    assert!(lookup.is_err());
}
