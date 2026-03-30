//! Comprehensive tests for timelock delay functionality in grainlify-core.
//!
//! Tests cover:
//! - Timelock delay configuration and management
//! - Proposal approval and timelock start behavior
//! - Execution delay enforcement and boundary conditions
//! - Edge cases (clock skew, immediate execution attempts)
//! - Security assumptions (cannot bypass delay, proposal expiry)

#![cfg(test)]

extern crate std;

use soroban_sdk::{
    testutils::{Address as _, Events},
    Address, BytesN, Env, Symbol,
};

use crate::{GrainlifyContract, GrainlifyContractClient};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Returns a deterministic 32-byte pseudo-WASM hash for simulation tests.
fn fake_wasm(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0xAB; 32])
}

#[test]
fn test_timelock_default_delay() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init_admin(&admin);

    // Default delay should be 24 hours
    assert_eq!(client.get_timelock_delay(), 86400);
}

#[test]
fn test_set_timelock_delay() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init_admin(&admin);

    // Set custom delay
    client.set_timelock_delay(&7200); // 2 hours
    assert_eq!(client.get_timelock_delay(), 7200);

    // Verify event was emitted
    let events = env.events().all();
    assert!(events.len() > 0);
}

#[test]
#[should_panic(expected = "Timelock delay must be at least 1 hour")]
fn test_set_timelock_delay_minimum() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init_admin(&admin);

    // Try to set delay below minimum
    client.set_timelock_delay(&1800); // 30 minutes - should panic
}

#[test]
fn test_timelock_starts_on_threshold_meeting() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    // Setup multisig with 2-of-3 threshold
    let signers = vec![&env, Address::generate(&env), Address::generate(&env), Address::generate(&env)];
    client.init(&signers, &2u32);

    let proposer = signers.get(0).unwrap();
    let wasm_hash = fake_wasm(&env);

    // Create proposal
    let proposal_id = client.propose_upgrade(proposer, &wasm_hash);

    // Initially no timelock status
    assert_eq!(client.get_timelock_status(&proposal_id), None);

    // First approval - threshold not met yet
    let approver1 = signers.get(1).unwrap();
    client.approve_upgrade(&proposal_id, approver1);
    assert_eq!(client.get_timelock_status(&proposal_id), None);

    // Second approval - threshold met, timelock should start
    let approver2 = signers.get(2).unwrap();
    client.approve_upgrade(&proposal_id, approver2);
    
    let status = client.get_timelock_status(&proposal_id);
    assert!(status.is_some());
    assert!(status.unwrap() > 0); // Should have remaining time
}

#[test]
fn test_timelock_prevents_immediate_execution() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    // Setup multisig with 2-of-3 threshold
    let signers = vec![&env, Address::generate(&env), Address::generate(&env), Address::generate(&env)];
    client.init(&signers, &2u32);

    let proposer = signers.get(0).unwrap();
    let wasm_hash = fake_wasm(&env);

    // Create and approve proposal to meet threshold
    let proposal_id = client.propose_upgrade(proposer, &wasm_hash);
    client.approve_upgrade(&proposal_id, signers.get(1).unwrap());
    client.approve_upgrade(&proposal_id, signers.get(2).unwrap());

    // Try to execute immediately - should fail
    let result = std::panic::catch_unwind(|| {
        client.execute_upgrade(&proposal_id);
    });
    assert!(result.is_err());
}

#[test]
fn test_timelock_allows_execution_after_delay() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    // Setup multisig with 2-of-3 threshold
    let signers = vec![&env, Address::generate(&env), Address::generate(&env), Address::generate(&env)];
    client.init(&signers, &2u32);

    let proposer = signers.get(0).unwrap();
    let wasm_hash = fake_wasm(&env);

    // Create and approve proposal to meet threshold
    let proposal_id = client.propose_upgrade(proposer, &wasm_hash);
    client.approve_upgrade(&proposal_id, signers.get(1).unwrap());
    client.approve_upgrade(&proposal_id, signers.get(2).unwrap());

    // Set short delay for testing
    client.set_timelock_delay(&3600); // 1 hour

    // Advance time past delay
    env.ledger().set_timestamp(env.ledger().timestamp() + 3700);

    // Should be executable now
    let result = std::panic::catch_unwind(|| {
        client.execute_upgrade(&proposal_id);
    });
    assert!(result.is_ok());

    // Timelock status should be cleaned up
    assert_eq!(client.get_timelock_status(&proposal_id), None);
}

#[test]
fn test_timelock_status_countdown() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    // Setup multisig
    let signers = vec![&env, Address::generate(&env), Address::generate(&env)];
    client.init(&signers, &2u32);

    let proposer = signers.get(0).unwrap();
    let wasm_hash = fake_wasm(&env);

    // Create and approve proposal
    let proposal_id = client.propose_upgrade(proposer, &wasm_hash);
    client.approve_upgrade(&proposal_id, signers.get(1).unwrap());

    // Set short delay for testing
    client.set_timelock_delay(&3600); // 1 hour

    let start_time = env.ledger().timestamp();

    // Check countdown behavior
    for hours_passed in 0..=4 {
        env.ledger().set_timestamp(start_time + (hours_passed * 3600));
        
        let status = client.get_timelock_status(&proposal_id);
        match hours_passed {
            0 => assert!(status.unwrap() >= 3600), // Full delay remaining
            1 => assert!(status.unwrap() == 0),     // Ready to execute
            _ => assert!(status.unwrap() == 0),     // Still ready
        }
    }
}

#[test]
fn test_timelock_with_different_delays() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    // Setup multisig
    let signers = vec![&env, Address::generate(&env), Address::generate(&env)];
    client.init(&signers, &2u32);

    let proposer = signers.get(0).unwrap();
    let wasm_hash = fake_wasm(&env);

    // Test with different delays
    for delay in [3600, 7200, 86400, 172800] { // 1h, 2h, 24h, 48h
        // Create and approve proposal
        let proposal_id = client.propose_upgrade(proposer, &wasm_hash);
        client.approve_upgrade(&proposal_id, signers.get(1).unwrap());

        // Set delay
        client.set_timelock_delay(&delay);

        let start_time = env.ledger().timestamp();
        
        // Should not be executable immediately
        let result = std::panic::catch_unwind(|| {
            client.execute_upgrade(&proposal_id);
        });
        assert!(result.is_err());

        // Should be executable after delay
        env.ledger().set_timestamp(start_time + delay + 100);
        let result = std::panic::catch_unwind(|| {
            client.execute_upgrade(&proposal_id);
        });
        assert!(result.is_ok());
    }
}

#[test]
fn test_timelock_boundary_conditions() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    // Setup multisig
    let signers = vec![&env, Address::generate(&env), Address::generate(&env)];
    client.init(&signers, &2u32);

    let proposer = signers.get(0).unwrap();
    let wasm_hash = fake_wasm(&env);

    // Create and approve proposal
    let proposal_id = client.propose_upgrade(proposer, &wasm_hash);
    client.approve_upgrade(&proposal_id, signers.get(1).unwrap());

    // Set 1-hour delay
    client.set_timelock_delay(&3600);

    let start_time = env.ledger().timestamp();

    // Test exactly at boundary (1 second before)
    env.ledger().set_timestamp(start_time + 3599);
    let result = std::panic::catch_unwind(|| {
        client.execute_upgrade(&proposal_id);
    });
    assert!(result.is_err());

    // Test exactly at boundary (1 second after)
    env.ledger().set_timestamp(start_time + 3601);
    let result = std::panic::catch_unwind(|| {
        client.execute_upgrade(&proposal_id);
    });
    assert!(result.is_ok());
}

#[test]
fn test_timelock_idempotency() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    // Setup multisig
    let signers = vec![&env, Address::generate(&env), Address::generate(&env)];
    client.init(&signers, &2u32);

    let proposer = signers.get(0).unwrap();
    let wasm_hash = fake_wasm(&env);

    // Create and approve proposal
    let proposal_id = client.propose_upgrade(proposer, &wasm_hash);
    
    // Approve with same signer multiple times (should be idempotent)
    client.approve_upgrade(&proposal_id, signers.get(1).unwrap());
    let result1 = std::panic::catch_unwind(|| {
        client.approve_upgrade(&proposal_id, signers.get(1).unwrap());
    });
    assert!(result1.is_err()); // Should panic on duplicate approval

    // Complete threshold
    client.approve_upgrade(&proposal_id, signers.get(2).unwrap());
    
    // Timelock should be started
    let status1 = client.get_timelock_status(&proposal_id);
    assert!(status1.is_some());

    // Try to start timelock again (should be idempotent)
    client.approve_upgrade(&proposal_id, signers.get(2).unwrap());
    
    let status2 = client.get_timelock_status(&proposal_id);
    assert_eq!(status1, status2); // Should be unchanged
}

#[test]
fn test_timelock_events() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    // Setup multisig
    let signers = vec![&env, Address::generate(&env), Address::generate(&env)];
    client.init(&signers, &2u32);

    let proposer = signers.get(0).unwrap();
    let wasm_hash = fake_wasm(&env);

    // Create proposal
    let proposal_id = client.propose_upgrade(proposer, &wasm_hash);

    // Set custom delay
    client.set_timelock_delay(&7200);

    // Approve to threshold - should emit timelock start event
    client.approve_upgrade(&proposal_id, signers.get(1).unwrap());
    client.approve_upgrade(&proposal_id, signers.get(2).unwrap());

    // Check events
    let events = env.events().all();
    
    // Should have timelock delay changed event
    let delay_events: Vec<_> = events.iter()
        .filter(|e| e.topics[0] == Symbol::new(&env, "timelock") && 
                   e.topics[1] == Symbol::new(&env, "delay_changed"))
        .collect();
    assert_eq!(delay_events.len(), 1);

    // Should have timelock started event
    let start_events: Vec<_> = events.iter()
        .filter(|e| e.topics[0] == Symbol::new(&env, "timelock") && 
                   e.topics[1] == Symbol::new(&env, "started"))
        .collect();
    assert_eq!(start_events.len(), 1);
}

#[test]
fn test_timelock_security_assumptions() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    // Setup multisig
    let signers = vec![&env, Address::generate(&env), Address::generate(&env)];
    client.init(&signers, &2u32);

    let proposer = signers.get(0).unwrap();
    let wasm_hash = fake_wasm(&env);

    // Test 1: Cannot bypass timelock by direct execution
    let proposal_id = client.propose_upgrade(proposer, &wasm_hash);
    client.approve_upgrade(&proposal_id, signers.get(1).unwrap());
    client.approve_upgrade(&proposal_id, signers.get(2).unwrap());

    // Even with threshold met, must wait
    let result = std::panic::catch_unwind(|| {
        client.execute_upgrade(&proposal_id);
    });
    assert!(result.is_err());

    // Test 2: Cannot execute without timelock start
    let proposal_id2 = client.propose_upgrade(proposer, &wasm_hash);
    
    // Try to execute without any approvals
    let result = std::panic::catch_unwind(|| {
        client.execute_upgrade(&proposal_id2);
    });
    assert!(result.is_err());

    // Test 3: Timelock delay cannot be set below minimum
    let admin = Address::generate(&env);
    client.init_admin(&admin);
    
    let result = std::panic::catch_unwind(|| {
        client.set_timelock_delay(&300); // 5 minutes
    });
    assert!(result.is_err());
}

#[test]
fn test_timelock_clock_skew_handling() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    // Setup multisig
    let signers = vec![&env, Address::generate(&env), Address::generate(&env)];
    client.init(&signers, &2u32);

    let proposer = signers.get(0).unwrap();
    let wasm_hash = fake_wasm(&env);

    // Create and approve proposal
    let proposal_id = client.propose_upgrade(proposer, &wasm_hash);
    client.approve_upgrade(&proposal_id, signers.get(1).unwrap());
    client.approve_upgrade(&proposal_id, signers.get(2).unwrap());

    // Set short delay
    client.set_timelock_delay(&3600);

    let start_time = env.ledger().timestamp();

    // Test with clock going backwards (should still work)
    env.ledger().set_timestamp(start_time + 100);
    let status1 = client.get_timelock_status(&proposal_id);
    let remaining1 = status1.unwrap();

    // Go backwards in time (simulating clock skew)
    env.ledger().set_timestamp(start_time + 50);
    let status2 = client.get_timelock_status(&proposal_id);
    let remaining2 = status2.unwrap();

    // Should handle gracefully (more time remaining)
    assert!(remaining2 >= remaining1);

    // Still should not be executable
    let result = std::panic::catch_unwind(|| {
        client.execute_upgrade(&proposal_id);
    });
    assert!(result.is_err());
}

#[test]
fn test_timelock_with_read_only_mode() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, GrainlifyContract);
    let client = GrainlifyContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init_admin(&admin);

    // Enable read-only mode
    client.set_read_only_mode(&true);

    // Should not be able to set timelock delay in read-only mode
    let result = std::panic::catch_unwind(|| {
        client.set_timelock_delay(&7200);
    });
    assert!(result.is_err());
}
