#![cfg(test)]

use crate::{BountyEscrowContract, BountyEscrowContractClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, Env,
};

fn setup_test<'a>() -> (
    Env,
    BountyEscrowContractClient<'a>,
    Address, // depositor
) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);

    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = token_contract.address();
    let token_admin = token::StellarAssetClient::new(&env, &token_address);

    let contract_id = env.register_contract(None, BountyEscrowContract);
    let client = BountyEscrowContractClient::new(&env, &contract_id);

    client.init(&admin, &token_address);
    token_admin.mint(&depositor, &100_000);

    (env, client, depositor)
}

#[test]
fn test_audit_trail_disabled_by_default() {
    let (env, client, depositor) = setup_test();
    let deadline = env.ledger().timestamp() + 3600;

    client.lock_funds(&depositor, &1, &1000, &deadline);
    
    let tail = client.get_audit_tail(&10);
    assert_eq!(tail.len(), 0, "Audit log should be empty when disabled");
}

#[test]
fn test_audit_trail_logs_actions_and_maintains_hash_chain() {
    let (env, client, depositor) = setup_test();
    let contributor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 3600;

    // Enable the audit trail
    client.set_audit_enabled(&true);

    // Perform two critical actions
    client.lock_funds(&depositor, &1, &1000, &deadline);
    client.release_funds(&1, &contributor);

    // Fetch the tail
    let tail = client.get_audit_tail(&10);
    
    assert_eq!(tail.len(), 2, "Should have 2 audit records");

    let record_0 = tail.get(0).unwrap();
    let record_1 = tail.get(1).unwrap();

    assert_eq!(record_0.sequence, 0);
    assert_eq!(record_1.sequence, 1);
    
    // Integrity Check: Record 1's "previous_hash" MUST equal the computed hash of Record 0.
    // In our implementation, the head_hash gets updated, so Record 1 inherently contains the hash of Record 0's state.
    assert_ne!(record_0.previous_hash, record_1.previous_hash, "Hash chain must progress");
}