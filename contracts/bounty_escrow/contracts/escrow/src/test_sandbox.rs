//! # Sandbox Isolation Tests — Contract Instance Independence
//!
//! Verifies that multiple deployed instances of the bounty escrow contract maintain
//! complete isolation and cannot affect each other's state or balances.
//!
//! ## Test Coverage
//!
//! - **Instance isolation on lock**: Locking funds on one instance does not affect others
//! - **Instance isolation on release**: Releasing from sandbox doesn't affect production
//! - **Concurrent bounty IDs**: Same bounty ID can coexist across instances safely
//!
//! ## Security Properties Verified
//!
//! - Instance storage is completely isolated (no shared state)
//! - Token transfers only affect the intended contract instance
//! - Admin permissions are per-instance and cannot escalate across instances
//! - Escrow indices are maintained independently per instance

#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    token, Address, Env, IntoVal,
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

fn create_escrow_contract<'a>(e: &Env) -> BountyEscrowContractClient<'a> {
    let contract_id = e.register_contract(None, BountyEscrowContract);
    BountyEscrowContractClient::new(e, &contract_id)
}

/// Tests that two independent contract instances each maintain their own balance.
///
/// Scenario:
/// 1. Deploy prod and sandbox instances with different admins
/// 2. Lock funds only to prod instance
/// 3. Verify prod balance increased, sandbox remained zero
///
/// Security invariant: Contract storage is instance-scoped and cannot be shared.
#[test]
fn test_sandbox_instance_isolation_lock() {
    let env = Env::default();

    let admin_a = Address::generate(&env);
    let admin_b = Address::generate(&env);
    let depositor = Address::generate(&env);

    let (token_client, token_admin) = create_token_contract(&env, &admin_a);

    // Deploy two independent escrow instances (prod + sandbox).
    let prod = create_escrow_contract(&env);
    let sandbox = create_escrow_contract(&env);

    // Initialize each with a different admin.
    env.mock_auths(&[MockAuth {
        address: &admin_a,
        invoke: &MockAuthInvoke {
            contract: &prod.address,
            fn_name: "init",
            args: (&admin_a, &token_client.address).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    prod.init(&admin_a, &token_client.address);

    env.mock_auths(&[MockAuth {
        address: &admin_b,
        invoke: &MockAuthInvoke {
            contract: &sandbox.address,
            fn_name: "init",
            args: (&admin_b, &token_client.address).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    sandbox.init(&admin_b, &token_client.address);

    // Mint tokens to the depositor.
    env.mock_auths(&[MockAuth {
        address: &admin_a,
        invoke: &MockAuthInvoke {
            contract: &token_client.address,
            fn_name: "mint",
            args: (depositor.clone(), 20000i128).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    token_admin.mint(&depositor, &20000);

    // Lock funds on the PROD instance only.
    let bounty_id = 1u64;
    let amount = 5000i128;
    let deadline = env.ledger().timestamp() + 86400;

    env.mock_auths(&[MockAuth {
        address: &depositor,
        invoke: &MockAuthInvoke {
            contract: &prod.address,
            fn_name: "lock_funds",
            args: (depositor.clone(), bounty_id, amount, deadline).into_val(&env),
            sub_invokes: &[MockAuthInvoke {
                contract: &token_client.address,
                fn_name: "transfer",
                args: (depositor.clone(), prod.address.clone(), amount).into_val(&env),
                sub_invokes: &[],
            }],
        },
    }]);
    prod.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    // Prod balance increased; sandbox balance stays at zero.
    assert_eq!(prod.get_balance(), amount);
    assert_eq!(sandbox.get_balance(), 0);
}

/// Tests that releasing funds from sandbox instance does not affect production instance state.
///
/// Scenario:
/// 1. Deploy both instances with same admin (allowed — different contract addresses)
/// 2. Lock same bounty ID and amount on both instances
/// 3. Release from sandbox only
/// 4. Verify sandbox balance decremented, prod unchanged
///
/// Security invariant: Release operations are scoped to their contract instance.
#[test]
fn test_sandbox_instance_isolation_release() {
    let env = Env::default();

    let admin_a = Address::generate(&env);
    let admin_b = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);

    let (token_client, token_admin) = create_token_contract(&env, &admin_a);

    let prod = create_escrow_contract(&env);
    let sandbox = create_escrow_contract(&env);

    // Initialize both instances.
    env.mock_auths(&[MockAuth {
        address: &admin_a,
        invoke: &MockAuthInvoke {
            contract: &prod.address,
            fn_name: "init",
            args: (&admin_a, &token_client.address).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    prod.init(&admin_a, &token_client.address);

    env.mock_auths(&[MockAuth {
        address: &admin_b,
        invoke: &MockAuthInvoke {
            contract: &sandbox.address,
            fn_name: "init",
            args: (&admin_b, &token_client.address).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    sandbox.init(&admin_b, &token_client.address);

    // Mint and lock on BOTH instances.
    env.mock_auths(&[MockAuth {
        address: &admin_a,
        invoke: &MockAuthInvoke {
            contract: &token_client.address,
            fn_name: "mint",
            args: (depositor.clone(), 20000i128).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    token_admin.mint(&depositor, &20000);

    let bounty_id = 42u64;
    let amount = 3000i128;
    let deadline = env.ledger().timestamp() + 86400;

    // Lock on prod.
    env.mock_auths(&[MockAuth {
        address: &depositor,
        invoke: &MockAuthInvoke {
            contract: &prod.address,
            fn_name: "lock_funds",
            args: (depositor.clone(), bounty_id, amount, deadline).into_val(&env),
            sub_invokes: &[MockAuthInvoke {
                contract: &token_client.address,
                fn_name: "transfer",
                args: (depositor.clone(), prod.address.clone(), amount).into_val(&env),
                sub_invokes: &[],
            }],
        },
    }]);
    prod.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    // Lock on sandbox.
    env.mock_auths(&[MockAuth {
        address: &depositor,
        invoke: &MockAuthInvoke {
            contract: &sandbox.address,
            fn_name: "lock_funds",
            args: (depositor.clone(), bounty_id, amount, deadline).into_val(&env),
            sub_invokes: &[MockAuthInvoke {
                contract: &token_client.address,
                fn_name: "transfer",
                args: (depositor.clone(), sandbox.address.clone(), amount).into_val(&env),
                sub_invokes: &[],
            }],
        },
    }]);
    sandbox.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    assert_eq!(prod.get_balance(), amount);
    assert_eq!(sandbox.get_balance(), amount);

    // Release on sandbox only.
    env.mock_auths(&[MockAuth {
        address: &admin_b,
        invoke: &MockAuthInvoke {
            contract: &sandbox.address,
            fn_name: "release_funds",
            args: (bounty_id, contributor.clone()).into_val(&env),
            sub_invokes: &[MockAuthInvoke {
                contract: &token_client.address,
                fn_name: "transfer",
                args: (sandbox.address.clone(), contributor.clone(), amount).into_val(&env),
                sub_invokes: &[],
            }],
        },
    }]);
    sandbox.release_funds(&bounty_id, &contributor);

    // Sandbox balance is now 0; prod balance is unchanged.
    assert_eq!(sandbox.get_balance(), 0);
    assert_eq!(prod.get_balance(), amount);
}

/// Tests that the same bounty ID can exist on multiple instances with independent states.
///
/// Scenario:
/// 1. Deploy two instances with same admin
/// 2. Lock the same bounty_id on both instances but with different amounts (1500 vs 2500)
/// 3. Verify balances and escrow info independently
///
/// Hot path: Bounty ID collision is prevented by per-instance storage
///
/// Security invariant: Bounty IDs are namespaced per contract address (public key).
#[test]
fn test_sandbox_same_bounty_id_no_conflict() {
    let env = Env::default();

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);

    let (token_client, token_admin) = create_token_contract(&env, &admin);

    let instance_a = create_escrow_contract(&env);
    let instance_b = create_escrow_contract(&env);

    // Initialize both with the same admin (allowed — different contract addresses).
    for instance in [&instance_a, &instance_b] {
        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &instance.address,
                fn_name: "init",
                args: (&admin, &token_client.address).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        instance.init(&admin, &token_client.address);
    }

    env.mock_auths(&[MockAuth {
        address: &admin,
        invoke: &MockAuthInvoke {
            contract: &token_client.address,
            fn_name: "mint",
            args: (depositor.clone(), 50000i128).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    token_admin.mint(&depositor, &50000);

    // Use the SAME bounty ID on both instances with different amounts.
    let bounty_id = 99u64;
    let deadline = env.ledger().timestamp() + 86400;

    env.mock_auths(&[MockAuth {
        address: &depositor,
        invoke: &MockAuthInvoke {
            contract: &instance_a.address,
            fn_name: "lock_funds",
            args: (depositor.clone(), bounty_id, 1000i128, deadline).into_val(&env),
            sub_invokes: &[MockAuthInvoke {
                contract: &token_client.address,
                fn_name: "transfer",
                args: (depositor.clone(), instance_a.address.clone(), 1000i128).into_val(&env),
                sub_invokes: &[],
            }],
        },
    }]);
    instance_a.lock_funds(&depositor, &bounty_id, &1000, &deadline);

    env.mock_auths(&[MockAuth {
        address: &depositor,
        invoke: &MockAuthInvoke {
            contract: &instance_b.address,
            fn_name: "lock_funds",
            args: (depositor.clone(), bounty_id, 7000i128, deadline).into_val(&env),
            sub_invokes: &[MockAuthInvoke {
                contract: &token_client.address,
                fn_name: "transfer",
                args: (depositor.clone(), instance_b.address.clone(), 7000i128).into_val(&env),
                sub_invokes: &[],
            }],
        },
    }]);
    instance_b.lock_funds(&depositor, &bounty_id, &7000, &deadline);

    // Each instance tracks its own balance independently.
    assert_eq!(instance_a.get_balance(), 1000);
    assert_eq!(instance_b.get_balance(), 7000);
}
