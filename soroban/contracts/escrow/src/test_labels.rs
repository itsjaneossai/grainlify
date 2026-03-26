#![cfg(test)]

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, vec, Address, Env, String};

fn create_token<'a>(
    env: &'a Env,
    admin: &Address,
) -> (Address, token::Client<'a>, token::StellarAssetClient<'a>) {
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let addr = token_contract.address();
    let client = token::Client::new(env, &addr);
    let admin_client = token::StellarAssetClient::new(env, &addr);
    (addr, client, admin_client)
}

fn setup<'a>(
    env: &'a Env,
    initial_balance: i128,
) -> (
    EscrowContractClient<'a>,
    Address,
    Address,
    Address,
    token::Client<'a>,
) {
    env.mock_all_auths();
    let contract_id = env.register(EscrowContract, ());
    let client = EscrowContractClient::new(env, &contract_id);

    let admin = Address::generate(env);
    let depositor = Address::generate(env);
    let contributor = Address::generate(env);
    let (token_addr, token_client, token_admin) = create_token(env, &admin);

    client.init(&admin, &token_addr);
    token_admin.mint(&depositor, &initial_balance);

    (client, admin, depositor, contributor, token_client)
}

#[test]
fn test_lock_funds_with_labels_and_query() {
    let env = Env::default();
    let (client, _admin, depositor, _contributor, _token_client) = setup(&env, 50_000);
    let deadline = env.ledger().timestamp() + 1_000;

    let payroll = vec![
        &env,
        String::from_str(&env, "payroll"),
        String::from_str(&env, "grant-2024"),
    ];
    let milestone = vec![&env, String::from_str(&env, "milestone-1")];

    client.lock_funds_with_labels(&depositor, &1, &1_000, &deadline, &payroll);
    client.lock_funds_with_labels(&depositor, &2, &1_000, &deadline, &milestone);
    client.lock_funds_with_labels(&depositor, &3, &1_000, &deadline, &payroll);

    let page = client.get_escrows_by_label(&String::from_str(&env, "payroll"), &None, &10);
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.records.get(0).unwrap().bounty_id, 1);
    assert_eq!(page.records.get(1).unwrap().bounty_id, 3);
    assert_eq!(client.get_escrow(&1).labels.len(), 2);
}

#[test]
fn test_update_labels_allows_depositor_or_admin() {
    let env = Env::default();
    let (client, admin, depositor, _contributor, _token_client) = setup(&env, 10_000);
    let deadline = env.ledger().timestamp() + 1_000;

    client.lock_funds(&depositor, &9, &1_000, &deadline);

    let depositor_labels = vec![&env, String::from_str(&env, "milestone-1")];
    let updated = client.update_labels(&depositor, &9, &depositor_labels);
    assert_eq!(updated.labels.len(), 1);

    let admin_labels = vec![&env, String::from_str(&env, "payroll")];
    let updated_by_admin = client.update_labels(&admin, &9, &admin_labels);
    assert_eq!(updated_by_admin.labels.get(0).unwrap(), String::from_str(&env, "payroll"));

    let outsider = Address::generate(&env);
    let denied = client.try_update_labels(&outsider, &9, &admin_labels);
    assert!(denied.is_err());
}

#[test]
fn test_restricted_escrow_labels_are_enforced() {
    let env = Env::default();
    let (client, admin, depositor, _contributor, _token_client) = setup(&env, 10_000);
    let deadline = env.ledger().timestamp() + 1_000;

    let allowed = vec![
        &env,
        String::from_str(&env, "payroll"),
        String::from_str(&env, "grant-2024"),
    ];
    let config = client.set_label_config(&true, &allowed);
    assert!(config.restricted);
    assert_eq!(config.allowed_labels.len(), 2);

    let allowed_labels = vec![&env, String::from_str(&env, "payroll")];
    client.lock_funds_with_labels(&depositor, &20, &1_000, &deadline, &allowed_labels);

    let denied_labels = vec![&env, String::from_str(&env, "milestone-1")];
    let denied = client.try_lock_funds_with_labels(&depositor, &21, &1_000, &deadline, &denied_labels);
    assert!(denied.is_err());

    let admin_update = client.update_labels(&admin, &20, &allowed_labels);
    assert_eq!(admin_update.labels.get(0).unwrap(), String::from_str(&env, "payroll"));
}
