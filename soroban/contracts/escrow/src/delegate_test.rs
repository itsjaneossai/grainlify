#![cfg(test)]

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{token, Address, Env, String};

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

    (
        client,
        contract_id,
        admin,
        depositor,
        contributor,
        token_client,
    )
}

#[test]
fn test_delegate_with_release_permission_can_release_escrow() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, contract_id, _admin, depositor, contributor, token_client) = setup(&env, amount);

    let bounty_id = 1u64;
    let deadline = env.ledger().timestamp() + 1000;
    let delegate = Address::generate(&env);

    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);
    client.set_delegate(
        &depositor,
        &bounty_id,
        &delegate,
        &DELEGATE_PERMISSION_RELEASE,
    );
    client.release_funds_by(&delegate, &bounty_id, &contributor);

    let escrow = client.get_escrow(&bounty_id);
    assert_eq!(escrow.status, EscrowStatus::Released);
    assert_eq!(escrow.remaining_amount, 0);
    assert_eq!(token_client.balance(&contributor), amount);
    assert_eq!(token_client.balance(&contract_id), 0);
}

#[test]
fn test_metadata_only_delegate_cannot_refund_escrow() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _contract_id, _admin, depositor, _contributor, _token_client) = setup(&env, amount);

    let bounty_id = 2u64;
    let deadline = env.ledger().timestamp() + 10;
    let delegate = Address::generate(&env);

    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);
    client.set_delegate(
        &depositor,
        &bounty_id,
        &delegate,
        &DELEGATE_PERMISSION_UPDATE_META,
    );
    client.update_metadata(
        &delegate,
        &bounty_id,
        &String::from_str(&env, "ops-only"),
    );

    let escrow = client.get_escrow(&bounty_id);
    assert_eq!(escrow.metadata, Some(String::from_str(&env, "ops-only")));

    env.ledger().set_timestamp(deadline + 1);
    assert!(client.try_refund_by(&delegate, &bounty_id).is_err());
}

#[test]
fn test_revoked_delegate_cannot_release_escrow() {
    let env = Env::default();
    let amount = 10_000i128;
    let (client, _contract_id, _admin, depositor, contributor, _token_client) = setup(&env, amount);

    let bounty_id = 3u64;
    let deadline = env.ledger().timestamp() + 1000;
    let delegate = Address::generate(&env);

    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);
    client.set_delegate(
        &depositor,
        &bounty_id,
        &delegate,
        &DELEGATE_PERMISSION_RELEASE,
    );
    client.revoke_delegate(&depositor, &bounty_id);

    assert!(client
        .try_release_funds_by(&delegate, &bounty_id, &contributor)
        .is_err());
}