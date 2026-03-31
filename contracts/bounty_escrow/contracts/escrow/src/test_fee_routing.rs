#![cfg(test)]
mod test_fee_routing {
    use crate::{BountyEscrowContract, BountyEscrowContractClient, Error, TreasuryDestination};
    use soroban_sdk::{testutils::Address as _, token, vec, Address, Env, String};

    fn make_token<'a>(
        env: &'a Env,
        admin: &Address,
    ) -> (Address, token::Client<'a>, token::StellarAssetClient<'a>) {
        let sac = env.register_stellar_asset_contract_v2(admin.clone());
        let addr = sac.address();
        let client = token::Client::new(env, &addr);
        let admin_client = token::StellarAssetClient::new(env, &addr);
        (addr, client, admin_client)
    }

    fn make_setup<'a>(
        env: &'a Env,
    ) -> (
        BountyEscrowContractClient<'a>,
        token::Client<'a>,
        token::StellarAssetClient<'a>,
        Address,
        Address,
    ) {
        let admin = Address::generate(env);
        let token_admin = Address::generate(env);
        let (token_addr, token_client, token_admin_client) = make_token(env, &token_admin);
        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(env, &contract_id);
        client.init(&admin, &token_addr);
        (client, token_client, token_admin_client, admin, contract_id)
    }

    #[test]
    fn lock_fee_routes_to_treasury_and_partner_split() {
        let env = Env::default();
        env.mock_all_auths();

        let (client, token_client, token_admin, _admin, contract_id) = make_setup(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);
        let treasury = Address::generate(&env);
        let partner = Address::generate(&env);

        token_admin.mint(&depositor, &1_000);

        // 7 args: lock_rate (10%), release_rate, lock_fixed, release_fixed, recipient, enabled
        client.update_fee_config(
            &Some(1000),
            &Some(0),
            &Some(0),
            &Some(0),
            &Some(treasury.clone()),
            &Some(true),
        );

        let destinations = vec![
            &env,
            TreasuryDestination {
                address: treasury.clone(),
                weight: 70,
                region: String::from_str(&env, "Main"),
            },
            TreasuryDestination {
                address: partner.clone(),
                weight: 30,
                region: String::from_str(&env, "Partner"),
            },
        ];
        client.set_treasury_distributions(&destinations, &true);

        client.lock_funds(&depositor, &1, &1_000, &(env.ledger().timestamp() + 1_000));
        client.release_funds(&1, &contributor);

        // lock fee = 100, split 70/30, escrow stores and releases 900
        assert_eq!(token_client.balance(&treasury), 70);
        assert_eq!(token_client.balance(&partner), 30);
        assert_eq!(token_client.balance(&contributor), 900);
        assert_eq!(token_client.balance(&contract_id), 0);
    }

    #[test]
    fn release_fee_split_is_deterministic_with_remainder_to_partner() {
        let env = Env::default();
        env.mock_all_auths();

        let (client, token_client, token_admin, _admin, contract_id) = make_setup(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);
        let treasury = Address::generate(&env);
        let partner = Address::generate(&env);

        token_admin.mint(&depositor, &1_000);
        client.update_fee_config(
            &Some(0),
            &Some(333),
            &Some(0),
            &Some(0),
            &Some(treasury.clone()),
            &Some(true),
        );

        let destinations = vec![
            &env,
            TreasuryDestination {
                address: treasury.clone(),
                weight: 50,
                region: String::from_str(&env, "Main"),
            },
            TreasuryDestination {
                address: partner.clone(),
                weight: 50,
                region: String::from_str(&env, "Partner"),
            },
        ];
        client.set_treasury_distributions(&destinations, &true);

        client.lock_funds(&depositor, &2, &1_000, &(env.ledger().timestamp() + 1_000));
        client.release_funds(&2, &contributor);

        // release fee = ceiling(1000 * 333 / 10000) = 34
        // split 50/50 => treasury 17, partner 17
        assert_eq!(token_client.balance(&treasury), 17);
        assert_eq!(token_client.balance(&partner), 17);
        assert_eq!(token_client.balance(&contributor), 966);
        assert_eq!(token_client.balance(&contract_id), 0);
    }

    #[test]
    fn default_routing_uses_fee_recipient_when_distribution_disabled() {
        let env = Env::default();
        env.mock_all_auths();

        let (client, token_client, token_admin, _admin, contract_id) = make_setup(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);
        let treasury = Address::generate(&env);
        let partner = Address::generate(&env);

        token_admin.mint(&depositor, &1_000);
        client.update_fee_config(
            &Some(0),
            &Some(500),
            &Some(0),
            &Some(0),
            &Some(treasury.clone()),
            &Some(true),
        );

        let destinations = vec![
            &env,
            TreasuryDestination {
                address: partner.clone(),
                weight: 100,
                region: String::from_str(&env, "Partner"),
            },
        ];
        // We set destinations but explicitly DISABLE distribution
        client.set_treasury_distributions(&destinations, &false);

        client.lock_funds(&depositor, &3, &1_000, &(env.ledger().timestamp() + 1_000));
        client.release_funds(&3, &contributor);

        // Fallback recipient (treasury) gets all 50. Partner gets 0.
        assert_eq!(token_client.balance(&treasury), 50);
        assert_eq!(token_client.balance(&partner), 0);
        assert_eq!(token_client.balance(&contributor), 950);
        assert_eq!(token_client.balance(&contract_id), 0);
    }

    #[test]
    fn test_no_duplicate_fee_collection_on_release_retry() {
        let env = Env::default();
        env.mock_all_auths();

        let (client, token_client, token_admin, _admin, _contract_id) = make_setup(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);
        let treasury = Address::generate(&env);

        token_admin.mint(&depositor, &10_000);
        client.update_fee_config(
            &Some(0),
            &Some(1000),
            &Some(0),
            &Some(0),
            &Some(treasury.clone()),
            &Some(true),
        );
        client.set_treasury_distributions(&vec![&env], &false);

        let bounty_id = 4u64;
        client.lock_funds(
            &depositor,
            &bounty_id,
            &10_000,
            &(env.ledger().timestamp() + 3600),
        );

        // First release
        client.release_funds(&bounty_id, &contributor);

        // Fee should be 1,000 (10% of 10,000)
        assert_eq!(token_client.balance(&treasury), 1000);

        // Try releasing again (retry scenario)
        let res = client.try_release_funds(&bounty_id, &contributor);
        assert_eq!(res.err().unwrap().unwrap(), Error::FundsNotLocked);

        // Balance should NOT double-charge!
        assert_eq!(token_client.balance(&treasury), 1000);
    }
}
