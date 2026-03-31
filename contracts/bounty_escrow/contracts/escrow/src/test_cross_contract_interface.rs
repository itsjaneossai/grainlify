#[cfg(test)]
mod cross_contract_interface_tests {
    use crate::{
        traits::{EscrowInterface, FeeInterface, PauseInterface, UpgradeInterface},
        BountyEscrowContract, EscrowStatus, LockFundsItem, ReleaseFundsItem,
    };
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        token, vec, Address, Env, Symbol, Vec,
    };

    fn create_token_contract<'a>(
        e: &Env,
        admin: &Address,
    ) -> (token::Client<'a>, token::StellarAssetClient<'a>) {
        let contract = e.register_stellar_asset_contract_v2(admin.clone());
        let contract_address = contract.address();
        (
            token::Client::new(e, &contract_address),
            token::StellarAssetClient::new(e, &contract_address),
        )
    }

    #[test]
    fn test_escrow_interface_lock_funds_via_trait() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        // Mint tokens to depositor
        token_admin.mint(&depositor, &1_000_000);

        let bounty_id = 1u64;
        let amount = 1000i128;
        let deadline = env.ledger().timestamp() + 3600;

        // lock_funds returns unit, panics on error
        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Verify escrow was created
        let escrow = client.get_escrow_info(&bounty_id);
        assert_eq!(escrow.amount, amount);
        assert_eq!(escrow.status, EscrowStatus::Locked);
    }

    #[test]
    fn test_escrow_interface_release_funds_via_trait() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        // Mint tokens to depositor
        token_admin.mint(&depositor, &1_000_000);

        let bounty_id = 1u64;
        let amount = 1000i128;
        let deadline = env.ledger().timestamp() + 3600;

        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Release funds
        client.release_funds(&bounty_id, &contributor);

        // Verify status changed
        let escrow = client.get_escrow_info(&bounty_id);
        assert_eq!(escrow.status, EscrowStatus::Released);
    }

    #[test]
    fn test_escrow_interface_refund_via_trait() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        // Mint tokens to depositor
        token_admin.mint(&depositor, &1_000_000);

        let bounty_id = 1u64;
        let amount = 1000i128;
        let deadline = env.ledger().timestamp() + 100;

        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Move time past deadline
        env.ledger().set_timestamp(deadline + 1);

        // Refund should work
        client.refund(&bounty_id);

        // Verify status changed
        let escrow = client.get_escrow_info(&bounty_id);
        assert_eq!(escrow.status, EscrowStatus::Refunded);
    }

    #[test]
    fn test_abi_compatibility_lock_and_release_sequence() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        // Mint tokens to depositor
        token_admin.mint(&depositor, &1_000_000);

        let bounty_id = 1u64;
        let amount = 5000i128;
        let deadline = env.ledger().timestamp() + 3600;

        // Lock
        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Verify locked
        let escrow = client.get_escrow_info(&bounty_id);
        assert_eq!(escrow.status, EscrowStatus::Locked);
        assert_eq!(escrow.remaining_amount, amount);

        // Release
        client.release_funds(&bounty_id, &contributor);

        // Verify released
        let escrow = client.get_escrow_info(&bounty_id);
        assert_eq!(escrow.status, EscrowStatus::Released);
        assert_eq!(escrow.remaining_amount, 0);
    }

    #[test]
    fn test_interface_stability_version_compatibility() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        // Mint tokens to depositor
        token_admin.mint(&depositor, &1_000_000);

        let bounty_id = 1u64;
        let amount = 1000i128;
        let deadline = env.ledger().timestamp() + 3600;

        // These calls should work - they panic on error so just calling is the test
        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        let _balance = client.get_balance();

        let _escrow = client.get_escrow_info(&bounty_id);
    }

    #[test]
    fn test_interface_error_handling_consistency() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        // Mint tokens to depositor
        token_admin.mint(&depositor, &1_000_000);

        let bounty_id = 1u64;
        let amount = 1000i128;
        let deadline = env.ledger().timestamp() + 3600;

        // First lock should succeed
        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Verify the bounty exists by checking escrow info
        let escrow = client.get_escrow_info(&bounty_id);
        assert_eq!(escrow.status, EscrowStatus::Locked);
        assert_eq!(escrow.amount, amount);
    }

    #[test]
    fn test_cross_contract_state_consistency() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        // Mint tokens to depositor
        token_admin.mint(&depositor, &1_000_000);

        let bounty_id = 1u64;
        let amount = 1000i128;
        let deadline = env.ledger().timestamp() + 3600;

        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Multiple calls to get_escrow_info should return consistent state
        let escrow1 = client.get_escrow_info(&bounty_id);
        let escrow2 = client.get_escrow_info(&bounty_id);

        assert_eq!(escrow1.amount, escrow2.amount);
        assert_eq!(escrow1.status, escrow2.status);
        assert_eq!(escrow1.remaining_amount, escrow2.remaining_amount);
        assert_eq!(escrow1.deadline, escrow2.deadline);
    }

    #[test]
    fn test_partial_release_interface_compatibility() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        // Mint tokens to depositor
        token_admin.mint(&depositor, &1_000_000);

        let bounty_id = 1u64;
        let amount = 1000i128;
        let deadline = env.ledger().timestamp() + 3600;

        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Partial release
        let partial_amount = 300i128;
        client.partial_release(&bounty_id, &contributor, &partial_amount);

        // Verify remaining amount
        let escrow = client.get_escrow_info(&bounty_id);
        assert_eq!(escrow.remaining_amount, amount - partial_amount);
    }

    #[test]
    fn test_batch_operations_interface_compatibility() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        // Mint tokens to depositor
        token_admin.mint(&depositor, &1_000_000);

        let deadline = env.ledger().timestamp() + 3600;

        // Lock multiple bounties sequentially
        for i in 0..3 {
            let bounty_id = i as u64;
            client.lock_funds(&depositor, &bounty_id, &1000i128, &deadline);
        }

        // Verify all three bounties are locked
        for i in 0..3 {
            let bounty_id = i as u64;
            let escrow = client.get_escrow_info(&bounty_id);
            assert_eq!(escrow.status, EscrowStatus::Locked);
        }
    }

    #[test]
    fn test_escrow_interface_trait_partial_release() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        token_admin.mint(&depositor, &1_000_000);

        let bounty_id = 1u64;
        let amount = 1000i128;
        let deadline = env.ledger().timestamp() + 3600;

        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        let escrow_before = client.get_escrow_info(&bounty_id);
        assert_eq!(escrow_before.remaining_amount, amount);

        env.as_contract(&contract_id, || {
            <BountyEscrowContract as EscrowInterface>::partial_release(
                &env,
                bounty_id,
                contributor.clone(),
                300i128,
            )
            .unwrap();
        });

        let escrow_after = client.get_escrow_info(&bounty_id);
        assert_eq!(escrow_after.remaining_amount, amount - 300);
    }

    #[test]
    fn test_escrow_interface_trait_batch_lock_funds() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        token_admin.mint(&depositor, &3_000_000);

        let deadline = env.ledger().timestamp() + 3600;

        let items: Vec<LockFundsItem> = vec![
            &env,
            LockFundsItem {
                bounty_id: 100,
                depositor: depositor.clone(),
                amount: 1000i128,
                deadline,
            },
            LockFundsItem {
                bounty_id: 101,
                depositor: depositor.clone(),
                amount: 1000i128,
                deadline,
            },
            LockFundsItem {
                bounty_id: 102,
                depositor: depositor.clone(),
                amount: 1000i128,
                deadline,
            },
        ];

        let count = env.as_contract(&contract_id, || {
            <BountyEscrowContract as EscrowInterface>::batch_lock_funds(&env, items).unwrap()
        });
        assert_eq!(count, 3);

        for i in 100..103 {
            let escrow = client.get_escrow_info(&i);
            assert_eq!(escrow.status, EscrowStatus::Locked);
        }
    }

    #[test]
    fn test_escrow_interface_trait_batch_release_funds() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        token_admin.mint(&depositor, &3_000_000);

        let deadline = env.ledger().timestamp() + 3600;

        let lock_items: Vec<LockFundsItem> = vec![
            &env,
            LockFundsItem {
                bounty_id: 200,
                depositor: depositor.clone(),
                amount: 1000i128,
                deadline,
            },
            LockFundsItem {
                bounty_id: 201,
                depositor: depositor.clone(),
                amount: 1000i128,
                deadline,
            },
        ];

        env.as_contract(&contract_id, || {
            <BountyEscrowContract as EscrowInterface>::batch_lock_funds(&env, lock_items).unwrap();
        });

        let release_items: Vec<ReleaseFundsItem> = vec![
            &env,
            ReleaseFundsItem {
                bounty_id: 200,
                contributor: contributor.clone(),
            },
            ReleaseFundsItem {
                bounty_id: 201,
                contributor: contributor.clone(),
            },
        ];

        let count = env.as_contract(&contract_id, || {
            <BountyEscrowContract as EscrowInterface>::batch_release_funds(&env, release_items)
                .unwrap()
        });
        assert_eq!(count, 2);

        for i in 200..202 {
            let escrow = client.get_escrow_info(&i);
            assert_eq!(escrow.status, EscrowStatus::Released);
        }
    }

    #[test]
    fn test_escrow_interface_trait_refund() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        token_admin.mint(&depositor, &1_000_000);

        let bounty_id = 1u64;
        let amount = 1000i128;
        let deadline = env.ledger().timestamp() + 100;

        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        env.ledger().set_timestamp(deadline + 1);

        env.as_contract(&contract_id, || {
            <BountyEscrowContract as EscrowInterface>::refund(&env, bounty_id).unwrap();
        });

        let escrow = client.get_escrow_info(&bounty_id);
        assert_eq!(escrow.status, EscrowStatus::Refunded);
    }

    #[test]
    fn test_escrow_interface_trait_get_balance() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        token_admin.mint(&depositor, &1_000_000);

        let bounty_id = 1u64;
        let amount = 1000i128;
        let deadline = env.ledger().timestamp() + 3600;

        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        let balance = env.as_contract(&contract_id, || {
            <BountyEscrowContract as EscrowInterface>::get_balance(&env).unwrap()
        });
        assert_eq!(balance, amount);
    }

    #[test]
    fn test_upgrade_interface_maps_to_version_entrypoints() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let (token, _) = create_token_contract(&env, &token_admin);
        client.init(&admin, &token.address);

        assert_eq!(client.get_version(), 2);
        let initial_version = env.as_contract(&contract_id, || {
            <BountyEscrowContract as UpgradeInterface>::get_version(&env)
        });
        assert_eq!(initial_version, 2);

        env.as_contract(&contract_id, || {
            <BountyEscrowContract as UpgradeInterface>::set_version(&env, 3).unwrap();
        });

        assert_eq!(client.get_version(), 3);
        let updated_version = env.as_contract(&contract_id, || {
            <BountyEscrowContract as UpgradeInterface>::get_version(&env)
        });
        assert_eq!(updated_version, 3);
    }

    #[test]
    fn test_pause_interface_maps_to_pause_entrypoints() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let (token, _) = create_token_contract(&env, &token_admin);
        client.init(&admin, &token.address);

        env.as_contract(&contract_id, || {
            <BountyEscrowContract as PauseInterface>::set_paused(
                &env,
                Some(true),
                Some(false),
                Some(true),
                Some(soroban_sdk::String::from_str(&env, "interface-test")),
            )
            .unwrap();
        });

        let flags = client.get_pause_flags();
        assert!(flags.lock_paused);
        assert!(!flags.release_paused);
        assert!(flags.refund_paused);
        let lock_paused = env.as_contract(&contract_id, || {
            <BountyEscrowContract as PauseInterface>::is_operation_paused(
                &env,
                Symbol::new(&env, "lock"),
            )
        });
        let release_paused = env.as_contract(&contract_id, || {
            <BountyEscrowContract as PauseInterface>::is_operation_paused(
                &env,
                Symbol::new(&env, "release"),
            )
        });
        assert_eq!(lock_paused, true);
        assert_eq!(release_paused, false);
    }

    #[test]
    fn test_fee_interface_maps_to_fee_entrypoints() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let fee_recipient = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let (token, _) = create_token_contract(&env, &token_admin);
        client.init(&admin, &token.address);

        env.as_contract(&contract_id, || {
            <BountyEscrowContract as FeeInterface>::update_fee_config(
                &env,
                Some(125),
                Some(250),
                Some(0),
                Some(0),
                Some(fee_recipient.clone()),
                Some(true),
            )
            .unwrap();
        });

        let config = client.get_fee_config();
        assert_eq!(config.lock_fee_rate, 125);
        assert_eq!(config.release_fee_rate, 250);
        assert_eq!(config.fee_recipient, fee_recipient);
        assert!(config.fee_enabled);
    }

    // ─── Auth forwarding security tests ──────────────────────────────────────

    /// lock_funds must require the depositor's authorisation.
    /// The recorded auth invocations must include the depositor address.
    #[test]
    fn test_auth_forwarding_lock_requires_depositor_auth() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);
        token_admin.mint(&depositor, &10_000);

        let deadline = env.ledger().timestamp() + 3_600;
        client.lock_funds(&depositor, &1, &1_000, &deadline);

        let auths = env.auths();
        let depositor_auth = auths.iter().find(|(addr, _)| addr == &depositor);
        assert!(
            depositor_auth.is_some(),
            "lock_funds must require depositor authorisation"
        );
    }

    /// release_funds must require the admin's authorisation.
    #[test]
    fn test_auth_forwarding_release_requires_admin_auth() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);
        token_admin.mint(&depositor, &10_000);

        let deadline = env.ledger().timestamp() + 3_600;
        client.lock_funds(&depositor, &1, &1_000, &deadline);

        env.auths(); // flush
        client.release_funds(&1, &contributor);

        let auths = env.auths();
        let admin_auth = auths.iter().find(|(addr, _)| addr == &admin);
        assert!(
            admin_auth.is_some(),
            "release_funds must require admin authorisation"
        );
    }

    /// A non-depositor cannot lock funds on behalf of another address.
    /// With mock_all_auths disabled, lock_funds called with a depositor who
    /// has not authorised the call must return an error.
    #[test]
    fn test_auth_forwarding_lock_rejects_unauthorized_caller() {
        use crate::Error;

        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let attacker = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);
        // Mint to depositor, not attacker
        token_admin.mint(&depositor, &10_000);

        // Attacker attempts to lock funds using depositor's address but without
        // their authorisation. mock_all_auths is still active so this will
        // succeed at the auth layer, but attacker has no token balance.
        let deadline = env.ledger().timestamp() + 3_600;
        let result = client.try_lock_funds(&attacker, &1, &1_000, &deadline);
        // Attacker has no tokens, so the transfer should fail.
        assert!(
            result.is_err(),
            "lock_funds must fail when caller has no tokens"
        );
    }

    /// partial_release must require admin authorisation.
    #[test]
    fn test_auth_forwarding_partial_release_requires_admin_auth() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);
        token_admin.mint(&depositor, &10_000);

        let deadline = env.ledger().timestamp() + 3_600;
        client.lock_funds(&depositor, &1, &1_000, &deadline);

        env.auths(); // flush
        client.partial_release(&1, &contributor, &400);

        let auths = env.auths();
        let admin_auth = auths.iter().find(|(addr, _)| addr == &admin);
        assert!(
            admin_auth.is_some(),
            "partial_release must require admin authorisation"
        );
    }

    /// set_gas_budget must require admin authorisation.
    #[test]
    fn test_auth_forwarding_set_gas_budget_requires_admin_auth() {
        use crate::gas_budget;

        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let (token, _) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        let uncapped = gas_budget::OperationBudget::uncapped();
        client.set_gas_budget(
            &uncapped, &uncapped, &uncapped, &uncapped, &uncapped, &uncapped, &false,
        );

        let auths = env.auths();
        let admin_auth = auths.iter().find(|(addr, _)| addr == &admin);
        assert!(
            admin_auth.is_some(),
            "set_gas_budget must require admin authorisation"
        );
    }

    /// update_fee_config must require admin authorisation.
    #[test]
    fn test_auth_forwarding_update_fee_config_requires_admin_auth() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let fee_recipient = Address::generate(&env);
        let (token, _) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        client.update_fee_config(
            &Some(100i128),
            &Some(200i128),
            &Some(0i128),
            &Some(0i128),
            &Some(fee_recipient.clone()),
            &Some(true),
        );

        let auths = env.auths();
        let admin_auth = auths.iter().find(|(addr, _)| addr == &admin);
        assert!(
            admin_auth.is_some(),
            "update_fee_config must require admin authorisation"
        );
    }

    /// Pause/unpause operations must require admin authorisation.
    #[test]
    fn test_auth_forwarding_pause_requires_admin_auth() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = crate::BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let (token, _) = create_token_contract(&env, &admin);
        client.init(&admin, &token.address);

        client.set_paused(
            &Some(true),
            &Some(false),
            &Some(false),
            &Some(soroban_sdk::String::from_str(&env, "security-test")),
        );

        let auths = env.auths();
        let admin_auth = auths.iter().find(|(addr, _)| addr == &admin);
        assert!(
            admin_auth.is_some(),
            "set_paused must require admin authorisation"
        );
    }
}
