#[cfg(test)]
mod test_settlement_grace_periods {
    use crate::{
        BountyEscrowContract, BountyEscrowContractClient, Error, EscrowStatus,
        SettlementGracePeriodConfig,
    };
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        token, Address, Env,
    };

    #[test]
    fn test_refund_fails_before_deadline() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let token_id = env.register_stellar_asset_contract_v2(admin.clone());
        let token = token_id.address();
        let token_admin_client = token::StellarAssetClient::new(&env, &token);
        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);

        client.init(&admin, &token);

        let bounty_id = 1u64;
        let amount: i128 = 1_000_0000;
        let deadline = env.ledger().timestamp() + 1000;
        token_admin_client.mint(&depositor, &amount);
        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Try to refund before deadline - should fail
        let result = client.try_refund(&bounty_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_refund_allowed_after_deadline_no_grace() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let token_id = env.register_stellar_asset_contract_v2(admin.clone());
        let token = token_id.address();
        let token_admin_client = token::StellarAssetClient::new(&env, &token);
        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);

        client.init(&admin, &token);

        let bounty_id = 1u64;
        let amount: i128 = 1_000_0000;
        let deadline = env.ledger().timestamp() + 100;
        token_admin_client.mint(&depositor, &amount);
        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Grace period disabled by default (grace_period_seconds = 0, enabled = false)
        let config = client.get_settlement_grace_period_config();
        assert!(!config.enabled);
        assert_eq!(config.grace_period_seconds, 0);

        // Advance to deadline
        env.ledger().set_timestamp(deadline);

        // Refund should succeed
        let result = client.try_refund(&bounty_id);
        assert!(result.is_ok());

        // Verify status is Refunded
        let escrow = client.get_escrow_v2(&bounty_id).unwrap();
        assert_eq!(escrow.status, EscrowStatus::Refunded);
    }

    #[test]
    fn test_grace_period_blocks_refund_during_grace() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let token_id = env.register_stellar_asset_contract_v2(admin.clone());
        let token = token_id.address();
        let token_admin_client = token::StellarAssetClient::new(&env, &token);
        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);

        client.init(&admin, &token);

        // Enable grace period (500 seconds)
        client
            .set_settlement_grace_period_config(&admin, &500, &true)
            .unwrap();

        let bounty_id = 1u64;
        let amount: i128 = 1_000_0000;
        let deadline = env.ledger().timestamp() + 100;
        token_admin_client.mint(&depositor, &amount);
        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Advance to deadline
        env.ledger().set_timestamp(deadline);

        // Try to refund at deadline - should fail (in grace period)
        let result = client.try_refund(&bounty_id);
        assert!(result.is_err());

        // Advance to middle of grace period (250 seconds into grace)
        env.ledger().set_timestamp(deadline + 250);

        // Still should fail (in grace period)
        let result = client.try_refund(&bounty_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_refund_allowed_after_grace_period() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let token_id = env.register_stellar_asset_contract_v2(admin.clone());
        let token = token_id.address();
        let token_admin_client = token::StellarAssetClient::new(&env, &token);
        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);

        client.init(&admin, &token);

        // Enable grace period (500 seconds)
        client
            .set_settlement_grace_period_config(&admin, &500, &true)
            .unwrap();

        let bounty_id = 1u64;
        let amount: i128 = 1_000_0000;
        let deadline = env.ledger().timestamp() + 100;
        token_admin_client.mint(&depositor, &amount);
        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Advance past grace period (100 + 500 + 1 = 601)
        env.ledger().set_timestamp(deadline + 501);

        // Refund should now succeed
        let result = client.try_refund(&bounty_id);
        assert!(result.is_ok());

        // Verify status is Refunded
        let escrow = client.get_escrow_v2(&bounty_id).unwrap();
        assert_eq!(escrow.status, EscrowStatus::Refunded);
    }

    #[test]
    fn test_admin_approval_bypasses_grace_period() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let token_id = env.register_stellar_asset_contract_v2(admin.clone());
        let token = token_id.address();
        let token_admin_client = token::StellarAssetClient::new(&env, &token);
        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);

        client.init(&admin, &token);

        // Enable grace period (500 seconds)
        client
            .set_settlement_grace_period_config(&admin, &500, &true)
            .unwrap();

        let bounty_id = 1u64;
        let amount: i128 = 1_000_0000;
        let deadline = env.ledger().timestamp() + 100;
        token_admin_client.mint(&depositor, &amount);
        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Advance to middle of grace period
        env.ledger().set_timestamp(deadline + 250);

        // Admin approves refund - should work even in grace period
        client
            .approve_refund(&bounty_id, &amount, &depositor)
            .unwrap();

        let result = client.try_refund(&bounty_id);
        assert!(result.is_ok());

        // Verify status is Refunded
        let escrow = client.get_escrow_v2(&bounty_id).unwrap();
        assert_eq!(escrow.status, EscrowStatus::Refunded);
    }

    #[test]
    fn test_schedule_release_blocks_during_grace() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);

        let token_id = env.register_stellar_asset_contract_v2(admin.clone());
        let token = token_id.address();
        let token_admin_client = token::StellarAssetClient::new(&env, &token);
        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);

        client.init(&admin, &token);

        // Enable grace period (500 seconds)
        client
            .set_settlement_grace_period_config(&admin, &500, &true)
            .unwrap();

        let bounty_id = 1u64;
        let amount: i128 = 2_000_0000;
        let deadline = env.ledger().timestamp() + 100;
        token_admin_client.mint(&depositor, &amount);
        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Create a schedule for release at deadline
        let release_ts = deadline;
        client.create_release_schedule(&bounty_id, &1_000_0000, &release_ts, &contributor);

        // Try to release at deadline - should fail (in grace period)
        env.ledger().set_timestamp(deadline);
        let result = client.try_release_schedule_automatic(&bounty_id, &1);
        assert!(result.is_err());

        // Advance past grace period
        env.ledger().set_timestamp(deadline + 501);

        // Now release should succeed
        let result = client.try_release_schedule_automatic(&bounty_id, &1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_grace_period_config_persistence() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);

        let token_id = env.register_stellar_asset_contract_v2(admin.clone());
        let token = token_id.address();
        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);

        client.init(&admin, &token);

        // Initially disabled
        let config = client.get_settlement_grace_period_config();
        assert!(!config.enabled);
        assert_eq!(config.grace_period_seconds, 0);

        // Enable with custom grace period
        client
            .set_settlement_grace_period_config(&admin, &300, &true)
            .unwrap();

        let config = client.get_settlement_grace_period_config();
        assert!(config.enabled);
        assert_eq!(config.grace_period_seconds, 300);

        // Update grace period
        client
            .set_settlement_grace_period_config(&admin, &600, &true)
            .unwrap();

        let config = client.get_settlement_grace_period_config();
        assert!(config.enabled);
        assert_eq!(config.grace_period_seconds, 600);

        // Disable
        client
            .set_settlement_grace_period_config(&admin, &0, &false)
            .unwrap();

        let config = client.get_settlement_grace_period_config();
        assert!(!config.enabled);
        assert_eq!(config.grace_period_seconds, 0);
    }

    #[test]
    fn test_non_admin_cannot_set_grace_period_config() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let non_admin = Address::generate(&env);

        let token_id = env.register_stellar_asset_contract_v2(admin.clone());
        let token = token_id.address();
        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);

        client.init(&admin, &token);

        // Non-admin tries to set config
        let result = client.try_set_settlement_grace_period_config(&non_admin, &300, &true);
        assert!(result.is_err());
    }

    #[test]
    fn test_grace_period_zero_with_enabled_true() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let token_id = env.register_stellar_asset_contract_v2(admin.clone());
        let token = token_id.address();
        let token_admin_client = token::StellarAssetClient::new(&env, &token);
        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);

        client.init(&admin, &token);

        // Set grace period to 0 seconds with enabled = true (edge case)
        client
            .set_settlement_grace_period_config(&admin, &0, &true)
            .unwrap();

        let bounty_id = 1u64;
        let amount: i128 = 1_000_0000;
        let deadline = env.ledger().timestamp() + 100;
        token_admin_client.mint(&depositor, &amount);
        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Advance to deadline
        env.ledger().set_timestamp(deadline);

        // Refund should succeed (grace_deadline = deadline + 0 = deadline)
        let result = client.try_refund(&bounty_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_grace_period_large_values() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);

        let token_id = env.register_stellar_asset_contract_v2(admin.clone());
        let token = token_id.address();
        let token_admin_client = token::StellarAssetClient::new(&env, &token);
        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);

        client.init(&admin, &token);

        // Set large grace period (30 days = 2,592,000 seconds)
        let grace_period = 2_592_000u64;
        client
            .set_settlement_grace_period_config(&admin, &grace_period, &true)
            .unwrap();

        let bounty_id = 1u64;
        let amount: i128 = 1_000_0000;
        let deadline = env.ledger().timestamp() + 100;
        token_admin_client.mint(&depositor, &amount);
        client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

        // Advance to deadline
        env.ledger().set_timestamp(deadline);

        // Refund should fail (in grace)
        let result = client.try_refund(&bounty_id);
        assert!(result.is_err());

        // Advance past grace period
        env.ledger().set_timestamp(deadline + grace_period + 1);

        // Refund should succeed
        let result = client.try_refund(&bounty_id);
        assert!(result.is_ok());
    }
}
