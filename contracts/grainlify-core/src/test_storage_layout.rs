#[cfg(test)]
mod test {
    use crate::{DataKey, GrainlifyContract, GrainlifyContractClient, STORAGE_SCHEMA_VERSION};
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup_test(env: &Env) -> (GrainlifyContractClient, Address) {
        let contract_id = env.register_contract(None, GrainlifyContract);
        let client = GrainlifyContractClient::new(env, &contract_id);
        let admin = Address::generate(env);
        client.init_admin(&admin);
        (client, admin)
    }

    #[test]
    fn test_storage_schema_version_constant() {
        assert_eq!(STORAGE_SCHEMA_VERSION, 1);
    }

    #[test]
    fn test_verify_storage_layout_after_init() {
        let env = Env::default();
        let (client, _admin) = setup_test(&env);
        assert!(client.verify_storage_layout());
    }

    #[test]
    fn test_all_instance_keys_readable_after_init() {
        let env = Env::default();
        let (client, _admin) = setup_test(&env);

        env.as_contract(&client.address, || {
            assert!(env.storage().instance().has(&DataKey::Admin));
            assert!(env.storage().instance().has(&DataKey::Version));
            assert!(env.storage().instance().has(&DataKey::ReadOnlyMode));
        });
    }
}
