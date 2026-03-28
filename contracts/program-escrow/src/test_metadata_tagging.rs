#![cfg(test)]
extern crate std;

use crate::*;
use soroban_sdk::{
    testutils::{Address as _, Events},
    token, Address, Env, String, Vec as SdkVec,
};

fn create_token(
    env: &Env,
    admin: &Address,
) -> (token::Client<'static>, token::StellarAssetClient<'static>) {
    let addr = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    (
        token::Client::new(env, &addr),
        token::StellarAssetClient::new(env, &addr),
    )
}

fn create_program_escrow(env: &Env) -> ProgramEscrowContractClient<'static> {
    let id = env.register_contract(None, ProgramEscrowContract);
    ProgramEscrowContractClient::new(env, &id)
}

struct Setup {
    env: Env,
    admin: Address,
    organizer: Address,
    backend: Address,
    escrow: ProgramEscrowContractClient<'static>,
    token: token::Client<'static>,
}

impl Setup {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let organizer = Address::generate(&env);
        let backend = Address::generate(&env);
        let (token, token_admin) = create_token(&env, &admin);
        let escrow = create_program_escrow(&env);
        token_admin.mint(&organizer, &100_000_000);
        Setup {
            env,
            admin,
            organizer,
            backend,
            escrow,
            token,
        }
    }
}

#[test]
fn test_program_metadata_set_on_creation() {
    let s = Setup::new();
    let program_id = String::from_str(&s.env, "Hackathon2024");

    let mut tags = SdkVec::new(&s.env);
    tags.push_back(String::from_str(&s.env, "hackathon"));

    let metadata = ProgramMetadata {
        program_name: Some(String::from_str(&s.env, "Hackathon")),
        program_type: Some(String::from_str(&s.env, "hackathon")),
        ecosystem: Some(String::from_str(&s.env, "stellar")),
        tags,
        start_date: None,
        end_date: None,
        custom_fields: SdkVec::new(&s.env),
    };

    s.escrow.init_program_with_metadata(
        &program_id,
        &s.backend,
        &s.token.address,
        &s.organizer,
        &None,
        &Some(metadata),
    );

    let retrieved = s.escrow.get_program_metadata(&program_id);
    assert_eq!(retrieved.program_name, Some(String::from_str(&s.env, "Hackathon")));
}

#[test]
fn test_program_metadata_update() {
    let s = Setup::new();
    let program_id = String::from_str(&s.env, "UpdateTest");

    s.escrow.init_program_with_metadata(&program_id, &s.backend, &s.token.address, &s.organizer, &None, &None);

    let metadata = ProgramMetadata {
        program_name: Some(String::from_str(&s.env, "Updated")),
        program_type: None,
        ecosystem: None,
        tags: SdkVec::new(&s.env),
        start_date: None,
        end_date: None,
        custom_fields: SdkVec::new(&s.env),
    };

    s.escrow.update_program_metadata(&program_id, &metadata);
    let retrieved = s.escrow.get_program_metadata(&program_id);
    assert_eq!(retrieved.program_name, Some(String::from_str(&s.env, "Updated")));
}
