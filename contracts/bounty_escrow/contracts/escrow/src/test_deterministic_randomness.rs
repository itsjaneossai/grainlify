#![cfg(test)]

use soroban_sdk::{testutils::Address as _, Address, Env};

#[test]
fn deterministic_randomness_smoke() {
    let env = Env::default();
    let _addr = Address::generate(&env);
}
