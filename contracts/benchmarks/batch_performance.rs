//! Performance regression benchmarks for batch operations in Program Escrow
//!
//! Measures gas and execution time for batch lock, batch release, and batch payouts
//! across increasing batch sizes. Fails if regressions surpass defined thresholds.

#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, vec, Address, Env, String,
};

use program_escrow::{ProgramEscrowContract, ProgramEscrowContractClient, LockItem, ReleaseItem};

const BATCH_SIZES: [usize; 5] = [1, 5, 10, 25, 50];
const GAS_THRESHOLDS: [u64; 5] = [80_000, 200_000, 350_000, 800_000, 1_600_000]; // Example values
const EXEC_TIME_THRESHOLDS: [u128; 5] = [10_000, 20_000, 40_000, 100_000, 200_000]; // microseconds

fn setup(env: &Env, initial_amount: i128) -> (ProgramEscrowContractClient, Address, Address, token::Client) {
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProgramEscrowContract);
    let client = ProgramEscrowContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    let token_admin = Address::generate(env);
    let token_id = env.register_stellar_asset_contract(token_admin.clone());
    let token_client = token::Client::new(env, &token_id);
    let program_id = String::from_str(env, "bench-batch");
    client.init_program(&program_id, &admin, &token_id);
    if initial_amount > 0 {
        token::StellarAssetClient::new(env, &token_id).mint(&client.address, &initial_amount);
        client.lock_program_funds(&initial_amount);
    }
    (client, admin, token_id, token_client)
}

#[test]
fn benchmark_batch_payouts() {
    let env = Env::default();
    let total = 2_000_000;
    let (client, _admin, _token_id, _token_client) = setup(&env, total);
    for (i, &batch_size) in BATCH_SIZES.iter().enumerate() {
        let recipients = (0..batch_size)
            .map(|_| Address::generate(&env))
            .collect::<Vec<_>>();
        let amounts = vec![&env];
        for _ in 0..batch_size {
            amounts.push_back(total / (batch_size as i128 * BATCH_SIZES.len() as i128));
        }
        let recipients_vec = vec![&env];
        for r in &recipients {
            recipients_vec.push_back(r.clone());
        }
        let start_gas = env.remaining_gas();
        let start_time = std::time::Instant::now();
        client.batch_payout(&recipients_vec, &amounts);
        let elapsed = start_time.elapsed().as_micros();
        let used_gas = start_gas - env.remaining_gas();
        println!("Batch size: {} | Gas: {} | Time: {}μs", batch_size, used_gas, elapsed);
        assert!(used_gas <= GAS_THRESHOLDS[i], "Gas regression: {} > {}", used_gas, GAS_THRESHOLDS[i]);
        assert!(elapsed <= EXEC_TIME_THRESHOLDS[i], "Exec time regression: {} > {}", elapsed, EXEC_TIME_THRESHOLDS[i]);
    }
}

#[test]
fn benchmark_batch_lock() {
    let env = Env::default();
    let (client, admin, token_id, _token_client) = setup(&env, 1_000_000);

    for (i, &batch_size) in BATCH_SIZES.iter().enumerate() {
        let mut items = vec![&env];

        for j in 0..batch_size {
            let program_id = String::from_str(&env, &format!("BL{:03}", j));
            let creator = Address::generate(&env);
            client.init_program(&program_id, &admin, &token_id, &creator, &None, &None);
            items.push_back(LockItem {
                program_id: program_id.clone(),
                amount: 1_000,
            });
        }

        let start_gas = env.remaining_gas();
        let start_time = std::time::Instant::now();
        let result = client.batch_lock(&items);
        let elapsed = start_time.elapsed().as_micros();
        let used_gas = start_gas - env.remaining_gas();

        println!("Batch lock size: {} | Gas: {} | Time: {}μs", batch_size, used_gas, elapsed);

        assert_eq!(result, batch_size as i128);
        assert!(used_gas <= GAS_THRESHOLDS[i], "Gas regression: {} > {}", used_gas, GAS_THRESHOLDS[i]);
        assert!(elapsed <= EXEC_TIME_THRESHOLDS[i], "Exec time regression: {} > {}", elapsed, EXEC_TIME_THRESHOLDS[i]);

        let sample_prog = client.get_program_info_v2(&String::from_str(&env, "BL000"));
        assert_eq!(sample_prog.total_funds, 1_000);
    }
}

#[test]
fn benchmark_batch_release() {
    let env = Env::default();
    let (client, admin, token_id, _token_client) = setup(&env, 1_000_000);

    for (i, &batch_size) in BATCH_SIZES.iter().enumerate() {
        let program_id = String::from_str(&env, &format!("BR{:03}", i));
        let creator = Address::generate(&env);
        let init_liquidity = (batch_size as i128) * 1_000;
        token::StellarAssetClient::new(&env, &token_id).mint(&creator, &init_liquidity);
        client.init_program(&program_id, &admin, &token_id, &creator, &Some(init_liquidity), &None);

        let mut items = vec![&env];
        let mut recipients = vec![&env];

        for _ in 0..batch_size {
            let recipient = Address::generate(&env);
            recipients.push_back(recipient.clone());
            client.create_program_release_schedule(&recipient, &1_000, &0);
            items.push_back(ReleaseItem {
                program_id: program_id.clone(),
                schedule_id: (recipients.len() - 1) as u64,
            });
        }

        let start_gas = env.remaining_gas();
        let start_time = std::time::Instant::now();
        let result = client.batch_release(&items);
        let elapsed = start_time.elapsed().as_micros();
        let used_gas = start_gas - env.remaining_gas();

        println!("Batch release size: {} | Gas: {} | Time: {}μs", batch_size, used_gas, elapsed);

        assert_eq!(result, batch_size as i128);
        assert!(used_gas <= GAS_THRESHOLDS[i], "Gas regression: {} > {}", used_gas, GAS_THRESHOLDS[i]);
        assert!(elapsed <= EXEC_TIME_THRESHOLDS[i], "Exec time regression: {} > {}", elapsed, EXEC_TIME_THRESHOLDS[i]);

        if batch_size > 0 {
            let first_recipient = recipients.get(1).expect("first recipient should exist");
            let token_client = token::Client::new(&env, &token_id);
            assert_eq!(token_client.balance(&first_recipient), 1_000);
        }
    }
}

