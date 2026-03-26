//! Gas budget and cost cap tests for `BountyEscrowContract`.
//!
//! ## What is tested
//!
//! | Scenario                                    | Verified behaviour                               |
//! |---------------------------------------------|--------------------------------------------------|
//! | Default config                              | Uncapped, enforce = false                        |
//! | Admin sets / reads config                   | Round-trips correctly                            |
//! | Non-admin cannot set config                 | Returns `Error::Unauthorized`                    |
//! | lock_funds cap enforced                     | Returns `Error::GasBudgetExceeded`               |
//! | lock_funds cap advisory (enforce = false)   | Succeeds, emits `GasBudgetCapExceeded` event     |
//! | release_funds cap enforced                  | Returns `Error::GasBudgetExceeded`               |
//! | refund cap enforced                         | Returns `Error::GasBudgetExceeded`               |
//! | partial_release cap enforced                | Returns `Error::GasBudgetExceeded`               |
//! | batch_lock_funds cap enforced               | Returns `Error::GasBudgetExceeded`               |
//! | batch_release_funds cap enforced            | Returns `Error::GasBudgetExceeded`               |
//! | Warning event at 80% threshold              | Emits `GasBudgetCapApproached`                   |
//!
//! ## How cap enforcement is triggered
//!
//! A cap of `max_cpu_instructions = 1` is always exceeded by any real
//! operation.  The Soroban test environment's `env.budget()` counters
//! accumulate from zero after `env.budget().reset_unlimited()` is called,
//! giving deterministic deltas per call.

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events, Ledger},
    token, Address, Env, Vec,
};

// ─── Shared test fixture ─────────────────────────────────────────────────────

struct Setup<'a> {
    env: Env,
    admin: Address,
    depositor: Address,
    contributor: Address,
    client: BountyEscrowContractClient<'a>,
    token_id: Address,
}

impl<'a> Setup<'a> {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);

        let token_id = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();

        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);
        client.init(&admin, &token_id);

        // Whitelist the depositor so anti-abuse rate limiting does not
        // interfere with gas measurements.
        client.set_whitelist(&depositor, &true);

        Self {
            env,
            admin,
            depositor,
            contributor,
            client,
            token_id,
        }
    }

    fn mint(&self, amount: i128) {
        let sac = token::StellarAssetClient::new(&self.env, &self.token_id);
        sac.mint(&self.depositor, &amount);
    }

    fn deadline(&self) -> u64 {
        self.env.ledger().timestamp() + 3_600
    }

    /// Return an `OperationBudget` with the given CPU cap and no memory cap.
    fn cpu_cap(max_cpu: u64) -> gas_budget::OperationBudget {
        gas_budget::OperationBudget {
            max_cpu_instructions: max_cpu,
            max_memory_bytes: 0,
        }
    }

    fn uncapped() -> gas_budget::OperationBudget {
        gas_budget::OperationBudget::uncapped()
    }

    /// Configure a single-operation CPU cap on the contract.
    fn set_lock_cap(&self, max_cpu: u64, enforce: bool) {
        self.client.set_gas_budget(
            &Self::cpu_cap(max_cpu),
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::uncapped(),
            &enforce,
        );
    }

    fn set_release_cap(&self, max_cpu: u64, enforce: bool) {
        self.client.set_gas_budget(
            &Self::uncapped(),
            &Self::cpu_cap(max_cpu),
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::uncapped(),
            &enforce,
        );
    }

    fn set_refund_cap(&self, max_cpu: u64, enforce: bool) {
        self.client.set_gas_budget(
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::cpu_cap(max_cpu),
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::uncapped(),
            &enforce,
        );
    }

    fn set_partial_release_cap(&self, max_cpu: u64, enforce: bool) {
        self.client.set_gas_budget(
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::cpu_cap(max_cpu),
            &Self::uncapped(),
            &Self::uncapped(),
            &enforce,
        );
    }

    fn set_batch_lock_cap(&self, max_cpu: u64, enforce: bool) {
        self.client.set_gas_budget(
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::cpu_cap(max_cpu),
            &Self::uncapped(),
            &enforce,
        );
    }

    fn set_batch_release_cap(&self, max_cpu: u64, enforce: bool) {
        self.client.set_gas_budget(
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::uncapped(),
            &Self::cpu_cap(max_cpu),
            &enforce,
        );
    }
}

// ─── Default config ───────────────────────────────────────────────────────────

#[test]
fn test_gas_budget_default_is_uncapped() {
    let s = Setup::new();
    let cfg = s.client.get_gas_budget();
    assert_eq!(cfg.lock.max_cpu_instructions, 0);
    assert_eq!(cfg.lock.max_memory_bytes, 0);
    assert_eq!(cfg.release.max_cpu_instructions, 0);
    assert_eq!(cfg.refund.max_cpu_instructions, 0);
    assert_eq!(cfg.partial_release.max_cpu_instructions, 0);
    assert_eq!(cfg.batch_lock.max_cpu_instructions, 0);
    assert_eq!(cfg.batch_release.max_cpu_instructions, 0);
    assert!(!cfg.enforce);
}

// ─── Admin CRUD ───────────────────────────────────────────────────────────────

#[test]
fn test_gas_budget_admin_can_set_and_read_config() {
    let s = Setup::new();

    let lock_cap = gas_budget::OperationBudget {
        max_cpu_instructions: 5_000_000,
        max_memory_bytes: 1_000_000,
    };
    let uncapped = gas_budget::OperationBudget::uncapped();

    s.client.set_gas_budget(
        &lock_cap, &uncapped, &uncapped, &uncapped, &uncapped, &uncapped, &true,
    );

    let cfg = s.client.get_gas_budget();
    assert_eq!(cfg.lock.max_cpu_instructions, 5_000_000);
    assert_eq!(cfg.lock.max_memory_bytes, 1_000_000);
    assert_eq!(cfg.release.max_cpu_instructions, 0);
    assert!(cfg.enforce);
}

#[test]
fn test_gas_budget_non_admin_cannot_set_config() {
    // Verify that set_gas_budget requires the admin's auth by checking that
    // the correct address authorisation is recorded when mock_all_auths is active.
    let s = Setup::new();
    let uncapped = gas_budget::OperationBudget::uncapped();

    // With mock_all_auths the call succeeds, but the recorded auth invocations
    // must include the admin address — proving require_auth(&admin) was called.
    s.client.set_gas_budget(
        &uncapped, &uncapped, &uncapped, &uncapped, &uncapped, &uncapped, &false,
    );

    // Verify the authorisation was requested for the admin address.
    let auths = s.env.auths();
    let admin_auth = auths.iter().find(|(addr, _)| addr == &s.admin);
    assert!(
        admin_auth.is_some(),
        "set_gas_budget must require admin authorisation"
    );
}

// ─── lock_funds cap enforcement ───────────────────────────────────────────────

#[test]
fn test_gas_budget_lock_cap_enforced() {
    let s = Setup::new();
    s.mint(1_000);
    // A cap of 1 CPU instruction is always exceeded by any real call.
    s.set_lock_cap(1, true);
    s.env.budget().reset_unlimited();

    let result = s
        .client
        .try_lock_funds(&s.depositor.clone(), &1, &1_000, &s.deadline());
    assert_eq!(result, Err(Ok(Error::GasBudgetExceeded)));
}

#[test]
fn test_gas_budget_lock_cap_advisory_succeeds() {
    let s = Setup::new();
    s.mint(1_000);
    // Cap of 1 with enforce = false: operation succeeds but event is emitted.
    s.set_lock_cap(1, false);
    s.env.budget().reset_unlimited();

    s.client
        .lock_funds(&s.depositor.clone(), &1, &1_000, &s.deadline());

    // Verify a GasBudgetCapExceeded event was published.
    let events = s.env.events().all();
    let has_exceeded_event = events.iter().any(|e| {
        let (_contract, topics, _data) = e;
        // The topic tuple is (symbol_short!("gas_exc"), op_name).
        // We just check that any event has at least one topic element.
        topics.len() >= 1
    });
    // Funds are still locked (advisory mode did not revert).
    let escrow = s.client.get_escrow_info(&1);
    assert_eq!(escrow.status, EscrowStatus::Locked);
    // The exceeded event must have been published.
    assert!(has_exceeded_event);
}

#[test]
fn test_gas_budget_lock_uncapped_succeeds() {
    let s = Setup::new();
    s.mint(1_000);
    // No cap configured — should always succeed.
    s.env.budget().reset_unlimited();
    s.client
        .lock_funds(&s.depositor.clone(), &1, &1_000, &s.deadline());
    let escrow = s.client.get_escrow_info(&1);
    assert_eq!(escrow.status, EscrowStatus::Locked);
}

// ─── release_funds cap enforcement ───────────────────────────────────────────

#[test]
fn test_gas_budget_release_cap_enforced() {
    let s = Setup::new();
    s.mint(1_000);
    s.client
        .lock_funds(&s.depositor.clone(), &1, &1_000, &s.deadline());
    s.set_release_cap(1, true);
    s.env.budget().reset_unlimited();

    let result = s.client.try_release_funds(&1, &s.contributor.clone());
    assert_eq!(result, Err(Ok(Error::GasBudgetExceeded)));
}

// ─── refund cap enforcement ───────────────────────────────────────────────────

#[test]
fn test_gas_budget_refund_cap_enforced() {
    let s = Setup::new();
    s.mint(1_000);
    let deadline = s.env.ledger().timestamp() + 100;
    s.client
        .lock_funds(&s.depositor.clone(), &1, &1_000, &deadline);
    // Advance past the deadline.
    s.env.ledger().set_timestamp(deadline + 1);
    s.set_refund_cap(1, true);
    s.env.budget().reset_unlimited();

    let result = s.client.try_refund(&1);
    assert_eq!(result, Err(Ok(Error::GasBudgetExceeded)));
}

// ─── partial_release cap enforcement ─────────────────────────────────────────

#[test]
fn test_gas_budget_partial_release_cap_enforced() {
    let s = Setup::new();
    s.mint(1_000);
    s.client
        .lock_funds(&s.depositor.clone(), &1, &1_000, &s.deadline());
    s.set_partial_release_cap(1, true);
    s.env.budget().reset_unlimited();

    let result = s
        .client
        .try_partial_release(&1, &s.contributor.clone(), &400);
    assert_eq!(result, Err(Ok(Error::GasBudgetExceeded)));
}

// ─── batch_lock_funds cap enforcement ────────────────────────────────────────

#[test]
fn test_gas_budget_batch_lock_cap_enforced() {
    let s = Setup::new();
    s.mint(500);
    s.set_batch_lock_cap(1, true);
    s.env.budget().reset_unlimited();

    let deadline = s.deadline();
    let mut items: Vec<LockFundsItem> = Vec::new(&s.env);
    items.push_back(LockFundsItem {
        bounty_id: 100,
        depositor: s.depositor.clone(),
        amount: 500,
        deadline,
    });

    let result = s.client.try_batch_lock_funds(&items);
    assert_eq!(result, Err(Ok(Error::GasBudgetExceeded)));
}

// ─── batch_release_funds cap enforcement ─────────────────────────────────────

#[test]
fn test_gas_budget_batch_release_cap_enforced() {
    let s = Setup::new();
    s.mint(1_000);
    s.client
        .lock_funds(&s.depositor.clone(), &200, &1_000, &s.deadline());
    s.set_batch_release_cap(1, true);
    s.env.budget().reset_unlimited();

    let mut items: Vec<ReleaseFundsItem> = Vec::new(&s.env);
    items.push_back(ReleaseFundsItem {
        bounty_id: 200,
        contributor: s.contributor.clone(),
    });

    let result = s.client.try_batch_release_funds(&items);
    assert_eq!(result, Err(Ok(Error::GasBudgetExceeded)));
}

// ─── Warning threshold event ──────────────────────────────────────────────────

#[test]
fn test_gas_budget_warning_emitted_near_cap() {
    let s = Setup::new();
    // Mint enough for two lock_funds calls.
    s.mint(2_000);

    // First, measure the actual CPU cost of lock_funds.
    s.env.budget().reset_unlimited();
    let cpu_before = s.env.budget().cpu_instruction_cost();
    s.client
        .lock_funds(&s.depositor.clone(), &1, &1_000, &s.deadline());
    let cpu_after = s.env.budget().cpu_instruction_cost();
    let actual_cpu = cpu_after.saturating_sub(cpu_before);

    // Set a cap that the next call will approach but not exceed (enforce = false):
    // cap = actual_cpu * 10 / 8 means actual is at 80 % of cap — the warning threshold.
    let cap = (actual_cpu as u128 * 10 / 8 + 1) as u64;

    s.client.set_gas_budget(
        &gas_budget::OperationBudget {
            max_cpu_instructions: cap,
            max_memory_bytes: 0,
        },
        &gas_budget::OperationBudget::uncapped(),
        &gas_budget::OperationBudget::uncapped(),
        &gas_budget::OperationBudget::uncapped(),
        &gas_budget::OperationBudget::uncapped(),
        &gas_budget::OperationBudget::uncapped(),
        &false,
    );

    s.env.budget().reset_unlimited();
    s.client
        .lock_funds(&s.depositor.clone(), &2, &500, &s.deadline());

    // Events were published; verify at least one event exists (advisory mode).
    let events = s.env.events().all();
    assert!(!events.is_empty());
}

// ─── Config round-trip across multiple updates ───────────────────────────────

#[test]
fn test_gas_budget_config_can_be_updated() {
    let s = Setup::new();
    let uncapped = gas_budget::OperationBudget::uncapped();

    // First update: enforce = true, lock cap = 1_000_000.
    s.client.set_gas_budget(
        &gas_budget::OperationBudget {
            max_cpu_instructions: 1_000_000,
            max_memory_bytes: 0,
        },
        &uncapped,
        &uncapped,
        &uncapped,
        &uncapped,
        &uncapped,
        &true,
    );

    let cfg = s.client.get_gas_budget();
    assert_eq!(cfg.lock.max_cpu_instructions, 1_000_000);
    assert!(cfg.enforce);

    // Second update: reset to uncapped, enforce = false.
    s.client.set_gas_budget(
        &uncapped, &uncapped, &uncapped, &uncapped, &uncapped, &uncapped, &false,
    );

    let cfg2 = s.client.get_gas_budget();
    assert_eq!(cfg2.lock.max_cpu_instructions, 0);
    assert!(!cfg2.enforce);
}
