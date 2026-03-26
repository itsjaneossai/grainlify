//! Gas budget and cost cap enforcement per operation type.
//!
//! ## Soroban Platform Behavior
//!
//! Soroban tracks resource consumption in two dimensions:
//! - **CPU instructions**: a fixed-point unit count of computation steps,
//!   capped at ~100 billion per transaction by the network.
//! - **Memory bytes**: heap allocation, capped at ~40 MB per transaction.
//!
//! Unlike EVM's `gasleft()` opcode, Soroban contracts **cannot query their own
//! accumulated budget from within a production contract**. The `env.budget()`
//! API that exposes `cpu_instruction_count()` and `memory_bytes_count()` is
//! available only via the `testutils` feature of `soroban-sdk` and is not
//! accessible to WASM contracts running on the Stellar network.
//!
//! ## Enforcement model
//!
//! | Environment           | Cap enforcement                                         |
//! |-----------------------|---------------------------------------------------------|
//! | Production / on-chain | Configuration is stored and observable; caps serve as   |
//! |                       | documented policy. No runtime measurement is possible.  |
//! | Test (`testutils`)    | Actual CPU and memory deltas are measured and compared  |
//! |                       | against the configured caps. Breaches produce           |
//! |                       | `Error::GasBudgetExceeded` or warning events.           |
//!
//! Returning `Err(Error::GasBudgetExceeded)` causes the Soroban host to revert
//! **all** storage writes and token transfers made during that transaction
//! atomically, so cap enforcement is both safe and loss-free.
//!
//! ## Tuning caps
//!
//! Run `cargo test gas_profile_scaling_summary -- --nocapture` to obtain
//! accurate per-operation CPU and memory measurements. Use those baseline
//! values to derive conservative caps, then configure them via
//! `BountyEscrowContract::set_gas_budget`. See `GAS_TESTS.md` for the full
//! profiling workflow.

use soroban_sdk::{contracttype, Env};

/// Warning threshold expressed in basis points (10 000 = 100 %).
///
/// A [`crate::events::GasBudgetCapApproached`] event is emitted when measured
/// resource usage reaches this fraction of the configured cap.
/// Default: `8_000` = 80 %.
pub const WARNING_THRESHOLD_BPS: u64 = 8_000;
const BASIS: u64 = 10_000;

/// CPU and memory resource limits for one operation class.
///
/// Both fields use `0` to mean "uncapped" for that dimension:
/// - `max_cpu_instructions`: Soroban CPU instruction units.
/// - `max_memory_bytes`: heap bytes allocated during the operation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationBudget {
    /// Maximum CPU instructions consumed by this operation. `0` = uncapped.
    pub max_cpu_instructions: u64,
    /// Maximum memory bytes consumed by this operation. `0` = uncapped.
    pub max_memory_bytes: u64,
}

impl OperationBudget {
    /// Construct an uncapped budget (no limits on either dimension).
    pub const fn uncapped() -> Self {
        OperationBudget {
            max_cpu_instructions: 0,
            max_memory_bytes: 0,
        }
    }
}

/// Per-operation gas budget configuration for the bounty escrow contract.
///
/// Stored in instance storage under [`crate::DataKey::GasBudgetConfig`].
/// The factory default — returned when no configuration has been stored —
/// is fully uncapped with `enforce = false`, so existing deployments are
/// unaffected until an admin calls `BountyEscrowContract::set_gas_budget`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GasBudgetConfig {
    /// Resource cap for `lock_funds` / `lock_funds_anonymous`.
    pub lock: OperationBudget,
    /// Resource cap for `release_funds`.
    pub release: OperationBudget,
    /// Resource cap for `refund`.
    pub refund: OperationBudget,
    /// Resource cap for `partial_release`.
    pub partial_release: OperationBudget,
    /// Aggregate resource cap for `batch_lock_funds` (all items combined).
    pub batch_lock: OperationBudget,
    /// Aggregate resource cap for `batch_release_funds` (all items combined).
    pub batch_release: OperationBudget,
    /// When `true`, any operation that exceeds its cap returns
    /// `Error::GasBudgetExceeded` and the transaction reverts atomically.
    /// When `false`, caps are advisory: a `GasBudgetCapExceeded` event is
    /// emitted but execution continues normally.
    pub enforce: bool,
}

impl GasBudgetConfig {
    /// Return a fully uncapped, non-enforcing configuration.
    pub fn uncapped() -> Self {
        GasBudgetConfig {
            lock: OperationBudget::uncapped(),
            release: OperationBudget::uncapped(),
            refund: OperationBudget::uncapped(),
            partial_release: OperationBudget::uncapped(),
            batch_lock: OperationBudget::uncapped(),
            batch_release: OperationBudget::uncapped(),
            enforce: false,
        }
    }
}

/// Read the stored [`GasBudgetConfig`], falling back to the uncapped default.
pub fn get_config(env: &Env) -> GasBudgetConfig {
    env.storage()
        .instance()
        .get(&crate::DataKey::GasBudgetConfig)
        .unwrap_or_else(GasBudgetConfig::uncapped)
}

/// Persist `config` to instance storage.
pub fn set_config(env: &Env, config: GasBudgetConfig) {
    env.storage()
        .instance()
        .set(&crate::DataKey::GasBudgetConfig, &config);
}

// ============================================================================
// Budget measurement — available only in test / testutils builds.
//
// `env.budget()` counters are not exposed to contracts on the production
// Soroban host.  These helpers are conditionally compiled so they remain
// available to the test suite without adding overhead to the production WASM.
// ============================================================================

/// Snapshot of budget meters captured immediately before an operation.
#[cfg(any(test, feature = "testutils"))]
pub struct BudgetSnapshot {
    pub cpu: u64,
    pub mem: u64,
}

/// Capture current CPU and memory budget counters.
///
/// Call this immediately **before** the operation under measurement.
/// The returned snapshot is passed to [`check`] after the operation completes.
#[cfg(any(test, feature = "testutils"))]
pub fn capture(env: &Env) -> BudgetSnapshot {
    BudgetSnapshot {
        cpu: env.budget().cpu_instruction_cost(),
        mem: env.budget().memory_bytes_cost(),
    }
}

/// Measure the resource delta since `snapshot`, emit events, and enforce caps.
///
/// ### Return value
/// - `Ok(())` — cap not breached (or `enforce` is `false`).
/// - `Err(Error::GasBudgetExceeded)` — cap breached **and** `enforce` is
///   `true`. Soroban's transaction atomicity rolls back all storage writes
///   and token transfers made during the enclosing call.
///
/// ### Events emitted
/// - [`crate::events::GasBudgetCapExceeded`] — emitted on every cap breach,
///   regardless of `enforce`.
/// - [`crate::events::GasBudgetCapApproached`] — emitted when usage reaches
///   `WARNING_THRESHOLD_BPS / BASIS` of the cap without breaching it.
#[cfg(any(test, feature = "testutils"))]
pub fn check(
    env: &Env,
    op_name: soroban_sdk::Symbol,
    budget: &OperationBudget,
    snapshot: &BudgetSnapshot,
    enforce: bool,
) -> Result<(), crate::Error> {
    use soroban_sdk::symbol_short;

    let cpu_used = env
        .budget()
        .cpu_instruction_cost()
        .saturating_sub(snapshot.cpu);
    let mem_used = env
        .budget()
        .memory_bytes_cost()
        .saturating_sub(snapshot.mem);

    let cpu_exceeded = budget.max_cpu_instructions > 0 && cpu_used > budget.max_cpu_instructions;
    let mem_exceeded = budget.max_memory_bytes > 0 && mem_used > budget.max_memory_bytes;

    if cpu_exceeded || mem_exceeded {
        env.events().publish(
            (symbol_short!("gas_exc"), op_name.clone()),
            crate::events::GasBudgetCapExceeded {
                operation: op_name,
                cpu_used,
                mem_used,
                cpu_cap: budget.max_cpu_instructions,
                mem_cap: budget.max_memory_bytes,
                timestamp: env.ledger().timestamp(),
            },
        );
        if enforce {
            return Err(crate::Error::GasBudgetExceeded);
        }
        return Ok(());
    }

    // Emit a warning when usage reaches the configured warning threshold.
    let cpu_warn = budget.max_cpu_instructions > 0
        && cpu_used.saturating_mul(BASIS)
            >= budget
                .max_cpu_instructions
                .saturating_mul(WARNING_THRESHOLD_BPS);
    let mem_warn = budget.max_memory_bytes > 0
        && mem_used.saturating_mul(BASIS)
            >= budget
                .max_memory_bytes
                .saturating_mul(WARNING_THRESHOLD_BPS);

    if cpu_warn || mem_warn {
        env.events().publish(
            (symbol_short!("gas_warn"), op_name.clone()),
            crate::events::GasBudgetCapApproached {
                operation: op_name,
                cpu_used,
                mem_used,
                cpu_cap: budget.max_cpu_instructions,
                mem_cap: budget.max_memory_bytes,
                threshold_bps: WARNING_THRESHOLD_BPS as u32,
                timestamp: env.ledger().timestamp(),
            },
        );
    }

    Ok(())
}
