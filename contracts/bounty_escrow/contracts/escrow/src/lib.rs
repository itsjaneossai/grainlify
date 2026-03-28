pub mod events;
pub mod gas_budget;
pub mod invariants;
pub mod multitoken_invariants;
pub mod reentrancy_guard;
// Broken test modules (Anchor→Soroban migration in progress, issue #754/#789)
// Gated out until the migration is complete.
#[cfg(feature = "legacy-tests")]
mod test_boundary_edge_cases;
#[cfg(feature = "legacy-tests")]
mod test_cross_contract_interface;
#[cfg(feature = "legacy-tests")]
mod test_deterministic_randomness;
#[cfg(feature = "legacy-tests")]
mod test_multi_region_treasury;
#[cfg(feature = "legacy-tests")]
mod test_multi_token_fees;
#[cfg(feature = "legacy-tests")]
mod test_rbac;
#[cfg(feature = "legacy-tests")]
mod test_risk_flags;
mod traits;
pub mod upgrade_safety;
pub mod audit_trail;

#[cfg(feature = "legacy-tests")]
mod test_frozen_balance;
#[cfg(feature = "legacy-tests")]
mod test_reentrancy_guard;
#[cfg(test)]
mod test_timelock;

use crate::events::{
    emit_batch_funds_locked, emit_batch_funds_released, emit_bounty_initialized,
    emit_deprecation_state_changed, emit_deterministic_selection, emit_funds_locked,
    emit_funds_locked_anon, emit_funds_refunded, emit_funds_released,
    emit_maintenance_mode_changed, emit_notification_preferences_updated,
    emit_participant_filter_mode_changed, emit_risk_flags_updated, emit_ticket_claimed,
    emit_ticket_issued, BatchFundsLocked, BatchFundsReleased, BountyEscrowInitialized,
    ClaimCancelled, ClaimCreated, ClaimExecuted, CriticalOperationOutcome, DeprecationStateChanged,
    DeterministicSelectionDerived, FundsLocked, FundsLockedAnon, FundsRefunded, FundsReleased,
    MaintenanceModeChanged, NotificationPreferencesUpdated, ParticipantFilterModeChanged,
    RefundTriggerType, RiskFlagsUpdated, TicketClaimed, TicketIssued, EVENT_VERSION_V2,
};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, token, vec, Address, Bytes,
    BytesN, Env, String, Symbol, Vec,
};

// ============================================================================
// INPUT VALIDATION MODULE
// ============================================================================

/// Validation rules for human-readable identifiers to prevent malicious or confusing inputs.
///
/// This module provides consistent validation across all contracts for:
/// - Bounty types and metadata
/// - Any user-provided string identifiers
///
/// Rules enforced:
/// - Maximum length limits to prevent UI/log issues
/// - Allowed character sets (alphanumeric, spaces, safe punctuation)
/// - No control characters that could cause display issues
/// - No leading/trailing whitespace
mod validation {
    use soroban_sdk::Env;

    /// Maximum length for bounty types and short identifiers
    const MAX_TAG_LEN: u32 = 50;

    /// Validates a tag, type, or short identifier.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `tag` - The tag string to validate
    /// * `field_name` - Name of the field for error messages
    ///
    /// # Panics
    /// Panics if validation fails with a descriptive error message.
    pub fn validate_tag(_env: &Env, tag: &soroban_sdk::String, field_name: &str) {
        if tag.len() > MAX_TAG_LEN {
            panic!(
                "{} exceeds maximum length of {} characters",
                field_name, MAX_TAG_LEN
            );
        }

        // Tags should not be empty if provided
        if tag.len() == 0 {
            panic!("{} cannot be empty", field_name);
        }
        // Additional character validation can be added when SDK supports it
    }
}

mod monitoring {
    use soroban_sdk::{contracttype, symbol_short, Address, Env, String, Symbol};

    // Storage keys
    #[allow(dead_code)]
    const OPERATION_COUNT: &str = "op_count";
    #[allow(dead_code)]
    const USER_COUNT: &str = "usr_count";
    #[allow(dead_code)]
    const ERROR_COUNT: &str = "err_count";

    // Event: Operation metric
    #[contracttype]
    #[derive(Clone, Debug)]
    pub struct OperationMetric {
        pub operation: Symbol,
        pub caller: Address,
        pub timestamp: u64,
        pub success: bool,
    }

    // Event: Performance metric
    #[contracttype]
    #[derive(Clone, Debug)]
    pub struct PerformanceMetric {
        pub function: Symbol,
        pub duration: u64,
        pub timestamp: u64,
    }

    // Data: Health status
    #[contracttype]
    #[derive(Clone, Debug)]
    pub struct HealthStatus {
        pub is_healthy: bool,
        pub last_operation: u64,
        pub total_operations: u64,
        pub contract_version: String,
    }

    // Data: Analytics
    #[contracttype]
    #[derive(Clone, Debug)]
    pub struct Analytics {
        pub operation_count: u64,
        pub unique_users: u64,
        pub error_count: u64,
        pub error_rate: u32,
    }

    // Data: State snapshot
    #[contracttype]
    #[derive(Clone, Debug)]
    pub struct StateSnapshot {
        pub timestamp: u64,
        pub total_operations: u64,
        pub total_users: u64,
        pub total_errors: u64,
    }

    // Data: Performance stats
    #[contracttype]
    #[derive(Clone, Debug)]
    pub struct PerformanceStats {
        pub function_name: Symbol,
        pub call_count: u64,
        pub total_time: u64,
        pub avg_time: u64,
        pub last_called: u64,
    }

    // Track operation
    #[allow(dead_code)]
    pub fn track_operation(env: &Env, operation: Symbol, caller: Address, success: bool) {
        let key = Symbol::new(env, OPERATION_COUNT);
        let count: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(count + 1));

        if !success {
            let err_key = Symbol::new(env, ERROR_COUNT);
            let err_count: u64 = env.storage().persistent().get(&err_key).unwrap_or(0);
            env.storage().persistent().set(&err_key, &(err_count + 1));
        }

        env.events().publish(
            (symbol_short!("metric"), symbol_short!("op")),
            OperationMetric {
                operation,
                caller,
                timestamp: env.ledger().timestamp(),
                success,
            },
        );
    }

    // Track performance
    #[allow(dead_code)]
    pub fn emit_performance(env: &Env, function: Symbol, duration: u64) {
        let count_key = (Symbol::new(env, "perf_cnt"), function.clone());
        let time_key = (Symbol::new(env, "perf_time"), function.clone());

        let count: u64 = env.storage().persistent().get(&count_key).unwrap_or(0);
        let total: u64 = env.storage().persistent().get(&time_key).unwrap_or(0);

        env.storage().persistent().set(&count_key, &(count + 1));
        env.storage()
            .persistent()
            .set(&time_key, &(total + duration));

        env.events().publish(
            (symbol_short!("metric"), symbol_short!("perf")),
            PerformanceMetric {
                function,
                duration,
                timestamp: env.ledger().timestamp(),
            },
        );
    }

    // Health check
    #[allow(dead_code)]
    pub fn health_check(env: &Env) -> HealthStatus {
        let key = Symbol::new(env, OPERATION_COUNT);
        let ops: u64 = env.storage().persistent().get(&key).unwrap_or(0);

        HealthStatus {
            is_healthy: true,
            last_operation: env.ledger().timestamp(),
            total_operations: ops,
            contract_version: String::from_str(env, "1.0.0"),
        }
    }

    // Get analytics
    #[allow(dead_code)]
    pub fn get_analytics(env: &Env) -> Analytics {
        let op_key = Symbol::new(env, OPERATION_COUNT);
        let usr_key = Symbol::new(env, USER_COUNT);
        let err_key = Symbol::new(env, ERROR_COUNT);

        let ops: u64 = env.storage().persistent().get(&op_key).unwrap_or(0);
        let users: u64 = env.storage().persistent().get(&usr_key).unwrap_or(0);
        let errors: u64 = env.storage().persistent().get(&err_key).unwrap_or(0);

        let error_rate = if ops > 0 {
            ((errors as u128 * 10000) / ops as u128) as u32
        } else {
            0
        };

        Analytics {
            operation_count: ops,
            unique_users: users,
            error_count: errors,
            error_rate,
        }
    }

    // Get state snapshot
    #[allow(dead_code)]
    pub fn get_state_snapshot(env: &Env) -> StateSnapshot {
        let op_key = Symbol::new(env, OPERATION_COUNT);
        let usr_key = Symbol::new(env, USER_COUNT);
        let err_key = Symbol::new(env, ERROR_COUNT);

        StateSnapshot {
            timestamp: env.ledger().timestamp(),
            total_operations: env.storage().persistent().get(&op_key).unwrap_or(0),
            total_users: env.storage().persistent().get(&usr_key).unwrap_or(0),
            total_errors: env.storage().persistent().get(&err_key).unwrap_or(0),
        }
    }

    // Get performance stats
    #[allow(dead_code)]
    pub fn get_performance_stats(env: &Env, function_name: Symbol) -> PerformanceStats {
        let count_key = (Symbol::new(env, "perf_cnt"), function_name.clone());
        let time_key = (Symbol::new(env, "perf_time"), function_name.clone());
        let last_key = (Symbol::new(env, "perf_last"), function_name.clone());

        let count: u64 = env.storage().persistent().get(&count_key).unwrap_or(0);
        let total: u64 = env.storage().persistent().get(&time_key).unwrap_or(0);
        let last: u64 = env.storage().persistent().get(&last_key).unwrap_or(0);

        let avg = if count > 0 { total / count } else { 0 };

        PerformanceStats {
            function_name,
            call_count: count,
            total_time: total,
            avg_time: avg,
            last_called: last,
        }
    }
}

mod anti_abuse {
    use soroban_sdk::{contracttype, symbol_short, Address, Env};

    #[contracttype]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AntiAbuseConfig {
        pub window_size: u64,     // Window size in seconds
        pub max_operations: u32,  // Max operations allowed in window
        pub cooldown_period: u64, // Minimum seconds between operations
    }

    #[contracttype]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AddressState {
        pub last_operation_timestamp: u64,
        pub window_start_timestamp: u64,
        pub operation_count: u32,
    }

    #[contracttype]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum AntiAbuseKey {
        Config,
        State(Address),
        Whitelist(Address),
        Blocklist(Address),
        Admin,
    }

    pub fn get_config(env: &Env) -> AntiAbuseConfig {
        env.storage()
            .instance()
            .get(&AntiAbuseKey::Config)
            .unwrap_or(AntiAbuseConfig {
                window_size: 3600, // 1 hour default
                max_operations: 100,
                cooldown_period: 60, // 1 minute default
            })
    }

    #[allow(dead_code)]
    pub fn set_config(env: &Env, config: AntiAbuseConfig) {
        env.storage().instance().set(&AntiAbuseKey::Config, &config);
    }

    pub fn is_whitelisted(env: &Env, address: Address) -> bool {
        env.storage()
            .instance()
            .has(&AntiAbuseKey::Whitelist(address))
    }

    pub fn set_whitelist(env: &Env, address: Address, whitelisted: bool) {
        if whitelisted {
            env.storage()
                .instance()
                .set(&AntiAbuseKey::Whitelist(address), &true);
        } else {
            env.storage()
                .instance()
                .remove(&AntiAbuseKey::Whitelist(address));
        }
    }

    pub fn is_blocklisted(env: &Env, address: Address) -> bool {
        env.storage()
            .instance()
            .has(&AntiAbuseKey::Blocklist(address))
    }

    pub fn set_blocklist(env: &Env, address: Address, blocked: bool) {
        if blocked {
            env.storage()
                .instance()
                .set(&AntiAbuseKey::Blocklist(address), &true);
        } else {
            env.storage()
                .instance()
                .remove(&AntiAbuseKey::Blocklist(address));
        }
    }

    pub fn get_admin(env: &Env) -> Option<Address> {
        env.storage().instance().get(&AntiAbuseKey::Admin)
    }

    pub fn set_admin(env: &Env, admin: Address) {
        env.storage().instance().set(&AntiAbuseKey::Admin, &admin);
    }

    pub fn check_rate_limit(env: &Env, address: Address) {
        if is_whitelisted(env, address.clone()) {
            return;
        }

        let config = get_config(env);
        let now = env.ledger().timestamp();
        let key = AntiAbuseKey::State(address.clone());

        let mut state: AddressState =
            env.storage()
                .persistent()
                .get(&key)
                .unwrap_or(AddressState {
                    last_operation_timestamp: 0,
                    window_start_timestamp: now,
                    operation_count: 0,
                });

        // 1. Cooldown check
        if state.last_operation_timestamp > 0
            && now
                < state
                    .last_operation_timestamp
                    .saturating_add(config.cooldown_period)
        {
            env.events().publish(
                (symbol_short!("abuse"), symbol_short!("cooldown")),
                (address.clone(), now),
            );
            panic!("Operation in cooldown period");
        }

        // 2. Window check
        if now
            >= state
                .window_start_timestamp
                .saturating_add(config.window_size)
        {
            // New window
            state.window_start_timestamp = now;
            state.operation_count = 1;
        } else {
            // Same window
            if state.operation_count >= config.max_operations {
                env.events().publish(
                    (symbol_short!("abuse"), symbol_short!("limit")),
                    (address.clone(), now),
                );
                panic!("Rate limit exceeded");
            }
            state.operation_count += 1;
        }

        state.last_operation_timestamp = now;
        env.storage().persistent().set(&key, &state);

        // Extend TTL for state (approx 1 day)
        env.storage().persistent().extend_ttl(&key, 17280, 17280);
    }
}

/// Role-Based Access Control (RBAC) helpers.
///
/// # Role Matrix
///
/// | Action                  | Admin | Operator (anti-abuse admin) | Participant (depositor) |
/// |-------------------------|-------|-----------------------------|-------------------------|
/// | `init`                  | ✓     | ✗                           | ✗                       |
/// | `set_paused`            | ✓     | ✗                           | ✗                       |
/// | `emergency_withdraw`    | ✓     | ✗                           | ✗                       |
/// | `update_fee_config`     | ✓     | ✗                           | ✗                       |
/// | `set_maintenance_mode`  | ✓     | ✗                           | ✗                       |
/// | `set_deprecated`        | ✓     | ✗                           | ✗                       |
/// | `release_funds`         | ✓     | ✗                           | ✗                       |
/// | `approve_refund`        | ✓     | ✗                           | ✗                       |
/// | `partial_release`       | ✓     | ✗                           | ✗                       |
/// | `set_anti_abuse_admin`  | ✓     | ✗                           | ✗                       |
/// | `set_whitelist_entry`   | ✓     | ✓ (via anti-abuse admin)    | ✗                       |
/// | `set_blocklist_entry`   | ✓     | ✓ (via anti-abuse admin)    | ✗                       |
/// | `set_filter_mode`       | ✓     | ✗                           | ✗                       |
/// | `update_anti_abuse_cfg` | ✓     | ✗                           | ✗                       |
/// | `lock_funds`            | ✗     | ✗                           | ✓ (self only)           |
/// | `refund`                | ✓+✓   | ✗                           | ✓ (co-sign)             |
///
/// # Security Invariants
/// - No privilege escalation: operators cannot call admin-only functions.
/// - No cross-call escalation: a participant cannot trigger admin actions indirectly.
/// - `refund` requires both admin AND depositor signatures (dual-auth).
pub mod rbac {
    use soroban_sdk::{Address, Env};

    use crate::DataKey;

    /// Returns the stored admin address, panicking if not initialized.
    pub fn require_admin(env: &Env) -> Address {
        env.storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Admin)
            .expect("contract not initialized")
    }

    /// Asserts that `caller` is the stored admin. Panics otherwise.
    pub fn assert_admin(env: &Env, caller: &Address) {
        let admin = require_admin(env);
        assert_eq!(&admin, caller, "caller is not admin");
        caller.require_auth();
    }

    /// Returns `true` if `addr` is the stored admin.
    pub fn is_admin(env: &Env, addr: &Address) -> bool {
        env.storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Admin)
            .map(|a| &a == addr)
            .unwrap_or(false)
    }

    /// Returns `true` if `addr` is the stored anti-abuse (operator) admin.
    pub fn is_operator(env: &Env, addr: &Address) -> bool {
        use crate::anti_abuse;
        anti_abuse::get_admin(env)
            .map(|a| &a == addr)
            .unwrap_or(false)
    }
}

#[allow(dead_code)]
const BASIS_POINTS: i128 = 10_000;
const MAX_FEE_RATE: i128 = 5_000; // 50% max fee
const MAX_BATCH_SIZE: u32 = 20;

// ============================================================================
// TIMELOCK CONSTANTS
// ============================================================================

/// Minimum timelock delay in seconds (1 hour) - absolute floor
const MINIMUM_DELAY: u64 = 3_600;
/// Default recommended timelock delay in seconds (24 hours)
const DEFAULT_DELAY: u64 = 86_400;
/// Maximum timelock delay in seconds (30 days)
const MAX_DELAY: u64 = 2_592_000;

extern crate grainlify_core;
use grainlify_core::asset;
use grainlify_core::pseudo_randomness;

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DisputeOutcome {
    ResolvedInFavorOfContributor = 1,
    ResolvedInFavorOfDepositor = 2,
    CancelledByAdmin = 3,
    Refunded = 4,
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DisputeReason {
    Expired = 1,
    UnsatisfactoryWork = 2,
    Fraud = 3,
    QualityIssue = 4,
    Other = 5,
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ReleaseType {
    Manual = 1,
    Automatic = 2,
}

// ============================================================================
// TIMELOCK DATA STRUCTURES
// ============================================================================

/// Types of admin actions that require timelock protection
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ActionType {
    ChangeAdmin = 1,
    ChangeFeeRecipient = 2,
    EnableKillSwitch = 3,
    DisableKillSwitch = 4,
    SetMaintenanceMode = 5,
    UnsetMaintenanceMode = 6,
    SetPaused = 7,
    UnsetPaused = 8,
}

/// Status of a pending admin action
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ActionStatus {
    Pending = 1,
    Executed = 2,
    Cancelled = 3,
}

/// Payload for admin actions - encoded variant-specific parameters
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionPayload {
    ChangeAdmin { new_admin: Address },
    ChangeFeeRecipient { new_recipient: Address },
    EnableKillSwitch {},
    DisableKillSwitch {},
    SetMaintenanceMode { enabled: bool },
    SetPaused { 
        lock: Option<bool>,
        release: Option<bool>,
        refund: Option<bool>,
    },
}

/// A pending admin action awaiting execution
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingAction {
    pub action_id: u64,
    pub action_type: ActionType,
    pub payload: Bytes, // Serialized ActionPayload
    pub proposed_by: Address,
    pub proposed_at: u64,
    pub execute_after: u64,
    pub status: ActionStatus,
}

/// Timelock configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelockConfig {
    pub delay: u64,
    pub is_enabled: bool,
}

use grainlify_core::errors;
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    BountyExists = 201,
    BountyNotFound = 202,
    FundsNotLocked = 203,
    DeadlineNotPassed = 6,
    Unauthorized = 7,
    InvalidFeeRate = 8,
    FeeRecipientNotSet = 9,
    InvalidBatchSize = 10,
    BatchSizeMismatch = 11,
    DuplicateBountyId = 12,
    /// Returned when amount is invalid (zero, negative, or exceeds available)
    InvalidAmount = 13,
    /// Returned when deadline is invalid (in the past or too far in the future)
    InvalidDeadline = 14,
    /// Returned when contract has insufficient funds for the operation
    InsufficientFunds = 16,
    /// Returned when refund is attempted without admin approval
    RefundNotApproved = 17,
    FundsPaused = 18,
    /// Returned when lock amount is below the configured policy minimum (Issue #62)
    AmountBelowMinimum = 19,
    /// Returned when lock amount is above the configured policy maximum (Issue #62)
    AmountAboveMaximum = 20,
    /// Returned when refund is blocked by a pending claim/dispute
    NotPaused = 21,
    ClaimPending = 22,
    /// Returned when claim ticket is not found
    TicketNotFound = 23,
    /// Returned when claim ticket has already been used (replay prevention)
    TicketAlreadyUsed = 24,
    /// Returned when claim ticket has expired
    TicketExpired = 25,
    CapabilityNotFound = 26,
    CapabilityExpired = 27,
    CapabilityRevoked = 28,
    CapabilityActionMismatch = 29,
    CapabilityAmountExceeded = 30,
    CapabilityUsesExhausted = 31,
    CapabilityExceedsAuthority = 32,
    InvalidAssetId = 33,
    /// Returned when new locks/registrations are disabled (contract deprecated)
    ContractDeprecated = 34,
    /// Returned when participant filtering is blocklist-only and the address is blocklisted
    ParticipantBlocked = 35,
    /// Returned when participant filtering is allowlist-only and the address is not allowlisted
    ParticipantNotAllowed = 36,
    /// Refund for anonymous escrow must go through refund_resolved (resolver provides recipient)
    AnonymousRefundRequiresResolution = 39,
    /// Anonymous resolver address not set in instance storage
    AnonymousResolverNotSet = 40,
    /// Bounty exists but is not an anonymous escrow (for refund_resolved)
    NotAnonymousEscrow = 41,
    /// Use get_escrow_info_v2 for anonymous escrows
    UseGetEscrowInfoV2ForAnonymous = 37,
    InvalidSelectionInput = 42,
    /// Returned when an upgrade safety pre-check fails
    UpgradeSafetyCheckFailed = 43,
    /// Returned when an operation's measured CPU or memory consumption exceeds
    /// the configured cap and [`gas_budget::GasBudgetConfig::enforce`] is `true`.
    /// The Soroban host reverts all storage writes and token transfers in the
    /// transaction atomically. Only reachable in test / testutils builds.
    GasBudgetExceeded = 44,
    /// Returned when an escrow is explicitly frozen by an admin hold.
    EscrowFrozen = 45,
    /// Returned when the escrow depositor is explicitly frozen by an admin hold.
    AddressFrozen = 46,

    // Timelock errors (47-53)
    /// Returned when timelock is not enabled but propose was called (shouldn't happen)
    TimelockNotEnabled = 47,
    /// Returned when execute is called before the timelock delay has elapsed
    TimelockNotElapsed = 48,
    /// Returned when direct admin call is attempted while timelock is enabled
    TimelockEnabled = 49,
    /// Returned when the requested action_id does not exist
    ActionNotFound = 50,
    /// Returned when the action has already been executed
    ActionAlreadyExecuted = 51,
    /// Returned when the action has already been cancelled
    ActionAlreadyCancelled = 52,
    /// Returned when the payload does not match the action type
    InvalidPayload = 53,
    /// Returned when configured delay is below minimum
    DelayBelowMinimum = 54,
    /// Returned when configured delay is above maximum
    DelayAboveMaximum = 55,
}

/// Bit flag: escrow or payout should be treated as elevated risk (indexers, UIs).
pub const RISK_FLAG_HIGH_RISK: u32 = 1 << 0;
/// Bit flag: manual or automated review is in progress; may restrict certain operations off-chain.
pub const RISK_FLAG_UNDER_REVIEW: u32 = 1 << 1;
/// Bit flag: restricted handling (e.g. compliance); informational for integrators.
pub const RISK_FLAG_RESTRICTED: u32 = 1 << 2;
/// Bit flag: aligned with soft-deprecation signaling; distinct from contract-level deprecation.
pub const RISK_FLAG_DEPRECATED: u32 = 1 << 3;

/// Notification preference flags (bitfield).
pub const NOTIFY_ON_LOCK: u32 = 1 << 0;
pub const NOTIFY_ON_RELEASE: u32 = 1 << 1;
pub const NOTIFY_ON_DISPUTE: u32 = 1 << 2;
pub const NOTIFY_ON_EXPIRATION: u32 = 1 << 3;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowMetadata {
    pub repo_id: u64,
    pub issue_id: u64,
    pub bounty_type: soroban_sdk::String,
    pub risk_flags: u32,
    pub notification_prefs: u32,
    pub reference_hash: Option<soroban_sdk::Bytes>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EscrowStatus {
    Locked,
    Released,
    Refunded,
    PartiallyRefunded,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Escrow {
    pub depositor: Address,
    /// Total amount originally locked into this escrow.
    pub amount: i128,
    /// Amount still available for release; decremented on each partial_release.
    /// Reaches 0 when fully paid out, at which point status becomes Released.
    pub remaining_amount: i128,
    pub status: EscrowStatus,
    pub deadline: u64,
    pub refund_history: Vec<RefundRecord>,
    pub archived: bool,
    pub archived_at: Option<u64>,
}

/// Mutually exclusive participant filtering mode for lock_funds / batch_lock_funds.
///
/// * **Disabled**: No list check; any address may participate (allowlist still used only for anti-abuse bypass).
/// * **BlocklistOnly**: Only blocklisted addresses are rejected; all others may participate.
/// * **AllowlistOnly**: Only allowlisted (whitelisted) addresses may participate; all others are rejected.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParticipantFilterMode {
    /// Disable participant filtering. Any depositor may lock funds.
    Disabled = 0,
    /// Reject only addresses present in the blocklist.
    BlocklistOnly = 1,
    /// Accept only addresses present in the allowlist.
    AllowlistOnly = 2,
}

/// Kill-switch state: when deprecated is true, new escrows are blocked; existing escrows can complete or migrate.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeprecationState {
    pub deprecated: bool,
    pub migration_target: Option<Address>,
}

/// View type for deprecation status (exposed to clients).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeprecationStatus {
    pub deprecated: bool,
    pub migration_target: Option<Address>,
}

/// Anonymous escrow: only a 32-byte depositor commitment is stored on-chain.
/// Refunds require the configured resolver to call `refund_resolved(bounty_id, recipient)`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnonymousEscrow {
    pub depositor_commitment: BytesN<32>,
    pub amount: i128,
    pub remaining_amount: i128,
    pub status: EscrowStatus,
    pub deadline: u64,
    pub refund_history: Vec<RefundRecord>,
    pub archived: bool,
    pub archived_at: Option<u64>,
}

/// Depositor identity: either a concrete address (non-anon) or a 32-byte commitment (anon).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnonymousParty {
    Address(Address),
    Commitment(BytesN<32>),
}

/// Unified escrow view: exposes either address or commitment for depositor.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowInfo {
    pub depositor: AnonymousParty,
    pub amount: i128,
    pub remaining_amount: i128,
    pub status: EscrowStatus,
    pub deadline: u64,
    pub refund_history: Vec<RefundRecord>,
}

/// Immutable audit record for an escrow-level or address-level freeze.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreezeRecord {
    pub frozen: bool,
    pub reason: Option<soroban_sdk::String>,
    pub frozen_at: u64,
    pub frozen_by: Address,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Token,
    Version,
    Escrow(u64),     // bounty_id
    EscrowAnon(u64), // bounty_id anonymous escrow variant
    Metadata(u64),
    EscrowIndex,             // Vec<u64> of all bounty_ids
    DepositorIndex(Address), // Vec<u64> of bounty_ids by depositor
    EscrowFreeze(u64),       // bounty_id -> FreezeRecord
    AddressFreeze(Address),  // address -> FreezeRecord
    FeeConfig,               // Fee configuration
    RefundApproval(u64),     // bounty_id -> RefundApproval
    ReentrancyGuard,
    MultisigConfig,
    ReleaseApproval(u64),        // bounty_id -> ReleaseApproval
    PendingClaim(u64),           // bounty_id -> ClaimRecord
    TicketCounter,               // monotonic claim ticket id
    ClaimTicket(u64),            // ticket_id -> ClaimTicket
    ClaimTicketIndex,            // Vec<u64> all ticket ids
    BeneficiaryTickets(Address), // beneficiary -> Vec<u64>
    ClaimWindow,                 // u64 seconds (global config)
    PauseFlags,                  // PauseFlags struct
    AmountPolicy, // Option<(i128, i128)> — (min_amount, max_amount) set by set_amount_policy
    CapabilityNonce, // monotonically increasing capability id
    Capability(BytesN<32>), // capability_id -> Capability

    /// Marks a bounty escrow as using non-transferable (soulbound) reward tokens.
    /// When set, the token is expected to disallow further transfers after claim.
    NonTransferableRewards(u64), // bounty_id -> bool

    /// Kill switch: when set, new escrows are blocked; existing escrows can complete or migrate
    DeprecationState,
    /// Participant filter mode: Disabled | BlocklistOnly | AllowlistOnly (default Disabled)
    ParticipantFilterMode,

    /// Address of the resolver that may authorize refunds for anonymous escrows
    AnonymousResolver,

    /// Chain identifier (e.g., "stellar", "ethereum") for cross-network protection
    /// Per-token fee configuration keyed by token contract address.
    TokenFeeConfig(Address),
    ChainId,
    NetworkId,

    MaintenanceMode, // bool flag
    /// Per-operation gas budget caps configured by the admin.
    /// See [`gas_budget::GasBudgetConfig`].
    GasBudgetConfig,

    /// Timelock configuration and pending actions
    TimelockConfig,           // TimelockConfig struct
    PendingAction(u64),      // action_id -> PendingAction
    ActionCounter,           // monotonically increasing action_id
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowWithId {
    pub bounty_id: u64,
    pub escrow: Escrow,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseFlags {
    pub lock_paused: bool,
    pub release_paused: bool,
    pub refund_paused: bool,
    pub pause_reason: Option<soroban_sdk::String>,
    pub paused_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateStats {
    pub total_locked: i128,
    pub total_released: i128,
    pub total_refunded: i128,
    pub count_locked: u32,
    pub count_released: u32,
    pub count_refunded: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseStateChanged {
    pub operation: Symbol,
    pub paused: bool,
    pub admin: Address,
    pub reason: Option<soroban_sdk::String>,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
/// Public view of anti-abuse config (rate limit and cooldown).
pub struct AntiAbuseConfigView {
    pub window_size: u64,
    pub max_operations: u32,
    pub cooldown_period: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
/// Treasury routing destination used for weighted multi-region fee distribution.
///
/// The `weight` field is interpreted relative to the sum of all configured
/// destination weights. Fee routing is deterministic: each destination receives
/// a proportional share and any rounding remainder is assigned to the final
/// destination in the configured order so accounting remains exact.
pub struct TreasuryDestination {
    /// Treasury wallet that receives routed fees.
    pub address: Address,
    /// Relative routing weight. Must be greater than zero when configured.
    pub weight: u32,
    /// Human-readable treasury region or routing label.
    pub region: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeConfig {
    /// Fee rate charged when funds are locked, expressed in basis points.
    pub lock_fee_rate: i128,
    /// Fee rate charged when funds are released, expressed in basis points.
    pub release_fee_rate: i128,
    /// Flat fee (token smallest units) added on each lock, before cap to deposit amount.
    pub lock_fixed_fee: i128,
    /// Flat fee added on each full release or partial payout, before cap to payout amount.
    pub release_fixed_fee: i128,
    pub fee_recipient: Address,
    /// Whether fee collection is enabled.
    pub fee_enabled: bool,
    /// Weighted treasury destinations used for multi-region routing.
    pub treasury_destinations: Vec<TreasuryDestination>,
    /// Whether multi-region treasury routing is enabled.
    pub distribution_enabled: bool,
}

/// Per-token fee configuration.
///
/// Allows different fee rates and recipients for each accepted token type.
/// When present, overrides the global `FeeConfig` for that specific token.
///
/// # Rounding protection
/// Fee amounts are always rounded **up** (ceiling division) so that
/// fractional stroops never reduce the fee to zero.  This prevents a
/// depositor from splitting a large deposit into many dust transactions
/// where floor-division would yield fee == 0 on every individual call.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenFeeConfig {
    /// Fee rate on lock, in basis points (1 bp = 0.01 %).
    pub lock_fee_rate: i128,
    /// Fee rate on release, in basis points.
    pub release_fee_rate: i128,
    pub lock_fixed_fee: i128,
    pub release_fixed_fee: i128,
    /// Address that receives fees collected for this token.
    pub fee_recipient: Address,
    /// Whether fee collection is active for this token.
    pub fee_enabled: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultisigConfig {
    pub threshold_amount: i128,
    pub signers: Vec<Address>,
    pub required_signatures: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseApproval {
    pub bounty_id: u64,
    pub contributor: Address,
    pub approvals: Vec<Address>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimRecord {
    pub bounty_id: u64,
    pub recipient: Address,
    pub amount: i128,
    pub expires_at: u64,
    pub claimed: bool,
    pub reason: DisputeReason,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimTicket {
    pub ticket_id: u64,
    pub bounty_id: u64,
    pub beneficiary: Address,
    pub amount: i128,
    pub expires_at: u64,
    pub used: bool,
    pub issued_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityAction {
    Claim,
    Release,
    Refund,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capability {
    pub owner: Address,
    pub holder: Address,
    pub action: CapabilityAction,
    pub bounty_id: u64,
    pub amount_limit: i128,
    pub remaining_amount: i128,
    pub expiry: u64,
    pub remaining_uses: u32,
    pub revoked: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefundMode {
    Full,
    Partial,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundApproval {
    pub bounty_id: u64,
    pub amount: i128,
    pub recipient: Address,
    pub mode: RefundMode,
    pub approved_by: Address,
    pub approved_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundRecord {
    pub amount: i128,
    pub recipient: Address,
    pub timestamp: u64,
    pub mode: RefundMode,
}

/// A single escrow entry to lock within a [`BountyEscrowContract::batch_lock_funds`] call.
///
/// All items in a batch are sorted by ascending `bounty_id` before processing to ensure
/// deterministic execution order. If any item fails validation, the entire batch reverts.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockFundsItem {
    /// Unique identifier for the bounty. Must not already exist in persistent storage
    /// and must not appear more than once within the same batch (`DuplicateBountyId`).
    pub bounty_id: u64,
    /// Address of the depositor. Tokens are transferred **from** this address.
    /// `require_auth()` is called once per unique depositor across the batch.
    pub depositor: Address,
    /// Gross amount (in token base units) to lock into escrow. Must be `> 0`.
    /// If an `AmountPolicy` is active, the value must fall within `[min_amount, max_amount]`.
    pub amount: i128,
    /// Unix timestamp (seconds) after which the depositor may claim a refund
    /// without requiring admin approval. Must be in the future at lock time.
    pub deadline: u64,
}

/// A single escrow release entry within a [`BountyEscrowContract::batch_release_funds`] call.
///
/// All items in a batch are sorted by ascending `bounty_id` before processing to ensure
/// deterministic execution order. If any item fails validation, the entire batch reverts.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseFundsItem {
    /// Identifier of the bounty to release. The escrow record must exist (`BountyNotFound`)
    /// and must be in `Locked` status (`FundsNotLocked`).
    pub bounty_id: u64,
    /// Address of the contributor who will receive the released tokens.
    pub contributor: Address,
}

/// Result of a dry-run simulation. Indicates whether the operation would succeed
/// and the resulting state without mutating storage or performing transfers.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationResult {
    pub success: bool,
    pub error_code: u32,
    pub amount: i128,
    pub resulting_status: EscrowStatus,
    pub remaining_amount: i128,
}

#[contract]
pub struct BountyEscrowContract;

#[contractimpl]
impl BountyEscrowContract {
    pub fn health_check(env: Env) -> monitoring::HealthStatus {
        monitoring::health_check(&env)
    }

    pub fn get_analytics(env: Env) -> monitoring::Analytics {
        monitoring::get_analytics(&env)
    }

    pub fn get_state_snapshot(env: Env) -> monitoring::StateSnapshot {
        monitoring::get_state_snapshot(&env)
    }
    /// Enable or disable the on-chain append-only audit log (Admin only).
    pub fn set_audit_enabled(env: Env, enabled: bool) -> Result<(), Error> {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).ok_or(Error::NotInitialized)?;
        admin.require_auth();
        audit_trail::set_enabled(&env, enabled);
        Ok(())
    }

    /// Retrieve the last `n` records from the audit log.
    pub fn get_audit_tail(env: Env, n: u32) -> Vec<audit_trail::AuditRecord> {
        audit_trail::get_audit_tail(&env, n)
    }

    fn order_batch_lock_items(env: &Env, items: &Vec<LockFundsItem>) -> Vec<LockFundsItem> {
        let mut ordered: Vec<LockFundsItem> = Vec::new(env);
        for item in items.iter() {
            let mut next: Vec<LockFundsItem> = Vec::new(env);
            let mut inserted = false;
            for existing in ordered.iter() {
                if !inserted && item.bounty_id < existing.bounty_id {
                    next.push_back(item.clone());
                    inserted = true;
                }
                next.push_back(existing);
            }
            if !inserted {
                next.push_back(item.clone());
            }
            ordered = next;
        }
        ordered
    }
    /// Filter escrows by their current status (Locked, Released, etc.)
        /// Stable ordering is guaranteed by the EscrowIndex.
	    pub fn query_escrows_by_status(
	            env: Env,
		            status: EscrowStatus,
			            offset: u32,
				            limit: u32,
					        ) -> Vec<EscrowInfo> {
						        let index: Vec<u64> = env.storage().persistent().get(&DataKey::EscrowIndex).unwrap_or(Vec::new(&env));
							        let mut results = Vec::new(&env);

        // Start from offset to support stable pagination
	        for i in offset..index.len() {
		            if results.len() >= limit { break; }
			                let id = index.get(i).unwrap();

            // Reusing your existing get_escrow_info logic
	                let info = Self::get_escrow_info(env.clone(), id);
			            if info.status == status {
				                    results.push_back(info);
						                }
								        }
									        results
										    }

    /// Filter escrows by amount range [min, max]
        pub fn query_escrows_by_amount(
	        env: Env,
		        min: i128,
			        max: i128,
				        offset: u32,
					        limit: u32,
						    ) -> Vec<EscrowInfo> {
						            let index: Vec<u64> = env.storage().persistent().get(&DataKey::EscrowIndex).unwrap_or(Vec::new(&env));
							            let mut results = Vec::new(&env);

        for i in offset..index.len() {
	            if results.len() >= limit { break; }
		                let id = index.get(i).unwrap();
				            let info = Self::get_escrow_info(env.clone(), id);

            if info.amount >= min && info.amount <= max {
	                    results.push_back(info);
			                }
					        }
						        results
							    }

    /// Filter escrows by deadline range [min_ts, max_ts]
        pub fn query_escrows_by_deadline(
	        env: Env,
		        min_ts: u64,
			        max_ts: u64,
				        offset: u32,
					        limit: u32,
						    ) -> Vec<EscrowInfo> {
						            let index: Vec<u64> = env.storage().persistent().get(&DataKey::EscrowIndex).unwrap_or(Vec::new(&env));
							            let mut results = Vec::new(&env);

        for i in offset..index.len() {
	            if results.len() >= limit { break; }
		                let id = index.get(i).unwrap();
				            let info = Self::get_escrow_info(env.clone(), id);

            if info.deadline >= min_ts && info.deadline <= max_ts {
	                    results.push_back(info);
			                }
					        }
						        results
							    }

    fn order_batch_release_items(
        env: &Env,
        items: &Vec<ReleaseFundsItem>,
    ) -> Vec<ReleaseFundsItem> {
        let mut ordered: Vec<ReleaseFundsItem> = Vec::new(env);
        for item in items.iter() {
            let mut next: Vec<ReleaseFundsItem> = Vec::new(env);
            let mut inserted = false;
            for existing in ordered.iter() {
                if !inserted && item.bounty_id < existing.bounty_id {
                    next.push_back(item.clone());
                    inserted = true;
                }
                next.push_back(existing);
            }
            if !inserted {
                next.push_back(item.clone());
            }
            ordered = next;
        }
        ordered
    }

    /// Initialize the contract with the admin address and the token address (XLM).
    pub fn init(env: Env, admin: Address, token: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        if admin == token {
            return Err(Error::Unauthorized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        // Version 2 reflects the breaking shared-trait interface alignment.
        env.storage().instance().set(&DataKey::Version, &2u32);

        events::emit_bounty_initialized(
            &env,
            events::BountyEscrowInitialized {
                version: EVENT_VERSION_V2,
                admin,
                token,
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(())
    }

    pub fn init_with_network(
        env: Env,
        admin: Address,
        token: Address,
        chain_id: soroban_sdk::String,
        network_id: soroban_sdk::String,
    ) -> Result<(), Error> {
        Self::init(env.clone(), admin, token)?;
        env.storage().instance().set(&DataKey::ChainId, &chain_id);
        env.storage()
            .instance()
            .set(&DataKey::NetworkId, &network_id);
        Ok(())
    }

    pub fn get_chain_id(env: Env) -> Option<soroban_sdk::String> {
        env.storage().instance().get(&DataKey::ChainId)
    }

    pub fn get_network_id(env: Env) -> Option<soroban_sdk::String> {
        env.storage().instance().get(&DataKey::NetworkId)
    }

    pub fn get_network_info(
        env: Env,
    ) -> (Option<soroban_sdk::String>, Option<soroban_sdk::String>) {
        (Self::get_chain_id(env.clone()), Self::get_network_id(env))
    }

    /// Return the persisted contract version.
    pub fn get_version(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::Version).unwrap_or(0)
    }

    /// Update the persisted contract version (admin only).
    pub fn set_version(env: Env, new_version: u32) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::Version, &new_version);
        Ok(())
    }

    /// Calculate fee amount based on rate (in basis points), using **ceiling division**.
    ///
    /// Ceiling division ensures that a non-zero fee rate always produces at least
    /// 1 stroop of fee, regardless of how small the individual amount is.  This
    /// closes the principal-drain vector where an attacker breaks a large deposit
    /// into dust amounts that each round down to a zero fee.
    ///
    /// Formula: ceil(amount * fee_rate / BASIS_POINTS)
    ///        = (amount * fee_rate + BASIS_POINTS - 1) / BASIS_POINTS
    ///
    /// # Panics
    /// Returns 0 on arithmetic overflow rather than panicking.
    fn calculate_fee(amount: i128, fee_rate: i128) -> i128 {
        if fee_rate == 0 || amount == 0 {
            return 0;
        }
        // Ceiling integer division: (a + b - 1) / b
        let numerator = amount
            .checked_mul(fee_rate)
            .and_then(|x| x.checked_add(BASIS_POINTS - 1))
            .unwrap_or(0);
        if numerator == 0 {
            return 0;
        }
        numerator / BASIS_POINTS
    }

    /// Total fee on `amount`: ceiling percentage plus optional fixed, capped at `amount`.
    fn combined_fee_amount(amount: i128, rate_bps: i128, fixed: i128, fee_enabled: bool) -> i128 {
        if !fee_enabled || amount <= 0 {
            return 0;
        }
        if fixed < 0 {
            return 0;
        }
        let pct = Self::calculate_fee(amount, rate_bps);
        let sum = pct.saturating_add(fixed);
        sum.min(amount).max(0)
    }

    /// Test-only shim exposing `calculate_fee` for unit-level assertions.
    #[cfg(test)]
    pub fn calculate_fee_pub(amount: i128, fee_rate: i128) -> i128 {
        Self::calculate_fee(amount, fee_rate)
    }

    /// Test-only: combined percentage + fixed fee (capped).
    #[cfg(test)]
    pub fn combined_fee_pub(amount: i128, rate_bps: i128, fixed: i128, fee_enabled: bool) -> i128 {
        Self::combined_fee_amount(amount, rate_bps, fixed, fee_enabled)
    }

    /// Get fee configuration (internal helper)
    fn get_fee_config_internal(env: &Env) -> FeeConfig {
        env.storage()
            .instance()
            .get(&DataKey::FeeConfig)
            .unwrap_or_else(|| FeeConfig {
                lock_fee_rate: 0,
                release_fee_rate: 0,
                lock_fixed_fee: 0,
                release_fixed_fee: 0,
                fee_recipient: env.storage().instance().get(&DataKey::Admin).unwrap(),
                fee_enabled: false,
                treasury_destinations: Vec::new(env),
                distribution_enabled: false,
            })
    }

    /// Validates treasury destinations before enabling multi-region routing.
    fn validate_treasury_destinations(
        _env: &Env,
        destinations: &Vec<TreasuryDestination>,
        distribution_enabled: bool,
    ) -> Result<(), Error> {
        if !distribution_enabled {
            return Ok(());
        }

        if destinations.is_empty() {
            return Err(Error::InvalidAmount);
        }

        let mut total_weight: u64 = 0;
        for destination in destinations.iter() {
            if destination.weight == 0 {
                return Err(Error::InvalidAmount);
            }

            if destination.region.is_empty() || destination.region.len() > 50 {
                return Err(Error::InvalidAmount);
            }

            total_weight = total_weight
                .checked_add(destination.weight as u64)
                .ok_or(Error::InvalidAmount)?;
        }

        if total_weight == 0 {
            return Err(Error::InvalidAmount);
        }

        Ok(())
    }

    /// Routes a collected fee to either the default recipient or configured treasury splits.
    ///
    /// Accepts a pre-constructed [`FeeCollected`] event which contains all fee details.
    /// The token client and fee config are resolved internally from contract storage.
    fn route_fee(
        env: &Env,
        client: &token::Client,
        fee_amount: i128,
        fee_rate: i128,
        operation_type: events::FeeOperationType,
    ) -> Result<(), Error> {
        if fee_amount <= 0 {
            return Ok(());
        }
        let config = Self::get_fee_config_internal(env);

        let fee_fixed = match operation_type {
            events::FeeOperationType::Lock => config.lock_fixed_fee,
            events::FeeOperationType::Release => config.release_fixed_fee,
        };

        if !config.distribution_enabled || config.treasury_destinations.is_empty() {
            client.transfer(
                &env.current_contract_address(),
                &config.fee_recipient,
                &fee_amount,
            );
            events::emit_fee_collected(
                env,
                events::FeeCollected {
                    operation_type: operation_type.clone(),
                    amount: fee_amount,
                    fee_rate,
                    fee_fixed,
                    recipient: config.fee_recipient.clone(),
                    timestamp: env.ledger().timestamp(),
                },
            );
            return Ok(());
        }

        let mut total_weight: u64 = 0;
        for dest in destinations.iter() {
            total_weight = total_weight.checked_add(dest.weight as u64).unwrap_or(u64::MAX);
        }

        if total_weight == 0 {
            client.transfer(
                &env.current_contract_address(),
                &config.fee_recipient,
                &fee_amount,
            );
            events::emit_fee_collected(
                env,
                events::FeeCollected {
                    operation_type: operation_type.clone(),
                    amount: fee_amount,
                    fee_rate,
                    fee_fixed,
                    recipient: config.fee_recipient.clone(),
                    timestamp: env.ledger().timestamp(),
                },
            );
            return Ok(());
        }

        let mut distributed = 0i128;
        let destination_count = config.treasury_destinations.len() as usize;

        for (index, destination) in config.treasury_destinations.iter().enumerate() {
            let share = if index + 1 == destination_count {
                fee_amount
                    .checked_sub(distributed)
                    .ok_or(Error::InvalidAmount)?
            } else {
                let w = destination.weight as i128;
                let tw = total_weight as i128;
                fee_amount.checked_mul(w).unwrap_or(0) / tw
            };

            distributed = distributed.checked_add(share).unwrap_or(distributed);

            if share > 0 {
                client.transfer(&env.current_contract_address(), &destination.address, &share);
            }

            client.transfer(
                &env.current_contract_address(),
                &destination.address,
                &share,
            );
            events::emit_fee_collected(
                env,
                events::FeeCollected {
                    operation_type: operation_type.clone(),
                    amount: share,
                    fee_rate,
                    fee_fixed,
                    recipient: destination.address,
                    timestamp: env.ledger().timestamp(),
                },
            );
        }
        Ok(())
    }

    /// Update fee configuration (admin only)
    /// 
    /// # Timelock Guard
    /// When timelock is enabled, this function returns `TimelockEnabled`.
    /// Use `propose_admin_action` with `ActionType::ChangeFeeRecipient` instead.
    pub fn update_fee_config(
        env: Env,
        lock_fee_rate: Option<i128>,
        release_fee_rate: Option<i128>,
        lock_fixed_fee: Option<i128>,
        release_fixed_fee: Option<i128>,
        fee_recipient: Option<Address>,
        fee_enabled: Option<bool>,
    ) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }

        // Timelock guard: reject direct calls when timelock is enabled
        Self::check_timelock_guard(&env)?;

        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let mut fee_config = Self::get_fee_config_internal(&env);

        if let Some(rate) = lock_fee_rate {
            if !(0..=MAX_FEE_RATE).contains(&rate) {
                return Err(Error::InvalidFeeRate);
            }
            fee_config.lock_fee_rate = rate;
        }

        if let Some(rate) = release_fee_rate {
            if !(0..=MAX_FEE_RATE).contains(&rate) {
                return Err(Error::InvalidFeeRate);
            }
            fee_config.release_fee_rate = rate;
        }

        if let Some(fixed) = lock_fixed_fee {
            if fixed < 0 {
                return Err(Error::InvalidAmount);
            }
            fee_config.lock_fixed_fee = fixed;
        }

        if let Some(fixed) = release_fixed_fee {
            if fixed < 0 {
                return Err(Error::InvalidAmount);
            }
            fee_config.release_fixed_fee = fixed;
        }

        if let Some(recipient) = fee_recipient {
            fee_config.fee_recipient = recipient;
        }

        if let Some(enabled) = fee_enabled {
            fee_config.fee_enabled = enabled;
        }

        env.storage()
            .instance()
            .set(&DataKey::FeeConfig, &fee_config);

        events::emit_fee_config_updated(
            &env,
            events::FeeConfigUpdated {
                lock_fee_rate: fee_config.lock_fee_rate,
                release_fee_rate: fee_config.release_fee_rate,
                lock_fixed_fee: fee_config.lock_fixed_fee,
                release_fixed_fee: fee_config.release_fixed_fee,
                fee_recipient: fee_config.fee_recipient.clone(),
                fee_enabled: fee_config.fee_enabled,
                timestamp: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    /// Configures weighted treasury destinations for multi-region fee routing.
    ///
    /// When enabled, collected lock and release fees are routed proportionally
    /// across `destinations` instead of sending the full amount to
    /// `fee_recipient`. Disabled routing preserves the configured destinations
    /// but falls back to the single-recipient path until re-enabled.
    pub fn set_treasury_distributions(
        env: Env,
        destinations: Vec<TreasuryDestination>,
        distribution_enabled: bool,
    ) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }

        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        Self::validate_treasury_destinations(&env, &destinations, distribution_enabled)?;

        let mut fee_config = Self::get_fee_config_internal(&env);
        fee_config.treasury_destinations = destinations;
        fee_config.distribution_enabled = distribution_enabled;

        env.storage()
            .instance()
            .set(&DataKey::FeeConfig, &fee_config);

        Ok(())
    }

    /// Returns the current treasury routing configuration.
    pub fn get_treasury_distributions(env: Env) -> (Vec<TreasuryDestination>, bool) {
        let fee_config = Self::get_fee_config_internal(&env);
        (
            fee_config.treasury_destinations,
            fee_config.distribution_enabled,
        )
    }

    /// Updates the granular pause state and metadata for the contract.
    ///
    /// # Arguments
    /// * `lock` - If Some(true), prevents new escrows from being created.
    /// * `release` - If Some(true), prevents payouts to contributors.
    /// * `refund` - If Some(true), prevents depositors from reclaiming funds.
    /// * `reason` - Optional UTF-8 string describing why the state was changed.
    ///
    /// # Errors
    /// Returns `Error::NotInitialized` if the admin has not been set.
    /// Returns `Error::Unauthorized` if the caller is not the registered admin.
    /// 
    /// # Timelock Guard
    /// When timelock is enabled, this function returns `TimelockEnabled`.
    /// Use `propose_admin_action` with `ActionType::SetPaused` instead.
    pub fn set_paused(
        env: Env,
        lock: Option<bool>,
        release: Option<bool>,
        refund: Option<bool>,
        reason: Option<soroban_sdk::String>,
    ) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }

        // Timelock guard: reject direct calls when timelock is enabled
        Self::check_timelock_guard(&env)?;

        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let mut flags = Self::get_pause_flags(&env);
        let timestamp = env.ledger().timestamp();

        if reason.is_some() {
            flags.pause_reason = reason.clone();
        }

        if let Some(paused) = lock {
            flags.lock_paused = paused;
            events::emit_pause_state_changed(
                &env,
                PauseStateChanged {
                    operation: symbol_short!("lock"),
                    paused,
                    admin: admin.clone(),
                    reason: reason.clone(),
                    timestamp,
                },
            );
        }

        if let Some(paused) = release {
            flags.release_paused = paused;
            events::emit_pause_state_changed(
                &env,
                PauseStateChanged {
                    operation: symbol_short!("release"),
                    paused,
                    admin: admin.clone(),
                    reason: reason.clone(),
                    timestamp,
                },
            );
        }

        if let Some(paused) = refund {
            flags.refund_paused = paused;
            events::emit_pause_state_changed(
                &env,
                PauseStateChanged {
                    operation: symbol_short!("refund"),
                    paused,
                    admin: admin.clone(),
                    reason: reason.clone(),
                    timestamp,
                },
            );
        }

        let any_paused = flags.lock_paused || flags.release_paused || flags.refund_paused;

        if any_paused {
            if flags.paused_at == 0 {
                flags.paused_at = timestamp;
            }
        } else {
            flags.pause_reason = None;
            flags.paused_at = 0;
        }

        env.storage().instance().set(&DataKey::PauseFlags, &flags);
        Ok(())
    }

    /// Drains all reward tokens from the contract to a target address.
    ///
    /// This is an emergency recovery function and should only be used as a last resort.
    /// The contract MUST have `lock_paused = true` before calling this.
    ///
    /// # Arguments
    /// * `target` - The address that will receive the full contract balance.
    ///
    /// # Errors
    /// Returns `Error::NotPaused` if `lock_paused` is false.
    /// Returns `Error::Unauthorized` if the caller is not the admin.
    pub fn emergency_withdraw(env: Env, target: Address) -> Result<(), Error> {
        // GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);

        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let flags = Self::get_pause_flags(&env);
        if !flags.lock_paused {
            return Err(Error::NotPaused);
        }

        let token_address: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let token_client = token::TokenClient::new(&env, &token_address);

        let contract_address = env.current_contract_address();
        let balance = token_client.balance(&contract_address);

        if balance > 0 {
            token_client.transfer(&contract_address, &target, &balance);
            events::emit_emergency_withdraw(
                &env,
                events::EmergencyWithdrawEvent {
                    admin,
                    recipient: target,
                    amount: balance,
                    timestamp: env.ledger().timestamp(),
                },
            );
        }

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Returns current deprecation state (internal). When deprecated is true, new locks are blocked.
    fn get_deprecation_state(env: &Env) -> DeprecationState {
        env.storage()
            .instance()
            .get(&DataKey::DeprecationState)
            .unwrap_or(DeprecationState {
                deprecated: false,
                migration_target: None,
            })
    }

    fn get_participant_filter_mode(env: &Env) -> ParticipantFilterMode {
        env.storage()
            .instance()
            .get(&DataKey::ParticipantFilterMode)
            .unwrap_or(ParticipantFilterMode::Disabled)
    }

    /// Enforces participant filtering: returns Err if the address is not allowed to participate
    /// (lock_funds / batch_lock_funds) under the current filter mode.
    fn check_participant_filter(env: &Env, address: Address) -> Result<(), Error> {
        let mode = Self::get_participant_filter_mode(env);
        match mode {
            ParticipantFilterMode::Disabled => Ok(()),
            ParticipantFilterMode::BlocklistOnly => {
                if anti_abuse::is_blocklisted(env, address) {
                    return Err(Error::ParticipantBlocked);
                }
                Ok(())
            }
            ParticipantFilterMode::AllowlistOnly => {
                if !anti_abuse::is_whitelisted(env, address) {
                    return Err(Error::ParticipantNotAllowed);
                }
                Ok(())
            }
        }
    }

    /// Set deprecation (kill switch) and optional migration target. Admin only.
    /// When deprecated is true: new lock_funds and batch_lock_funds are blocked; existing escrows
    /// can still release, refund, or be migrated off-chain. Emits DeprecationStateChanged.
    /// 
    /// # Timelock Guard
    /// When timelock is enabled, this function returns `TimelockEnabled`.
    /// Use `propose_admin_action` with `ActionType::EnableKillSwitch` or `ActionType::DisableKillSwitch` instead.
    pub fn set_deprecated(
        env: Env,
        deprecated: bool,
        migration_target: Option<Address>,
    ) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        
        // Timelock guard: reject direct calls when timelock is enabled
        Self::check_timelock_guard(&env)?;
        
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let state = DeprecationState {
            deprecated,
            migration_target: migration_target.clone(),
        };
        env.storage()
            .instance()
            .set(&DataKey::DeprecationState, &state);
        emit_deprecation_state_changed(
            &env,
            DeprecationStateChanged {
                deprecated: state.deprecated,
                migration_target: state.migration_target,
                admin,
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(())
    }

    /// View: returns whether the contract is deprecated and the optional migration target address.
    pub fn get_deprecation_status(env: Env) -> DeprecationStatus {
        let s = Self::get_deprecation_state(&env);
        DeprecationStatus {
            deprecated: s.deprecated,
            migration_target: s.migration_target,
        }
    }

    /// Get current pause flags
    pub fn get_pause_flags(env: &Env) -> PauseFlags {
        env.storage()
            .instance()
            .get(&DataKey::PauseFlags)
            .unwrap_or(PauseFlags {
                lock_paused: false,
                release_paused: false,
                refund_paused: false,
                pause_reason: None,
                paused_at: 0,
            })
    }

    fn get_escrow_freeze_record_internal(env: &Env, bounty_id: u64) -> Option<FreezeRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::EscrowFreeze(bounty_id))
    }

    fn get_address_freeze_record_internal(env: &Env, address: &Address) -> Option<FreezeRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::AddressFreeze(address.clone()))
    }

    fn ensure_escrow_not_frozen(env: &Env, bounty_id: u64) -> Result<(), Error> {
        if Self::get_escrow_freeze_record_internal(env, bounty_id)
            .map(|record| record.frozen)
            .unwrap_or(false)
        {
            return Err(Error::EscrowFrozen);
        }
        Ok(())
    }

    fn ensure_address_not_frozen(env: &Env, address: &Address) -> Result<(), Error> {
        if Self::get_address_freeze_record_internal(env, address)
            .map(|record| record.frozen)
            .unwrap_or(false)
        {
            return Err(Error::AddressFrozen);
        }
        Ok(())
    }

    /// Check if an operation is paused
    fn check_paused(env: &Env, operation: Symbol) -> bool {
        let flags = Self::get_pause_flags(env);
        if operation == symbol_short!("lock") {
            if Self::is_maintenance_mode(env.clone()) {
                return true;
            }
            return flags.lock_paused;
        } else if operation == symbol_short!("release") {
            return flags.release_paused;
        } else if operation == symbol_short!("refund") {
            return flags.refund_paused;
        }
        false
    }

    /// Freeze a specific escrow so release and refund paths fail before any token transfer.
    ///
    /// Read-only queries remain available while the freeze is active.
    pub fn freeze_escrow(
        env: Env,
        bounty_id: u64,
        reason: Option<soroban_sdk::String>,
    ) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id))
            && !env
                .storage()
                .persistent()
                .has(&DataKey::EscrowAnon(bounty_id))
        {
            return Err(Error::BountyNotFound);
        }

        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let record = FreezeRecord {
            frozen: true,
            reason,
            frozen_at: env.ledger().timestamp(),
            frozen_by: admin,
        };
        env.storage()
            .persistent()
            .set(&DataKey::EscrowFreeze(bounty_id), &record);
        env.events()
            .publish((symbol_short!("frzesc"), bounty_id), record);
        Ok(())
    }

    /// Remove an escrow-level freeze and restore normal release/refund behavior.
    pub fn unfreeze_escrow(env: Env, bounty_id: u64) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id))
            && !env
                .storage()
                .persistent()
                .has(&DataKey::EscrowAnon(bounty_id))
        {
            return Err(Error::BountyNotFound);
        }

        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        env.storage()
            .persistent()
            .remove(&DataKey::EscrowFreeze(bounty_id));
        env.events().publish(
            (symbol_short!("unfrzes"), bounty_id),
            (admin, env.ledger().timestamp()),
        );
        Ok(())
    }

    /// Return the current escrow-level freeze record, if one exists.
    pub fn get_escrow_freeze_record(env: Env, bounty_id: u64) -> Option<FreezeRecord> {
        Self::get_escrow_freeze_record_internal(&env, bounty_id)
    }

    /// Returns the escrow record for `bounty_id`. Panics if not found.
    pub fn get_escrow(env: Env, bounty_id: u64) -> Escrow {
        env.storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .expect("bounty not found")
    }

    /// Freeze all release/refund operations for escrows owned by `address`.
    ///
    /// Read-only queries remain available while the freeze is active.
    pub fn freeze_address(
        env: Env,
        address: Address,
        reason: Option<soroban_sdk::String>,
    ) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let record = FreezeRecord {
            frozen: true,
            reason,
            frozen_at: env.ledger().timestamp(),
            frozen_by: admin,
        };
        env.storage()
            .persistent()
            .set(&DataKey::AddressFreeze(address.clone()), &record);
        env.events()
            .publish((symbol_short!("frzaddr"), address), record);
        Ok(())
    }

    /// Remove an address-level freeze and restore normal release/refund behavior.
    pub fn unfreeze_address(env: Env, address: Address) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        env.storage()
            .persistent()
            .remove(&DataKey::AddressFreeze(address.clone()));
        env.events().publish(
            (symbol_short!("unfrzad"), address),
            (admin, env.ledger().timestamp()),
        );
        Ok(())
    }

    /// Return the current address-level freeze record, if one exists.
    pub fn get_address_freeze_record(env: Env, address: Address) -> Option<FreezeRecord> {
        Self::get_address_freeze_record_internal(&env, &address)
    }

    /// Check if the contract is in maintenance mode
    pub fn is_maintenance_mode(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::MaintenanceMode)
            .unwrap_or(false)
    }

    /// Update maintenance mode (admin only)
    /// 
    /// # Timelock Guard
    /// When timelock is enabled, this function returns `TimelockEnabled`.
    /// Use `propose_admin_action` with `ActionType::SetMaintenanceMode` instead.
    pub fn set_maintenance_mode(env: Env, enabled: bool) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        
        // Timelock guard: reject direct calls when timelock is enabled
        Self::check_timelock_guard(&env)?;
        
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::MaintenanceMode, &enabled);

        events::emit_maintenance_mode_changed(
            &env,
            MaintenanceModeChanged {
                enabled,
                admin: admin.clone(),
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(())
    }

    // ============================================================================
    // TIMELOCK FUNCTIONS
    // ============================================================================

    /// Configure timelock settings (admin only).
    /// 
    /// # Arguments
    /// * `delay` - Timelock delay in seconds (must be between MINIMUM_DELAY and MAX_DELAY)
    /// * `is_enabled` - Whether timelock is enabled
    /// 
    /// # Errors
    /// * `NotInitialized` - Contract not initialized
    /// * `Unauthorized` - Caller not admin
    /// * `DelayBelowMinimum` - Delay < MINIMUM_DELAY
    /// * `DelayAboveMaximum` - Delay > MAX_DELAY
    /// 
    /// # Events
    /// * `TimelockConfigured` - Emitted when configuration changes
    /// 
    /// # Design Note
    /// This function bypasses the timelock (bootstrap problem). The initial admin
    /// must trust this function or the contract can never enable timelock protection.
    pub fn configure_timelock(env: Env, delay: u64, is_enabled: bool) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        // Validate delay bounds if timelock is being enabled
        if is_enabled {
            if delay < MINIMUM_DELAY {
                return Err(Error::DelayBelowMinimum);
            }
            if delay > MAX_DELAY {
                return Err(Error::DelayAboveMaximum);
            }
        }

        let config = TimelockConfig { delay, is_enabled };
        env.storage()
            .instance()
            .set(&DataKey::TimelockConfig, &config);

        emit_timelock_configured(
            &env,
            TimelockConfigured {
                version: EVENT_VERSION_V2,
                delay,
                is_enabled,
                configured_by: admin,
                timestamp: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    /// Get current timelock configuration
    pub fn get_timelock_config(env: Env) -> TimelockConfig {
        env.storage()
            .instance()
            .get(&DataKey::TimelockConfig)
            .unwrap_or(TimelockConfig {
                delay: DEFAULT_DELAY,
                is_enabled: false,
            })
    }

    /// Propose an admin action with optional timelock delay.
    /// 
    /// If timelock is disabled, executes immediately and returns 0.
    /// If timelock is enabled, creates a pending action and returns the action_id.
    /// 
    /// # Arguments
    /// * `action_type` - Type of admin action
    /// * `payload` - Action-specific parameters
    /// 
    /// # Returns
    /// * `u64` - Action ID if pending, 0 if executed immediately
    /// 
    /// # Errors
    /// * `NotInitialized` - Contract not initialized
    /// * `Unauthorized` - Caller not admin
    /// * `InvalidPayload` - Payload doesn't match action type
    /// * `TimelockNotEnabled` - Shouldn't happen (logic error)
    pub fn propose_admin_action(
        env: Env,
        action_type: ActionType,
        payload: ActionPayload,
    ) -> Result<u64, Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        // Validate payload matches action type
        Self::validate_payload_matches_action_type(&action_type, &payload)?;

        let timelock_config = Self::get_timelock_config(env.clone());

        if !timelock_config.is_enabled {
            // Execute immediately - bypass timelock
            Self::execute_action(env.clone(), payload.clone())?;
            return Ok(0); // Signal immediate execution
        }

        // Create pending action
        let action_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ActionCounter)
            .unwrap_or(0)
            .checked_add(1)
            .unwrap_or(0);

        let current_timestamp = env.ledger().timestamp();
        let execute_after = current_timestamp
            .checked_add(timelock_config.delay)
            .unwrap_or(current_timestamp);

        // Serialize payload for storage
        let serialized_payload = env.to_val(&payload).try_to_val::<Bytes, _>(&env).unwrap_or(Bytes::new(&env));

        let pending_action = PendingAction {
            action_id,
            action_type,
            payload: serialized_payload,
            proposed_by: admin.clone(),
            proposed_at: current_timestamp,
            execute_after,
            status: ActionStatus::Pending,
        };

        // Store the action and increment counter
        env.storage()
            .persistent()
            .set(&DataKey::PendingAction(action_id), &pending_action);
        env.storage()
            .instance()
            .set(&DataKey::ActionCounter, &action_id);

        emit_admin_action_proposed(
            &env,
            AdminActionProposed {
                version: EVENT_VERSION_V2,
                action_type,
                execute_after,
                proposed_by: admin,
                timestamp: current_timestamp,
            },
        );

        Ok(action_id)
    }

    /// Execute a pending admin action after the timelock delay.
    /// 
    /// Anyone can call this function - it's permissionless by design.
    /// The action will only execute if the delay has elapsed.
    /// 
    /// # Arguments
    /// * `action_id` - ID of the pending action
    /// 
    /// # Errors
    /// * `ActionNotFound` - Action doesn't exist
    /// * `ActionAlreadyExecuted` - Action already executed
    /// * `ActionAlreadyCancelled` - Action already cancelled
    /// * `TimelockNotElapsed` - Delay hasn't elapsed yet
    pub fn execute_after_delay(env: Env, action_id: u64) -> Result<(), Error> {
        // Load pending action
        let mut action: PendingAction = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAction(action_id))
            .ok_or(Error::ActionNotFound)?;

        // Check status
        if action.status == ActionStatus::Executed {
            return Err(Error::ActionAlreadyExecuted);
        }
        if action.status == ActionStatus::Cancelled {
            return Err(Error::ActionAlreadyCancelled);
        }

        // Check timelock elapsed
        let current_timestamp = env.ledger().timestamp();
        if current_timestamp < action.execute_after {
            return Err(Error::TimelockNotElapsed);
        }

        // Deserialize payload
        let payload: ActionPayload = env.from_val(&action.payload);

        // Execute the action
        Self::execute_action(env.clone(), payload.clone())?;

        // Update status
        action.status = ActionStatus::Executed;
        env.storage()
            .persistent()
            .set(&DataKey::PendingAction(action_id), &action);

        emit_admin_action_executed(
            &env,
            AdminActionExecuted {
                version: EVENT_VERSION_V2,
                action_type: action.action_type,
                executed_by: env.current_contract_address(), // Any caller can execute
                executed_at: current_timestamp,
            },
        );

        Ok(())
    }

    /// Cancel a pending admin action (admin only).
    /// 
    /// # Arguments
    /// * `action_id` - ID of the pending action
    /// 
    /// # Errors
    /// * `NotInitialized` - Contract not initialized
    /// * `Unauthorized` - Caller not admin
    /// * `ActionNotFound` - Action doesn't exist
    /// * `ActionAlreadyExecuted` - Action already executed
    /// * `ActionAlreadyCancelled` - Action already cancelled
    pub fn cancel_admin_action(env: Env, action_id: u64) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        // Load pending action
        let mut action: PendingAction = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAction(action_id))
            .ok_or(Error::ActionNotFound)?;

        // Check status
        if action.status == ActionStatus::Executed {
            return Err(Error::ActionAlreadyExecuted);
        }
        if action.status == ActionStatus::Cancelled {
            return Err(Error::ActionAlreadyCancelled);
        }

        // Update status
        action.status = ActionStatus::Cancelled;
        env.storage()
            .persistent()
            .set(&DataKey::PendingAction(action_id), &action);

        emit_admin_action_cancelled(
            &env,
            AdminActionCancelled {
                version: EVENT_VERSION_V2,
                action_type: action.action_type,
                cancelled_by: admin,
                cancelled_at: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    /// Get all pending admin actions ordered by proposal time.
    /// 
    /// This provides public visibility into proposed admin actions.
    pub fn get_pending_actions(env: Env) -> Vec<PendingAction> {
        let mut pending = Vec::new(&env);
        
        // Get the action counter to know the range to search
        let counter: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ActionCounter)
            .unwrap_or(0);

        // Collect all pending actions
        for action_id in 1..=counter {
            if let Some(action) = env.storage().persistent().get(&DataKey::PendingAction(action_id)) {
                if action.status == ActionStatus::Pending {
                    pending.push_back(action);
                }
            }
        }

        // Sort by proposed_at (earliest first)
        pending.sort(|a, b| a.proposed_at.cmp(&b.proposed_at));
        pending
    }

    /// Get a specific admin action by ID.
    /// 
    /// # Errors
    /// * `ActionNotFound` - Action doesn't exist
    pub fn get_action(env: Env, action_id: u64) -> Result<PendingAction, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::PendingAction(action_id))
            .ok_or(Error::ActionNotFound)
    }

    // ============================================================================
    // PRIVATE TIMELOCK HELPERS
    // ============================================================================

    /// Check if timelock is enabled and reject direct admin calls if so
    fn check_timelock_guard(env: &Env) -> Result<(), Error> {
        let timelock_config = Self::get_timelock_config(env.clone());
        if timelock_config.is_enabled {
            return Err(Error::TimelockEnabled);
        }
        Ok(())
    }

    /// Validate that payload matches the expected action type
    fn validate_payload_matches_action_type(
        action_type: &ActionType,
        payload: &ActionPayload,
    ) -> Result<(), Error> {
        match (action_type, payload) {
            (ActionType::ChangeAdmin, ActionPayload::ChangeAdmin { .. }) => Ok(()),
            (ActionType::ChangeFeeRecipient, ActionPayload::ChangeFeeRecipient { .. }) => Ok(()),
            (ActionType::EnableKillSwitch, ActionPayload::EnableKillSwitch {}) => Ok(()),
            (ActionType::DisableKillSwitch, ActionPayload::DisableKillSwitch {}) => Ok(()),
            (ActionType::SetMaintenanceMode, ActionPayload::SetMaintenanceMode { .. }) => Ok(()),
            (ActionType::UnsetMaintenanceMode, ActionPayload::SetMaintenanceMode { .. }) => Ok(()),
            (ActionType::SetPaused, ActionPayload::SetPaused { .. }) => Ok(()),
            (ActionType::UnsetPaused, ActionPayload::SetPaused { .. }) => Ok(()),
            _ => Err(Error::InvalidPayload),
        }
    }

    /// Execute an admin action (bypasses all auth checks)
    fn execute_action(env: Env, payload: ActionPayload) -> Result<(), Error> {
        match payload {
            ActionPayload::ChangeAdmin { new_admin } => {
                Self::_execute_change_admin(env, new_admin)
            }
            ActionPayload::ChangeFeeRecipient { new_recipient } => {
                Self::_execute_change_fee_recipient(env, new_recipient)
            }
            ActionPayload::EnableKillSwitch {} => {
                Self::_execute_set_deprecated(env, true, None)
            }
            ActionPayload::DisableKillSwitch {} => {
                Self::_execute_set_deprecated(env, false, None)
            }
            ActionPayload::SetMaintenanceMode { enabled } => {
                Self::_execute_set_maintenance_mode(env, enabled)
            }
            ActionPayload::SetPaused { lock, release, refund } => {
                Self::_execute_set_paused(env, lock, release, refund, None)
            }
        }
    }

    // ============================================================================
    // PRIVATE EXECUTION HELPERS (called by timelock)
    // ============================================================================

    /// Private helper to change admin without auth checks
    fn _execute_change_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        env.storage()
            .instance()
            .set(&DataKey::Admin, &new_admin);
        Ok(())
    }

    /// Private helper to change fee recipient without auth checks
    fn _execute_change_fee_recipient(env: Env, new_recipient: Address) -> Result<(), Error> {
        let mut fee_config = Self::get_fee_config_internal(&env);
        fee_config.fee_recipient = new_recipient;
        env.storage()
            .instance()
            .set(&DataKey::FeeConfig, &fee_config);

        events::emit_fee_config_updated(
            &env,
            events::FeeConfigUpdated {
                lock_fee_rate: fee_config.lock_fee_rate,
                release_fee_rate: fee_config.release_fee_rate,
                lock_fixed_fee: fee_config.lock_fixed_fee,
                release_fixed_fee: fee_config.release_fixed_fee,
                fee_recipient: fee_config.fee_recipient.clone(),
                fee_enabled: fee_config.fee_enabled,
                timestamp: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    /// Private helper to set deprecation without auth checks
    fn _execute_set_deprecated(env: Env, deprecated: bool, migration_target: Option<Address>) -> Result<(), Error> {
        let state = DeprecationState {
            deprecated,
            migration_target: migration_target.clone(),
        };
        env.storage()
            .instance()
            .set(&DataKey::DeprecationState, &state);
        
        emit_deprecation_state_changed(
            &env,
            DeprecationStateChanged {
                deprecated: state.deprecated,
                migration_target: state.migration_target,
                admin: rbac::require_admin(&env), // For event purposes
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(())
    }

    /// Private helper to set maintenance mode without auth checks
    fn _execute_set_maintenance_mode(env: Env, enabled: bool) -> Result<(), Error> {
        env.storage()
            .instance()
            .set(&DataKey::MaintenanceMode, &enabled);

        events::emit_maintenance_mode_changed(
            &env,
            MaintenanceModeChanged {
                enabled,
                admin: rbac::require_admin(&env), // For event purposes
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(())
    }

    /// Private helper to set pause flags without auth checks
    fn _execute_set_paused(
        env: Env,
        lock: Option<bool>,
        release: Option<bool>,
        refund: Option<bool>,
        reason: Option<soroban_sdk::String>,
    ) -> Result<(), Error> {
        let mut flags = Self::get_pause_flags(&env);

        if let Some(lock_paused) = lock {
            flags.lock_paused = lock_paused;
        }
        if let Some(release_paused) = release {
            flags.release_paused = release_paused;
        }
        if let Some(refund_paused) = refund {
            flags.refund_paused = refund_paused;
        }
        if reason.is_some() {
            flags.pause_reason = reason;
        }
        if lock.is_some() || release.is_some() || refund.is_some() {
            flags.paused_at = env.ledger().timestamp();
        }

        env.storage()
            .instance()
            .set(&DataKey::PauseFlags, &flags);

        Ok(())
    }

    pub fn set_whitelist(env: Env, address: Address, whitelisted: bool) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        anti_abuse::set_whitelist(&env, address, whitelisted);
        Ok(())
    }

    fn next_capability_id(env: &Env) -> BytesN<32> {
        let mut id = [0u8; 32];
        let r1: u64 = env.prng().gen();
        let r2: u64 = env.prng().gen();
        let r3: u64 = env.prng().gen();
        let r4: u64 = env.prng().gen();
        id[0..8].copy_from_slice(&r1.to_be_bytes());
        id[8..16].copy_from_slice(&r2.to_be_bytes());
        id[16..24].copy_from_slice(&r3.to_be_bytes());
        id[24..32].copy_from_slice(&r4.to_be_bytes());
        BytesN::from_array(env, &id)
    }

    fn record_receipt(
        _env: &Env,
        _outcome: CriticalOperationOutcome,
        _bounty_id: u64,
        _amount: i128,
        _recipient: Address,
    ) {
        // Backward-compatible no-op until receipt storage/events are fully wired.
    }

    fn load_capability(env: &Env, capability_id: BytesN<32>) -> Result<Capability, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Capability(capability_id.clone()))
            .ok_or(Error::CapabilityNotFound)
    }

    fn validate_capability_scope_at_issue(
        env: &Env,
        owner: &Address,
        action: &CapabilityAction,
        bounty_id: u64,
        amount_limit: i128,
    ) -> Result<(), Error> {
        if amount_limit <= 0 {
            return Err(Error::InvalidAmount);
        }

        match action {
            CapabilityAction::Claim => {
                let claim: ClaimRecord = env
                    .storage()
                    .persistent()
                    .get(&DataKey::PendingClaim(bounty_id))
                    .ok_or(Error::BountyNotFound)?;
                if claim.claimed {
                    return Err(Error::FundsNotLocked);
                }
                if env.ledger().timestamp() > claim.expires_at {
                    return Err(Error::DeadlineNotPassed);
                }
                if claim.recipient != owner.clone() {
                    return Err(Error::Unauthorized);
                }
                if amount_limit > claim.amount {
                    return Err(Error::CapabilityExceedsAuthority);
                }
            }
            CapabilityAction::Release => {
                let admin: Address = env
                    .storage()
                    .instance()
                    .get(&DataKey::Admin)
                    .ok_or(Error::NotInitialized)?;
                if admin != owner.clone() {
                    return Err(Error::Unauthorized);
                }
                let escrow: Escrow = env
                    .storage()
                    .persistent()
                    .get(&DataKey::Escrow(bounty_id))
                    .ok_or(Error::BountyNotFound)?;
                if escrow.status != EscrowStatus::Locked {
                    return Err(Error::FundsNotLocked);
                }
                if amount_limit > escrow.remaining_amount {
                    return Err(Error::CapabilityExceedsAuthority);
                }
            }
            CapabilityAction::Refund => {
                let admin: Address = env
                    .storage()
                    .instance()
                    .get(&DataKey::Admin)
                    .ok_or(Error::NotInitialized)?;
                if admin != owner.clone() {
                    return Err(Error::Unauthorized);
                }
                let escrow: Escrow = env
                    .storage()
                    .persistent()
                    .get(&DataKey::Escrow(bounty_id))
                    .ok_or(Error::BountyNotFound)?;
                if escrow.status != EscrowStatus::Locked
                    && escrow.status != EscrowStatus::PartiallyRefunded
                {
                    return Err(Error::FundsNotLocked);
                }
                if amount_limit > escrow.remaining_amount {
                    return Err(Error::CapabilityExceedsAuthority);
                }
            }
        }

        Ok(())
    }

    fn ensure_owner_still_authorized(
        env: &Env,
        capability: &Capability,
        requested_amount: i128,
    ) -> Result<(), Error> {
        if requested_amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        match capability.action {
            CapabilityAction::Claim => {
                let claim: ClaimRecord = env
                    .storage()
                    .persistent()
                    .get(&DataKey::PendingClaim(capability.bounty_id))
                    .ok_or(Error::BountyNotFound)?;
                if claim.claimed {
                    return Err(Error::FundsNotLocked);
                }
                if env.ledger().timestamp() > claim.expires_at {
                    return Err(Error::DeadlineNotPassed);
                }
                if claim.recipient != capability.owner {
                    return Err(Error::Unauthorized);
                }
                if requested_amount > claim.amount {
                    return Err(Error::CapabilityExceedsAuthority);
                }
            }
            CapabilityAction::Release => {
                let admin: Address = env
                    .storage()
                    .instance()
                    .get(&DataKey::Admin)
                    .ok_or(Error::NotInitialized)?;
                if admin != capability.owner {
                    return Err(Error::Unauthorized);
                }
                let escrow: Escrow = env
                    .storage()
                    .persistent()
                    .get(&DataKey::Escrow(capability.bounty_id))
                    .ok_or(Error::BountyNotFound)?;
                if escrow.status != EscrowStatus::Locked {
                    return Err(Error::FundsNotLocked);
                }
                if requested_amount > escrow.remaining_amount {
                    return Err(Error::CapabilityExceedsAuthority);
                }
            }
            CapabilityAction::Refund => {
                let admin: Address = env
                    .storage()
                    .instance()
                    .get(&DataKey::Admin)
                    .ok_or(Error::NotInitialized)?;
                if admin != capability.owner {
                    return Err(Error::Unauthorized);
                }
                let escrow: Escrow = env
                    .storage()
                    .persistent()
                    .get(&DataKey::Escrow(capability.bounty_id))
                    .ok_or(Error::BountyNotFound)?;
                if escrow.status != EscrowStatus::Locked
                    && escrow.status != EscrowStatus::PartiallyRefunded
                {
                    return Err(Error::FundsNotLocked);
                }
                if requested_amount > escrow.remaining_amount {
                    return Err(Error::CapabilityExceedsAuthority);
                }
            }
        }
        Ok(())
    }

    /// Validates and consumes a capability token for a specific action.
    ///
    /// The capability token must be a secure `BytesN<32>` identifier explicitly issued
    /// to the requested `holder` for the requested `bounty_id` and `expected_action`.
    /// Consuming a capability securely updates its internal balance and usage counts,
    /// protecting against replay attacks or brute-force forgery.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `holder` - The address attempting to consume the capability
    /// * `capability_id` - The `BytesN<32>` unforgeable token identifier
    /// * `expected_action` - The required action mapped to this capability
    /// * `bounty_id` - The bounty ID relating to the action
    /// * `amount` - The transaction value requested during this consumption limit
    ///
    /// # Returns
    /// The updated `Capability` struct successfully verified, or an `Error`.
    fn consume_capability(
        env: &Env,
        holder: &Address,
        capability_id: BytesN<32>,
        expected_action: CapabilityAction,
        bounty_id: u64,
        amount: i128,
    ) -> Result<Capability, Error> {
        let mut capability = Self::load_capability(env, capability_id.clone())?;

        if capability.revoked {
            return Err(Error::CapabilityRevoked);
        }
        if capability.action != expected_action {
            return Err(Error::CapabilityActionMismatch);
        }
        if capability.bounty_id != bounty_id {
            return Err(Error::CapabilityActionMismatch);
        }
        if capability.holder != holder.clone() {
            return Err(Error::Unauthorized);
        }
        if env.ledger().timestamp() > capability.expiry {
            return Err(Error::CapabilityExpired);
        }
        if capability.remaining_uses == 0 {
            return Err(Error::CapabilityUsesExhausted);
        }
        if amount > capability.remaining_amount {
            return Err(Error::CapabilityAmountExceeded);
        }

        holder.require_auth();
        Self::ensure_owner_still_authorized(env, &capability, amount)?;

        capability.remaining_amount -= amount;
        capability.remaining_uses -= 1;
        env.storage()
            .persistent()
            .set(&DataKey::Capability(capability_id.clone()), &capability);

        events::emit_capability_used(
            env,
            events::CapabilityUsed {
                capability_id,
                holder: holder.clone(),
                action: capability.action.clone(),
                bounty_id,
                amount_used: amount,
                remaining_amount: capability.remaining_amount,
                remaining_uses: capability.remaining_uses,
                used_at: env.ledger().timestamp(),
            },
        );

        Ok(capability)
    }

    /// Issues a new capability token for a specific action on a bounty.
    ///
    /// The capability token is represented by a secure, unforgeable `BytesN<32>` identifier
    /// generated using the Soroban environment's pseudo-random number generator (PRNG).
    /// This ensures that capability tokens cannot be predicted or forged by arbitrary addresses.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The address delegating authority (e.g. the bounty admin or depositor)
    /// * `holder` - The address receiving the capability token
    /// * `action` - The specific action authorized (`Release`, `Refund`, etc.)
    /// * `bounty_id` - The bounty this capability applies to
    /// * `amount_limit` - The maximum amount of funds authorized by this capability
    /// * `expiry` - The ledger timestamp when this capability expires
    /// * `max_uses` - The maximum number of times this capability can be consumed
    ///
    /// # Returns
    /// The generated `BytesN<32>` capability identifier, or an `Error` if issuance fails.
    pub fn issue_capability(
        env: Env,
        owner: Address,
        holder: Address,
        action: CapabilityAction,
        bounty_id: u64,
        amount_limit: i128,
        expiry: u64,
        max_uses: u32,
    ) -> Result<BytesN<32>, Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        if max_uses == 0 {
            return Err(Error::InvalidAmount);
        }

        let now = env.ledger().timestamp();
        if expiry <= now {
            return Err(Error::InvalidDeadline);
        }

        owner.require_auth();
        Self::validate_capability_scope_at_issue(&env, &owner, &action, bounty_id, amount_limit)?;

        let capability_id = Self::next_capability_id(&env);
        let capability = Capability {
            owner: owner.clone(),
            holder: holder.clone(),
            action: action.clone(),
            bounty_id,
            amount_limit,
            remaining_amount: amount_limit,
            expiry,
            remaining_uses: max_uses,
            revoked: false,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Capability(capability_id.clone()), &capability);

        events::emit_capability_issued(
            &env,
            events::CapabilityIssued {
                capability_id: capability_id.clone(),
                owner,
                holder,
                action,
                bounty_id,
                amount_limit,
                expires_at: expiry,
                max_uses,
                timestamp: now,
            },
        );

        Ok(capability_id.clone())
    }

    pub fn revoke_capability(
        env: Env,
        owner: Address,
        capability_id: BytesN<32>,
    ) -> Result<(), Error> {
        let mut capability = Self::load_capability(&env, capability_id.clone())?;
        if capability.owner != owner {
            return Err(Error::Unauthorized);
        }
        owner.require_auth();

        if capability.revoked {
            return Ok(());
        }

        capability.revoked = true;
        env.storage()
            .persistent()
            .set(&DataKey::Capability(capability_id.clone()), &capability);

        events::emit_capability_revoked(
            &env,
            events::CapabilityRevoked {
                capability_id,
                owner,
                revoked_at: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    pub fn get_capability(env: Env, capability_id: BytesN<32>) -> Result<Capability, Error> {
        Self::load_capability(&env, capability_id.clone())
    }

    /// Get current fee configuration (view function)
    pub fn get_fee_config(env: Env) -> FeeConfig {
        Self::get_fee_config_internal(&env)
    }

    /// Set a per-token fee configuration (admin only).
    ///
    /// When a `TokenFeeConfig` is set for a given token address it takes
    /// precedence over the global `FeeConfig` for all escrows denominated
    /// in that token.
    ///
    /// # Arguments
    /// * `token`            – the token contract address this config applies to
    /// * `lock_fee_rate`    – fee rate on lock in basis points (0 – 5 000)
    /// * `release_fee_rate` – fee rate on release in basis points (0 – 5 000)
    /// * `lock_fixed_fee` / `release_fixed_fee` – flat fees in token units (≥ 0)
    /// * `fee_recipient`    – address that receives fees for this token
    /// * `fee_enabled`      – whether fee collection is active
    ///
    /// # Errors
    /// * `NotInitialized`  – contract not yet initialised
    /// * `InvalidFeeRate`  – any rate is outside `[0, MAX_FEE_RATE]`
    pub fn set_token_fee_config(
        env: Env,
        token: Address,
        lock_fee_rate: i128,
        release_fee_rate: i128,
        lock_fixed_fee: i128,
        release_fixed_fee: i128,
        fee_recipient: Address,
        fee_enabled: bool,
    ) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        if !(0..=MAX_FEE_RATE).contains(&lock_fee_rate) {
            return Err(Error::InvalidFeeRate);
        }
        if !(0..=MAX_FEE_RATE).contains(&release_fee_rate) {
            return Err(Error::InvalidFeeRate);
        }
        if lock_fixed_fee < 0 || release_fixed_fee < 0 {
            return Err(Error::InvalidAmount);
        }

        let config = TokenFeeConfig {
            lock_fee_rate,
            release_fee_rate,
            lock_fixed_fee,
            release_fixed_fee,
            fee_recipient,
            fee_enabled,
        };

        env.storage()
            .instance()
            .set(&DataKey::TokenFeeConfig(token), &config);

        Ok(())
    }

    /// Get the per-token fee configuration for `token`, if one has been set.
    ///
    /// Returns `None` when no token-specific config exists; callers should
    /// fall back to the global `FeeConfig` in that case.
    pub fn get_token_fee_config(env: Env, token: Address) -> Option<TokenFeeConfig> {
        env.storage()
            .instance()
            .get(&DataKey::TokenFeeConfig(token))
    }

    /// Internal: resolve the effective fee config for the escrow token.
    ///
    /// Precedence: `TokenFeeConfig(token)` > global `FeeConfig`.
    fn resolve_fee_config(env: &Env) -> (i128, i128, i128, i128, Address, bool) {
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        if let Some(tok_cfg) = env
            .storage()
            .instance()
            .get::<DataKey, TokenFeeConfig>(&DataKey::TokenFeeConfig(token_addr))
        {
            (
                tok_cfg.lock_fee_rate,
                tok_cfg.release_fee_rate,
                tok_cfg.lock_fixed_fee,
                tok_cfg.release_fixed_fee,
                tok_cfg.fee_recipient,
                tok_cfg.fee_enabled,
            )
        } else {
            let global = Self::get_fee_config_internal(env);
            (
                global.lock_fee_rate,
                global.release_fee_rate,
                global.lock_fixed_fee,
                global.release_fixed_fee,
                global.fee_recipient,
                global.fee_enabled,
            )
        }
    }

    /// Update multisig configuration (admin only)
    pub fn update_multisig_config(
        env: Env,
        threshold_amount: i128,
        signers: Vec<Address>,
        required_signatures: u32,
    ) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }

        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        if required_signatures > signers.len() {
            return Err(Error::InvalidAmount);
        }

        let config = MultisigConfig {
            threshold_amount,
            signers,
            required_signatures,
        };

        env.storage()
            .instance()
            .set(&DataKey::MultisigConfig, &config);

        Ok(())
    }

    /// Get multisig configuration
    pub fn get_multisig_config(env: Env) -> MultisigConfig {
        env.storage()
            .instance()
            .get(&DataKey::MultisigConfig)
            .unwrap_or(MultisigConfig {
                threshold_amount: i128::MAX,
                signers: vec![&env],
                required_signatures: 0,
            })
    }

    /// Approve release for large amount (requires multisig)
    pub fn approve_large_release(
        env: Env,
        bounty_id: u64,
        contributor: Address,
        approver: Address,
    ) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }

        let multisig_config: MultisigConfig = Self::get_multisig_config(env.clone());

        let mut is_signer = false;
        for signer in multisig_config.signers.iter() {
            if signer == approver {
                is_signer = true;
                break;
            }
        }

        if !is_signer {
            return Err(Error::Unauthorized);
        }

        approver.require_auth();

        let approval_key = DataKey::ReleaseApproval(bounty_id);
        let mut approval: ReleaseApproval = env
            .storage()
            .persistent()
            .get(&approval_key)
            .unwrap_or(ReleaseApproval {
                bounty_id,
                contributor: contributor.clone(),
                approvals: vec![&env],
            });

        for existing in approval.approvals.iter() {
            if existing == approver {
                return Ok(());
            }
        }

        approval.approvals.push_back(approver.clone());
        env.storage().persistent().set(&approval_key, &approval);

        events::emit_approval_added(
            &env,
            events::ApprovalAdded {
                bounty_id,
                contributor: contributor.clone(),
                approver,
                timestamp: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    /// Locks funds for a bounty and records escrow state.
    ///
    /// # Security
    /// - Validation order is deterministic to avoid ambiguous failure behavior under contention.
    /// - Reentrancy guard is acquired before validation and released on completion.
    ///
    /// # Errors
    /// Returns `Error` variants for initialization, policy, authorization, and duplicate-bounty
    /// failures.
    pub fn lock_funds(
        env: Env,
        depositor: Address,
        bounty_id: u64,
        amount: i128,
        deadline: u64,
    ) -> Result<(), Error> {
        let res =
            Self::lock_funds_logic(env.clone(), depositor.clone(), bounty_id, amount, deadline);
        monitoring::track_operation(&env, symbol_short!("lock"), depositor, res.is_ok());
        res
    }

    fn lock_funds_logic(
        env: Env,
        depositor: Address,
        bounty_id: u64,
        amount: i128,
        deadline: u64,
    ) -> Result<(), Error> {
        // Validation precedence (deterministic ordering):
        // 1. Reentrancy guard
        // 2. Contract initialized
        // 3. Paused / deprecated (operational state)
        // 4. Participant filter + rate limiting
        // 5. Authorization
        // 6. Input validation (amount policy)
        // 7. Business logic (bounty uniqueness)

        // 1. GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);
        // Snapshot resource meters for gas cap enforcement (test / testutils only).
        #[cfg(any(test, feature = "testutils"))]
        let gas_snapshot = gas_budget::capture(&env);

        // 2. Contract must be initialized before any other check
        if !env.storage().instance().has(&DataKey::Admin) {
            reentrancy_guard::release(&env);
            return Err(Error::NotInitialized);
        }
        soroban_sdk::log!(&env, "admin ok");

        // 3. Operational state: paused / deprecated
        if Self::check_paused(&env, symbol_short!("lock")) {
            reentrancy_guard::release(&env);
            return Err(Error::FundsPaused);
        }
        if Self::get_deprecation_state(&env).deprecated {
            reentrancy_guard::release(&env);
            return Err(Error::ContractDeprecated);
        }
        soroban_sdk::log!(&env, "check paused ok");

        // 4. Participant filtering and rate limiting
        Self::check_participant_filter(&env, depositor.clone())?;
        soroban_sdk::log!(&env, "start lock_funds");
        anti_abuse::check_rate_limit(&env, depositor.clone());
        soroban_sdk::log!(&env, "rate limit ok");

        let _start = env.ledger().timestamp();
        let _caller = depositor.clone();

        // 5. Authorization
        depositor.require_auth();
        soroban_sdk::log!(&env, "auth ok");

        // 6. Input validation: amount policy
        // Enforce min/max amount policy if one has been configured (Issue #62).
        if let Some((min_amount, max_amount)) = env
            .storage()
            .instance()
            .get::<DataKey, (i128, i128)>(&DataKey::AmountPolicy)
        {
            if amount < min_amount {
                reentrancy_guard::release(&env);
                return Err(Error::AmountBelowMinimum);
            }
            if amount > max_amount {
                reentrancy_guard::release(&env);
                return Err(Error::AmountAboveMaximum);
            }
        }
        soroban_sdk::log!(&env, "amount policy ok");

        // 7. Business logic: bounty must not already exist
        if env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            reentrancy_guard::release(&env);
            return Err(Error::BountyExists);
        }
        soroban_sdk::log!(&env, "bounty exists ok");

        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);
        soroban_sdk::log!(&env, "token client ok");

        // Transfer full gross amount from depositor to contract first.
        client.transfer(&depositor, &env.current_contract_address(), &amount);
        soroban_sdk::log!(&env, "transfer ok");

        // Resolve effective fee config (per-token takes precedence over global).
        let (
            lock_fee_rate,
            _release_fee_rate,
            lock_fixed_fee,
            _release_fixed,
            fee_recipient,
            fee_enabled,
        ) = Self::resolve_fee_config(&env);

        // Deduct lock fee from the escrowed principal (percentage + fixed, capped at deposit).
        let fee_amount =
            Self::combined_fee_amount(amount, lock_fee_rate, lock_fixed_fee, fee_enabled);

        // Net amount stored in escrow after fee.
        // Fee must never exceed the deposit; guard against misconfiguration.
        let net_amount = amount.checked_sub(fee_amount).unwrap_or(amount);
        if net_amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        // Transfer fee to recipient immediately (separate transfer so it is
        // visible as a distinct on-chain operation).
        if fee_amount > 0 {
            let global_config = Self::get_fee_config_internal(&env);
            Self::route_fee(
                &env,
                &client,
                fee_amount,
                &fee_recipient,
                global_config.distribution_enabled,
                &global_config.treasury_destinations,
            );
        }
        soroban_sdk::log!(&env, "fee ok");

        let escrow = Escrow {
            depositor: depositor.clone(),
            amount: net_amount,
            status: EscrowStatus::Locked,
            deadline,
            refund_history: vec![&env],
            remaining_amount: net_amount,
            archived: false,
            archived_at: None,
        };
        invariants::assert_escrow(&env, &escrow);

        // Extend the TTL of the storage entry to ensure it lives long enough
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        // Update indexes
        let mut index: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::EscrowIndex)
            .unwrap_or(Vec::new(&env));
        index.push_back(bounty_id);
        env.storage()
            .persistent()
            .set(&DataKey::EscrowIndex, &index);

        let mut depositor_index: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::DepositorIndex(depositor.clone()))
            .unwrap_or(Vec::new(&env));
        depositor_index.push_back(bounty_id);
        env.storage().persistent().set(
            &DataKey::DepositorIndex(depositor.clone()),
            &depositor_index,
        );

        // Emit value allows for off-chain indexing
        emit_funds_locked(
            &env,
            FundsLocked {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount,
                depositor: depositor.clone(),
                deadline,
            },
        );

        // INV-2: Verify aggregate balance matches token balance after lock
        multitoken_invariants::assert_after_lock(&env);

        // Gas budget cap enforcement (test / testutils only; see `gas_budget` module docs).
        #[cfg(any(test, feature = "testutils"))]
        {
            let gas_cfg = gas_budget::get_config(&env);
            if let Err(e) = gas_budget::check(
                &env,
                symbol_short!("lock"),
                &gas_cfg.lock,
                &gas_snapshot,
                gas_cfg.enforce,
            ) {
                reentrancy_guard::release(&env);
                return Err(e);
            }
        }
        audit_trail::log_action(&env, symbol_short!("lock"), depositor.clone(), bounty_id);
        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Simulate lock operation without state changes or token transfers.
    ///
    /// Returns a `SimulationResult` indicating whether the operation would succeed and the
    /// resulting escrow state. Does not require authorization; safe for off-chain preview.
    ///
    /// # Arguments
    /// * `depositor` - Address that would lock funds
    /// * `bounty_id` - Bounty identifier
    /// * `amount` - Amount to lock
    /// * `deadline` - Deadline timestamp
    ///
    /// # Security
    /// This function performs only read operations. No storage writes, token transfers,
    /// or events are emitted.
    pub fn archive_escrow(env: Env, bounty_id: u64) -> Result<(), Error> {
        let admin = rbac::require_admin(&env);
        admin.require_auth();

        let mut escrow = env
            .storage()
            .persistent()
            .get::<DataKey, Escrow>(&DataKey::Escrow(bounty_id))
            .ok_or(Error::BountyNotFound)?;

        escrow.archived = true;
        escrow.archived_at = Some(env.ledger().timestamp());

        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        // Also check anon escrow
        if let Some(mut anon) = env
            .storage()
            .persistent()
            .get::<DataKey, AnonymousEscrow>(&DataKey::EscrowAnon(bounty_id))
        {
            anon.archived = true;
            anon.archived_at = Some(env.ledger().timestamp());
            env.storage()
                .persistent()
                .set(&DataKey::EscrowAnon(bounty_id), &anon);
        }

        events::emit_archived(&env, bounty_id, env.ledger().timestamp());
        Ok(())
    }

    /// Get all archived escrow IDs.
    pub fn get_archived_escrows(env: Env) -> Vec<u64> {
        let index: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::EscrowIndex)
            .unwrap_or(Vec::new(&env));
        let mut archived = Vec::new(&env);
        for id in index.iter() {
            if let Some(escrow) = env
                .storage()
                .persistent()
                .get::<DataKey, Escrow>(&DataKey::Escrow(id))
            {
                if escrow.archived {
                    archived.push_back(id);
                }
            } else if let Some(anon) = env
                .storage()
                .persistent()
                .get::<DataKey, AnonymousEscrow>(&DataKey::EscrowAnon(id))
            {
                if anon.archived {
                    archived.push_back(id);
                }
            }
        }
        archived
    }

    /// Simulation of a lock operation.
    pub fn dry_run_lock(
        env: Env,
        depositor: Address,
        bounty_id: u64,
        amount: i128,
        deadline: u64,
    ) -> SimulationResult {
        fn err_result(e: Error) -> SimulationResult {
            SimulationResult {
                success: false,
                error_code: e as u32,
                amount: 0,
                resulting_status: EscrowStatus::Locked,
                remaining_amount: 0,
            }
        }
        match Self::dry_run_lock_impl(&env, depositor, bounty_id, amount, deadline) {
            Ok((net_amount,)) => SimulationResult {
                success: true,
                error_code: 0,
                amount: net_amount,
                resulting_status: EscrowStatus::Locked,
                remaining_amount: net_amount,
            },
            Err(e) => err_result(e),
        }
    }

    fn dry_run_lock_impl(
        env: &Env,
        depositor: Address,
        bounty_id: u64,
        amount: i128,
        _deadline: u64,
    ) -> Result<(i128,), Error> {
        // 1. Contract must be initialized
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        // 2. Operational state: paused / deprecated
        if Self::check_paused(env, symbol_short!("lock")) {
            return Err(Error::FundsPaused);
        }
        if Self::get_deprecation_state(env).deprecated {
            return Err(Error::ContractDeprecated);
        }
        // 3. Participant filtering (read-only)
        Self::check_participant_filter(env, depositor.clone())?;
        // 4. Amount policy
        if let Some((min_amount, max_amount)) = env
            .storage()
            .instance()
            .get::<DataKey, (i128, i128)>(&DataKey::AmountPolicy)
        {
            if amount < min_amount {
                return Err(Error::AmountBelowMinimum);
            }
            if amount > max_amount {
                return Err(Error::AmountAboveMaximum);
            }
        }
        // 5. Bounty must not already exist
        if env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyExists);
        }
        // 6. Amount validation
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(env, &token_addr);
        // 7. Sufficient balance (read-only)
        let balance = client.balance(&depositor);
        if balance < amount {
            return Err(Error::InsufficientFunds);
        }
        // 8. Fee computation (pure)
        let (
            lock_fee_rate,
            _release_fee_rate,
            lock_fixed_fee,
            _release_fixed,
            _fee_recipient,
            fee_enabled,
        ) = Self::resolve_fee_config(env);
        let fee_amount =
            Self::combined_fee_amount(amount, lock_fee_rate, lock_fixed_fee, fee_enabled);
        let net_amount = amount.checked_sub(fee_amount).unwrap_or(amount);
        if net_amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        Ok((net_amount,))
    }

    /// Returns whether the given bounty escrow is marked as using non-transferable (soulbound)
    /// reward tokens. When true, the token is expected to disallow further transfers after claim.
    pub fn get_non_transferable_rewards(env: Env, bounty_id: u64) -> Result<bool, Error> {
        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }
        Ok(env
            .storage()
            .persistent()
            .get(&DataKey::NonTransferableRewards(bounty_id))
            .unwrap_or(false))
    }

    /// Lock funds for a bounty in anonymous mode: only a 32-byte depositor commitment is stored.
    /// The depositor must authorize and transfer; their address is used only for the transfer
    /// in this call and is not stored on-chain. Refunds require the configured anonymous
    /// resolver to call `refund_resolved(bounty_id, recipient)`.
    pub fn lock_funds_anonymous(
        env: Env,
        depositor: Address,
        depositor_commitment: BytesN<32>,
        bounty_id: u64,
        amount: i128,
        deadline: u64,
    ) -> Result<(), Error> {
        // Validation precedence (deterministic ordering):
        // 1. Reentrancy guard
        // 2. Contract initialized
        // 3. Paused (operational state)
        // 4. Rate limiting
        // 5. Authorization
        // 6. Business logic (bounty uniqueness, amount policy)

        // 1. Reentrancy guard
        reentrancy_guard::acquire(&env);

        // 2. Contract must be initialized
        if !env.storage().instance().has(&DataKey::Admin) {
            reentrancy_guard::release(&env);
            return Err(Error::NotInitialized);
        }

        // 3. Operational state: paused
        if Self::check_paused(&env, symbol_short!("lock")) {
            reentrancy_guard::release(&env);
            return Err(Error::FundsPaused);
        }

        // 4. Rate limiting
        anti_abuse::check_rate_limit(&env, depositor.clone());

        // 5. Authorization
        depositor.require_auth();

        if env.storage().persistent().has(&DataKey::Escrow(bounty_id))
            || env
                .storage()
                .persistent()
                .has(&DataKey::EscrowAnon(bounty_id))
        {
            reentrancy_guard::release(&env);
            return Err(Error::BountyExists);
        }

        if let Some((min_amount, max_amount)) = env
            .storage()
            .instance()
            .get::<DataKey, (i128, i128)>(&DataKey::AmountPolicy)
        {
            if amount < min_amount {
                reentrancy_guard::release(&env);
                return Err(Error::AmountBelowMinimum);
            }
            if amount > max_amount {
                reentrancy_guard::release(&env);
                return Err(Error::AmountAboveMaximum);
            }
        }

        let escrow_anon = AnonymousEscrow {
            depositor_commitment: depositor_commitment.clone(),
            amount,
            remaining_amount: amount,
            status: EscrowStatus::Locked,
            deadline,
            refund_history: vec![&env],
            archived: false,
            archived_at: None,
        };

        env.storage()
            .persistent()
            .set(&DataKey::EscrowAnon(bounty_id), &escrow_anon);

        let mut index: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::EscrowIndex)
            .unwrap_or(Vec::new(&env));
        index.push_back(bounty_id);
        env.storage()
            .persistent()
            .set(&DataKey::EscrowIndex, &index);

        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);
        client.transfer(&depositor, &env.current_contract_address(), &amount);

        emit_funds_locked_anon(
            &env,
            FundsLockedAnon {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount,
                depositor_commitment,
                deadline,
            },
        );

        multitoken_invariants::assert_after_lock(&env);
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Releases escrowed funds to a contributor.
    ///
    /// # Access Control
    /// Admin-only.
    ///
    /// # Front-running Behavior
    /// First valid release for a bounty transitions state to `Released`. Later release/refund/claim
    /// races against that bounty must fail with `Error::FundsNotLocked`.
    ///
    /// # Security
    /// Reentrancy guard is always cleared before any explicit error return after acquisition.
    pub fn release_funds(env: Env, bounty_id: u64, contributor: Address) -> Result<(), Error> {
        let caller = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Admin)
            .unwrap_or(contributor.clone());
        let res = Self::release_funds_logic(env.clone(), bounty_id, contributor);
        monitoring::track_operation(&env, symbol_short!("release"), caller, res.is_ok());
        res
    }

    fn release_funds_logic(env: Env, bounty_id: u64, contributor: Address) -> Result<(), Error> {
        // Validation precedence (deterministic ordering):
        // 1. Reentrancy guard
        // 2. Contract initialized
        // 3. Paused (operational state)
        // 4. Authorization
        // 5. Business logic (bounty exists, funds locked)

        // 1. GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);

        // 2. Contract must be initialized
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }

        // 3. Operational state: paused
        if Self::check_paused(&env, symbol_short!("release")) {
            return Err(Error::FundsPaused);
        }

        // 4. Authorization
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        // 5. Business logic: bounty must exist and be locked
        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }

        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .unwrap();

        Self::ensure_escrow_not_frozen(&env, bounty_id)?;
        Self::ensure_address_not_frozen(&env, &escrow.depositor)?;

        if escrow.status != EscrowStatus::Locked {
            reentrancy_guard::release(&env);
            return Err(Error::FundsNotLocked);
        }

        // Resolve effective fee config for release.
        let (
            _lock_fee_rate,
            release_fee_rate,
            _lock_fixed,
            release_fixed_fee,
            fee_recipient,
            fee_enabled,
        ) = Self::resolve_fee_config(&env);

        let release_fee = Self::combined_fee_amount(
            escrow.amount,
            release_fee_rate,
            release_fixed_fee,
            fee_enabled,
        );
        let mut fee_config = Self::get_fee_config_internal(&env);
        fee_config.release_fee_rate = release_fee_rate;
        fee_config.release_fixed_fee = release_fixed_fee;
        fee_config.fee_recipient = fee_recipient.clone();
        fee_config.fee_enabled = fee_enabled;

        // Net payout to contributor after release fee.
        let net_payout = escrow
            .amount
            .checked_sub(release_fee)
            .unwrap_or(escrow.amount);
        if net_payout <= 0 {
            reentrancy_guard::release(&env);
            return Err(Error::InvalidAmount);
        }

        // EFFECTS: update state before external calls (CEI)
        escrow.status = EscrowStatus::Released;
        escrow.remaining_amount = 0;
        invariants::assert_escrow(&env, &escrow);
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        // INTERACTION: external token transfers are last
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);

        if release_fee > 0 {
            Self::route_fee(
                &env,
                &client,
                release_fee,
                &fee_recipient,
                fee_config.distribution_enabled,
                &fee_config.treasury_destinations,
            );
        }

        client.transfer(&env.current_contract_address(), &contributor, &net_payout);

        emit_funds_released(
            &env,
            FundsReleased {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount: escrow.amount,
                recipient: contributor.clone(),
                timestamp: env.ledger().timestamp(),
            },
        );
        audit_trail::log_action(&env, symbol_short!("release"), contributor.clone(), bounty_id);
        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Simulate release operation without state changes or token transfers.
    ///
    /// Returns a `SimulationResult` indicating whether the operation would succeed and the
    /// resulting escrow state. Does not require authorization; safe for off-chain preview.
    ///
    /// # Arguments
    /// * `bounty_id` - Bounty identifier
    /// * `contributor` - Recipient address
    ///
    /// # Security
    /// This function performs only read operations. No storage writes, token transfers,
    /// or events are emitted.
    pub fn dry_run_release(env: Env, bounty_id: u64, contributor: Address) -> SimulationResult {
        fn err_result(e: Error) -> SimulationResult {
            SimulationResult {
                success: false,
                error_code: e as u32,
                amount: 0,
                resulting_status: EscrowStatus::Released,
                remaining_amount: 0,
            }
        }
        match Self::dry_run_release_impl(&env, bounty_id, contributor) {
            Ok((amount,)) => SimulationResult {
                success: true,
                error_code: 0,
                amount,
                resulting_status: EscrowStatus::Released,
                remaining_amount: 0,
            },
            Err(e) => err_result(e),
        }
    }

    fn dry_run_release_impl(
        env: &Env,
        bounty_id: u64,
        _contributor: Address,
    ) -> Result<(i128,), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        if Self::check_paused(env, symbol_short!("release")) {
            return Err(Error::FundsPaused);
        }
        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }
        let escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .unwrap();
        Self::ensure_escrow_not_frozen(env, bounty_id)?;
        Self::ensure_address_not_frozen(env, &escrow.depositor)?;
        if escrow.status != EscrowStatus::Locked {
            return Err(Error::FundsNotLocked);
        }
        let (
            _lock_fee_rate,
            release_fee_rate,
            _lock_fixed,
            release_fixed_fee,
            _fee_recipient,
            fee_enabled,
        ) = Self::resolve_fee_config(env);
        let release_fee = Self::combined_fee_amount(
            escrow.amount,
            release_fee_rate,
            release_fixed_fee,
            fee_enabled,
        );
        let net_payout = escrow
            .amount
            .checked_sub(release_fee)
            .unwrap_or(escrow.amount);
        if net_payout <= 0 {
            return Err(Error::InvalidAmount);
        }
        Ok((escrow.amount,))
    }

    /// Delegated release flow using a capability instead of admin auth.
    /// The capability amount limit is consumed by `payout_amount`.
    pub fn release_with_capability(
        env: Env,
        bounty_id: u64,
        contributor: Address,
        payout_amount: i128,
        holder: Address,
        capability_id: BytesN<32>,
    ) -> Result<(), Error> {
        // GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);

        if Self::check_paused(&env, symbol_short!("release")) {
            return Err(Error::FundsPaused);
        }
        if payout_amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }

        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .unwrap();
        Self::ensure_escrow_not_frozen(&env, bounty_id)?;
        Self::ensure_address_not_frozen(&env, &escrow.depositor)?;
        if escrow.status != EscrowStatus::Locked {
            return Err(Error::FundsNotLocked);
        }
        if payout_amount > escrow.remaining_amount {
            return Err(Error::InsufficientFunds);
        }

        Self::consume_capability(
            &env,
            &holder,
            capability_id,
            CapabilityAction::Release,
            bounty_id,
            payout_amount,
        )?;

        // EFFECTS: update state before external call (CEI)
        escrow.remaining_amount -= payout_amount;
        if escrow.remaining_amount == 0 {
            escrow.status = EscrowStatus::Released;
        }
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        // INTERACTION: external token transfer is last
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);
        client.transfer(
            &env.current_contract_address(),
            &contributor,
            &payout_amount,
        );

        emit_funds_released(
            &env,
            FundsReleased {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount: payout_amount,
                recipient: contributor,
                timestamp: env.ledger().timestamp(),
            },
        );

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Set the claim window duration (admin only).
    /// claim_window: seconds beneficiary has to claim after release is authorized.
    pub fn set_claim_window(env: Env, claim_window: u64) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::ClaimWindow, &claim_window);
        Ok(())
    }

    /// Authorizes a pending claim instead of immediate transfer.
    ///
    /// # Access Control
    /// Admin-only.
    ///
    /// # Front-running Behavior
    /// Repeated authorizations are overwrite semantics: the latest successful authorization for
    /// a locked bounty replaces the previous pending recipient/record.
    pub fn authorize_claim(
        env: Env,
        bounty_id: u64,
        recipient: Address,
        reason: DisputeReason,
    ) -> Result<(), Error> {
        if Self::check_paused(&env, symbol_short!("release")) {
            return Err(Error::FundsPaused);
        }
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }

        let escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .unwrap();

        Self::ensure_escrow_not_frozen(&env, bounty_id)?;
        Self::ensure_address_not_frozen(&env, &escrow.depositor)?;

        if escrow.status != EscrowStatus::Locked {
            return Err(Error::FundsNotLocked);
        }

        let now = env.ledger().timestamp();
        let claim_window: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ClaimWindow)
            .unwrap_or(0);
        let claim = ClaimRecord {
            bounty_id,
            recipient: recipient.clone(),
            amount: escrow.amount,
            expires_at: now.saturating_add(claim_window),
            claimed: false,
            reason: reason.clone(),
        };

        env.storage()
            .persistent()
            .set(&DataKey::PendingClaim(bounty_id), &claim);

        env.events().publish(
            (symbol_short!("claim"), symbol_short!("created")),
            ClaimCreated {
                bounty_id,
                recipient,
                amount: escrow.amount,
                expires_at: claim.expires_at,
            },
        );
        Ok(())
    }

    /// Claims an existing pending authorization.
    ///
    /// # Access Control
    /// Only the authorized pending `recipient` can claim.
    ///
    /// # Front-running Behavior
    /// Claim is single-use: once marked claimed and escrow is released, subsequent calls fail.
    pub fn claim(env: Env, bounty_id: u64) -> Result<(), Error> {
        // GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);

        if Self::check_paused(&env, symbol_short!("release")) {
            return Err(Error::FundsPaused);
        }
        if !env
            .storage()
            .persistent()
            .has(&DataKey::PendingClaim(bounty_id))
        {
            return Err(Error::BountyNotFound);
        }
        let mut claim: ClaimRecord = env
            .storage()
            .persistent()
            .get(&DataKey::PendingClaim(bounty_id))
            .unwrap();

        claim.recipient.require_auth();

        let now = env.ledger().timestamp();
        if now > claim.expires_at {
            return Err(Error::DeadlineNotPassed); // reuse or add ClaimExpired error
        }
        if claim.claimed {
            return Err(Error::FundsNotLocked);
        }

        // EFFECTS: update state before external call (CEI)
        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .unwrap();
        Self::ensure_escrow_not_frozen(&env, bounty_id)?;
        Self::ensure_address_not_frozen(&env, &escrow.depositor)?;
        escrow.status = EscrowStatus::Released;
        escrow.remaining_amount = 0;
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        claim.claimed = true;
        env.storage()
            .persistent()
            .set(&DataKey::PendingClaim(bounty_id), &claim);

        // INTERACTION: external token transfer is last
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);
        client.transfer(
            &env.current_contract_address(),
            &claim.recipient,
            &claim.amount,
        );

        env.events().publish(
            (symbol_short!("claim"), symbol_short!("done")),
            ClaimExecuted {
                bounty_id,
                recipient: claim.recipient.clone(),
                amount: claim.amount,
                claimed_at: now,
            },
        );

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Delegated claim execution using a capability.
    /// Funds are still transferred to the pending claim recipient.
    pub fn claim_with_capability(
        env: Env,
        bounty_id: u64,
        holder: Address,
        capability_id: BytesN<32>,
    ) -> Result<(), Error> {
        // GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);

        if Self::check_paused(&env, symbol_short!("release")) {
            return Err(Error::FundsPaused);
        }
        if !env
            .storage()
            .persistent()
            .has(&DataKey::PendingClaim(bounty_id))
        {
            return Err(Error::BountyNotFound);
        }

        let mut claim: ClaimRecord = env
            .storage()
            .persistent()
            .get(&DataKey::PendingClaim(bounty_id))
            .unwrap();

        let now = env.ledger().timestamp();
        if now > claim.expires_at {
            return Err(Error::DeadlineNotPassed);
        }
        if claim.claimed {
            return Err(Error::FundsNotLocked);
        }

        Self::consume_capability(
            &env,
            &holder,
            capability_id,
            CapabilityAction::Claim,
            bounty_id,
            claim.amount,
        )?;

        // EFFECTS: update state before external call (CEI)
        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .unwrap();
        Self::ensure_escrow_not_frozen(&env, bounty_id)?;
        Self::ensure_address_not_frozen(&env, &escrow.depositor)?;
        escrow.status = EscrowStatus::Released;
        escrow.remaining_amount = 0;
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        claim.claimed = true;
        env.storage()
            .persistent()
            .set(&DataKey::PendingClaim(bounty_id), &claim);

        // INTERACTION: external token transfer is last
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);
        client.transfer(
            &env.current_contract_address(),
            &claim.recipient,
            &claim.amount,
        );

        env.events().publish(
            (symbol_short!("claim"), symbol_short!("done")),
            ClaimExecuted {
                bounty_id,
                recipient: claim.recipient,
                amount: claim.amount,
                claimed_at: now,
            },
        );

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Admin can cancel an expired or unwanted pending claim, returning escrow to Locked.
    pub fn cancel_pending_claim(
        env: Env,
        bounty_id: u64,
        outcome: DisputeOutcome,
    ) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        if !env
            .storage()
            .persistent()
            .has(&DataKey::PendingClaim(bounty_id))
        {
            return Err(Error::BountyNotFound);
        }
        let claim: ClaimRecord = env
            .storage()
            .persistent()
            .get(&DataKey::PendingClaim(bounty_id))
            .unwrap();

        let now = env.ledger().timestamp(); // Added this line
        let recipient = claim.recipient.clone(); // Added this line
        let amount = claim.amount; // Added this line

        env.storage()
            .persistent()
            .remove(&DataKey::PendingClaim(bounty_id));

        env.events().publish(
            (symbol_short!("claim"), symbol_short!("cancel")),
            ClaimCancelled {
                bounty_id,
                recipient,
                amount,
                cancelled_at: now,
                cancelled_by: admin,
            },
        );
        Ok(())
    }

    /// View: get pending claim for a bounty.
    pub fn get_pending_claim(env: Env, bounty_id: u64) -> Result<ClaimRecord, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::PendingClaim(bounty_id))
            .ok_or(Error::BountyNotFound)
    }

    /// Approve a refund before deadline (admin only).
    /// This allows early refunds with admin approval.
    pub fn approve_refund(
        env: Env,
        bounty_id: u64,
        amount: i128,
        recipient: Address,
        mode: RefundMode,
    ) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }

        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }

        let escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .unwrap();

        if escrow.status != EscrowStatus::Locked && escrow.status != EscrowStatus::PartiallyRefunded
        {
            return Err(Error::FundsNotLocked);
        }

        if amount <= 0 || amount > escrow.remaining_amount {
            return Err(Error::InvalidAmount);
        }

        let approval = RefundApproval {
            bounty_id,
            amount,
            recipient: recipient.clone(),
            mode: mode.clone(),
            approved_by: admin.clone(),
            approved_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&DataKey::RefundApproval(bounty_id), &approval);

        Ok(())
    }

    /// Releases a partial amount of locked funds.
    ///
    /// # Access Control
    /// Admin-only.
    ///
    /// # Front-running Behavior
    /// Each successful call decreases `remaining_amount` exactly once. Attempts to exceed remaining
    /// balance fail with `Error::InsufficientFunds`.
    ///
    /// - `payout_amount` must be > 0 and <= `remaining_amount`.
    /// - `remaining_amount` is decremented by `payout_amount` after each call.
    /// - When `remaining_amount` reaches 0 the escrow status is set to Released.
    /// - The bounty stays Locked while any funds remain unreleased.
    pub fn partial_release(
        env: Env,
        bounty_id: u64,
        contributor: Address,
        payout_amount: i128,
    ) -> Result<(), Error> {
        // GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);

        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }

        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        // Snapshot resource meters for gas cap enforcement (test / testutils only).
        #[cfg(any(test, feature = "testutils"))]
        let gas_snapshot = gas_budget::capture(&env);

        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }

        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .unwrap();

        Self::ensure_escrow_not_frozen(&env, bounty_id)?;
        Self::ensure_address_not_frozen(&env, &escrow.depositor)?;

        if escrow.status != EscrowStatus::Locked {
            return Err(Error::FundsNotLocked);
        }

        // Guard: zero or negative payout makes no sense and would corrupt state
        if payout_amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        // Guard: prevent overpayment — payout cannot exceed what is still owed
        if payout_amount > escrow.remaining_amount {
            return Err(Error::InsufficientFunds);
        }

        // EFFECTS: update state before external call (CEI)
        // Decrement remaining; this is always an exact integer subtraction — no rounding
        escrow.remaining_amount = escrow.remaining_amount.checked_sub(payout_amount).unwrap();

        // Automatically transition to Released once fully paid out
        if escrow.remaining_amount == 0 {
            escrow.status = EscrowStatus::Released;
        }

        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        // INTERACTION: external token transfer is last
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);
        client.transfer(
            &env.current_contract_address(),
            &contributor,
            &payout_amount,
        );

        events::emit_funds_released(
            &env,
            FundsReleased {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount: payout_amount,
                recipient: contributor,
                timestamp: env.ledger().timestamp(),
            },
        );

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Refunds remaining funds when refund conditions are met.
    ///
    /// # Authorization
    /// Refund execution requires authenticated authorization from the contract admin
    /// and the escrow depositor.
    ///
    /// # Eligibility
    /// Refund is allowed when either:
    /// 1. The deadline has passed (standard full refund to depositor), or
    /// 2. An admin approval exists (early, partial, or custom-recipient refund).
    ///
    /// # Errors
    /// Returns `Error::NotInitialized` if admin is not set.
    pub fn refund(env: Env, bounty_id: u64) -> Result<(), Error> {
        // GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);

        if Self::check_paused(&env, symbol_short!("refund")) {
            return Err(Error::FundsPaused);
        }
        // Snapshot resource meters for gas cap enforcement (test / testutils only).
        #[cfg(any(test, feature = "testutils"))]
        let gas_snapshot = gas_budget::capture(&env);

        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }

        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .unwrap();

        Self::ensure_escrow_not_frozen(&env, bounty_id)?;
        Self::ensure_address_not_frozen(&env, &escrow.depositor)?;

        // Require authenticated approval from both admin and depositor.
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();
        escrow.depositor.require_auth();

        if escrow.status != EscrowStatus::Locked && escrow.status != EscrowStatus::PartiallyRefunded
        {
            return Err(Error::FundsNotLocked);
        }

        // Block refund if there is a pending claim (Issue #391 fix)
        if env
            .storage()
            .persistent()
            .has(&DataKey::PendingClaim(bounty_id))
        {
            let claim: ClaimRecord = env
                .storage()
                .persistent()
                .get(&DataKey::PendingClaim(bounty_id))
                .unwrap();
            if !claim.claimed {
                return Err(Error::ClaimPending);
            }
        }

        let now = env.ledger().timestamp();
        let approval_key = DataKey::RefundApproval(bounty_id);
        let approval: Option<RefundApproval> = env.storage().persistent().get(&approval_key);

        // Refund is allowed if:
        // 1. Deadline has passed (returns full amount to depositor)
        // 2. An administrative approval exists (can be early, partial, and to custom recipient)
        if now < escrow.deadline && approval.is_none() {
            return Err(Error::DeadlineNotPassed);
        }

        let (refund_amount, refund_to, is_full) = if let Some(app) = approval.clone() {
            let full = app.mode == RefundMode::Full || app.amount >= escrow.remaining_amount;
            (app.amount, app.recipient, full)
        } else {
            // Standard refund after deadline
            (escrow.remaining_amount, escrow.depositor.clone(), true)
        };

        if refund_amount <= 0 || refund_amount > escrow.remaining_amount {
            return Err(Error::InvalidAmount);
        }

        // EFFECTS: update state before external call (CEI)
        invariants::assert_escrow(&env, &escrow);
        // Update escrow state: subtract the amount exactly refunded
        escrow.remaining_amount = escrow.remaining_amount.checked_sub(refund_amount).unwrap();
        if is_full || escrow.remaining_amount == 0 {
            escrow.status = EscrowStatus::Refunded;
        } else {
            escrow.status = EscrowStatus::PartiallyRefunded;
        }

        // Add to refund history
        escrow.refund_history.push_back(RefundRecord {
            amount: refund_amount,
            recipient: refund_to.clone(),
            timestamp: now,
            mode: if is_full {
                RefundMode::Full
            } else {
                RefundMode::Partial
            },
        });

        // Save updated escrow
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        // Remove approval after successful execution
        if approval.is_some() {
            env.storage().persistent().remove(&approval_key);
        }

        // INTERACTION: external token transfer is last
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);
        client.transfer(&env.current_contract_address(), &refund_to, &refund_amount);

        emit_funds_refunded(
            &env,
            FundsRefunded {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount: refund_amount,
                refund_to: refund_to.clone(),
                timestamp: now,
                trigger_type: if approval.is_some() {
                    RefundTriggerType::AdminApproval
                } else {
                    RefundTriggerType::DeadlineExpired
                },
            },
        );
        Self::record_receipt(
            &env,
            CriticalOperationOutcome::Refunded,
            bounty_id,
            refund_amount,
            refund_to.clone(),
        );

        // INV-2: Verify aggregate balance matches token balance after refund
        multitoken_invariants::assert_after_disbursement(&env);

        // Gas budget cap enforcement (test / testutils only).
        #[cfg(any(test, feature = "testutils"))]
        {
            let gas_cfg = gas_budget::get_config(&env);
            if let Err(e) = gas_budget::check(
                &env,
                symbol_short!("refund"),
                &gas_cfg.refund,
                &gas_snapshot,
                gas_cfg.enforce,
            ) {
                reentrancy_guard::release(&env);
                return Err(e);
            }
        }
        audit_trail::log_action(&env, symbol_short!("refund"), escrow.depositor.clone(), bounty_id);
        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Simulate refund operation without state changes or token transfers.
    ///
    /// Returns a `SimulationResult` indicating whether the operation would succeed and the
    /// resulting escrow state. Does not require authorization; safe for off-chain preview.
    ///
    /// # Arguments
    /// * `bounty_id` - Bounty identifier
    ///
    /// # Security
    /// This function performs only read operations. No storage writes, token transfers,
    /// or events are emitted.
    pub fn dry_run_refund(env: Env, bounty_id: u64) -> SimulationResult {
        fn err_result(e: Error, default_status: EscrowStatus) -> SimulationResult {
            SimulationResult {
                success: false,
                error_code: e as u32,
                amount: 0,
                resulting_status: default_status,
                remaining_amount: 0,
            }
        }
        match Self::dry_run_refund_impl(&env, bounty_id) {
            Ok((refund_amount, resulting_status, remaining_amount)) => SimulationResult {
                success: true,
                error_code: 0,
                amount: refund_amount,
                resulting_status,
                remaining_amount,
            },
            Err(e) => err_result(e, EscrowStatus::Refunded),
        }
    }

    fn dry_run_refund_impl(env: &Env, bounty_id: u64) -> Result<(i128, EscrowStatus, i128), Error> {
        if Self::check_paused(env, symbol_short!("refund")) {
            return Err(Error::FundsPaused);
        }
        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }
        let escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .unwrap();
        Self::ensure_escrow_not_frozen(env, bounty_id)?;
        Self::ensure_address_not_frozen(env, &escrow.depositor)?;
        if escrow.status != EscrowStatus::Locked && escrow.status != EscrowStatus::PartiallyRefunded
        {
            return Err(Error::FundsNotLocked);
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::PendingClaim(bounty_id))
        {
            let claim: ClaimRecord = env
                .storage()
                .persistent()
                .get(&DataKey::PendingClaim(bounty_id))
                .unwrap();
            if !claim.claimed {
                return Err(Error::ClaimPending);
            }
        }
        let now = env.ledger().timestamp();
        let approval_key = DataKey::RefundApproval(bounty_id);
        let approval: Option<RefundApproval> = env.storage().persistent().get(&approval_key);
        if now < escrow.deadline && approval.is_none() {
            return Err(Error::DeadlineNotPassed);
        }
        let (refund_amount, _refund_to, is_full) = if let Some(app) = approval {
            let full = app.mode == RefundMode::Full || app.amount >= escrow.remaining_amount;
            (app.amount, app.recipient, full)
        } else {
            (escrow.remaining_amount, escrow.depositor.clone(), true)
        };
        if refund_amount <= 0 || refund_amount > escrow.remaining_amount {
            return Err(Error::InvalidAmount);
        }
        let remaining_after = escrow
            .remaining_amount
            .checked_sub(refund_amount)
            .unwrap_or(0);
        let resulting_status = if is_full || remaining_after == 0 {
            EscrowStatus::Refunded
        } else {
            EscrowStatus::PartiallyRefunded
        };
        Ok((refund_amount, resulting_status, remaining_after))
    }

    /// Sets or clears the anonymous resolver address.
    /// Only the admin can call this. The resolver is the trusted entity that
    /// resolves anonymous escrow refunds via `refund_resolved`.
    pub fn set_anonymous_resolver(env: Env, resolver: Option<Address>) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        match resolver {
            Some(addr) => env
                .storage()
                .instance()
                .set(&DataKey::AnonymousResolver, &addr),
            None => env.storage().instance().remove(&DataKey::AnonymousResolver),
        }
        Ok(())
    }

    /// Refund an anonymous escrow to a resolved recipient.
    /// Only the configured anonymous resolver can call this; they resolve the depositor
    /// commitment off-chain and pass the recipient address (signed instruction pattern).
    pub fn refund_resolved(env: Env, bounty_id: u64, recipient: Address) -> Result<(), Error> {
        if Self::check_paused(&env, symbol_short!("refund")) {
            return Err(Error::FundsPaused);
        }

        let resolver: Address = env
            .storage()
            .instance()
            .get(&DataKey::AnonymousResolver)
            .ok_or(Error::AnonymousResolverNotSet)?;
        resolver.require_auth();

        if !env
            .storage()
            .persistent()
            .has(&DataKey::EscrowAnon(bounty_id))
        {
            return Err(Error::NotAnonymousEscrow);
        }

        reentrancy_guard::acquire(&env);

        let mut anon: AnonymousEscrow = env
            .storage()
            .persistent()
            .get(&DataKey::EscrowAnon(bounty_id))
            .unwrap();

        Self::ensure_escrow_not_frozen(&env, bounty_id)?;

        if anon.status != EscrowStatus::Locked && anon.status != EscrowStatus::PartiallyRefunded {
            return Err(Error::FundsNotLocked);
        }

        // GUARD 1: Block refund if there is a pending claim (Issue #391 fix)
        if env
            .storage()
            .persistent()
            .has(&DataKey::PendingClaim(bounty_id))
        {
            let claim: ClaimRecord = env
                .storage()
                .persistent()
                .get(&DataKey::PendingClaim(bounty_id))
                .unwrap();
            if !claim.claimed {
                return Err(Error::ClaimPending);
            }
        }

        let now = env.ledger().timestamp();
        let approval_key = DataKey::RefundApproval(bounty_id);
        let approval: Option<RefundApproval> = env.storage().persistent().get(&approval_key);

        // Refund is allowed if:
        // 1. Deadline has passed (returns full amount to depositor)
        // 2. An administrative approval exists (can be early, partial, and to custom recipient)
        if now < anon.deadline && approval.is_none() {
            return Err(Error::DeadlineNotPassed);
        }

        let (refund_amount, refund_to, is_full) = if let Some(app) = approval.clone() {
            let full = app.mode == RefundMode::Full || app.amount >= anon.remaining_amount;
            (app.amount, app.recipient, full)
        } else {
            // Standard refund after deadline
            (anon.remaining_amount, recipient.clone(), true)
        };

        if refund_amount <= 0 || refund_amount > anon.remaining_amount {
            return Err(Error::InvalidAmount);
        }

        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);

        // Transfer the calculated refund amount to the designated recipient
        client.transfer(&env.current_contract_address(), &refund_to, &refund_amount);

        // Anonymous escrow uses a parallel storage record and invariant model.
        // Update escrow state: subtract the amount exactly refunded
        anon.remaining_amount -= refund_amount;
        if is_full || anon.remaining_amount == 0 {
            anon.status = EscrowStatus::Refunded;
        } else {
            anon.status = EscrowStatus::PartiallyRefunded;
        }

        // Add to refund history
        anon.refund_history.push_back(RefundRecord {
            amount: refund_amount,
            recipient: refund_to.clone(),
            timestamp: now,
            mode: if is_full {
                RefundMode::Full
            } else {
                RefundMode::Partial
            },
        });

        // Save updated escrow
        env.storage()
            .persistent()
            .set(&DataKey::EscrowAnon(bounty_id), &anon);

        // Remove approval after successful execution
        if approval.is_some() {
            env.storage().persistent().remove(&approval_key);
        }

        emit_funds_refunded(
            &env,
            FundsRefunded {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount: refund_amount,
                refund_to: refund_to.clone(),
                timestamp: now,
                trigger_type: if approval.is_some() {
                    RefundTriggerType::AdminApproval
                } else {
                    RefundTriggerType::DeadlineExpired
                },
            },
        );

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Delegated refund path using a capability.
    /// This can be used for short-lived, bounded delegated refunds without granting admin rights.
    pub fn refund_with_capability(
        env: Env,
        bounty_id: u64,
        amount: i128,
        holder: Address,
        capability_id: BytesN<32>,
    ) -> Result<(), Error> {
        // GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);

        if Self::check_paused(&env, symbol_short!("refund")) {
            return Err(Error::FundsPaused);
        }
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }

        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .unwrap();

        Self::ensure_escrow_not_frozen(&env, bounty_id)?;
        Self::ensure_address_not_frozen(&env, &escrow.depositor)?;

        if escrow.status != EscrowStatus::Locked && escrow.status != EscrowStatus::PartiallyRefunded
        {
            return Err(Error::FundsNotLocked);
        }
        if amount > escrow.remaining_amount {
            return Err(Error::InvalidAmount);
        }

        if env
            .storage()
            .persistent()
            .has(&DataKey::PendingClaim(bounty_id))
        {
            let claim: ClaimRecord = env
                .storage()
                .persistent()
                .get(&DataKey::PendingClaim(bounty_id))
                .unwrap();
            if !claim.claimed {
                return Err(Error::ClaimPending);
            }
        }

        Self::consume_capability(
            &env,
            &holder,
            capability_id,
            CapabilityAction::Refund,
            bounty_id,
            amount,
        )?;

        // EFFECTS: update state before external call (CEI)
        let now = env.ledger().timestamp();
        let refund_to = escrow.depositor.clone();

        // EFFECTS: update escrow state before external call (CEI)
        escrow.remaining_amount = escrow.remaining_amount.saturating_sub(amount);
        if escrow.remaining_amount == 0 {
            escrow.status = EscrowStatus::Refunded;
        } else {
            escrow.status = EscrowStatus::PartiallyRefunded;
        }
        escrow.refund_history.push_back(RefundRecord {
            amount,
            recipient: refund_to.clone(),
            timestamp: now,
            mode: RefundMode::Partial,
        });
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        // INTERACTION: external token transfer
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);
        client.transfer(&env.current_contract_address(), &refund_to, &amount);
        emit_funds_refunded(
            &env,
            FundsRefunded {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount,
                refund_to: refund_to.clone(),
                timestamp: now,
                trigger_type: RefundTriggerType::AdminApproval,
            },
        );

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Return the current per-operation gas budget configuration.
    ///
    /// Returns the fully uncapped default if no configuration has been set.
    pub fn get_gas_budget(env: Env) -> gas_budget::GasBudgetConfig {
        gas_budget::get_config(&env)
    }

    /// Batch lock funds for multiple bounties in a single atomic transaction.
    ///
    /// Locks between 1 and [`MAX_BATCH_SIZE`] bounties in one call, reducing
    /// per-transaction overhead compared to repeated single-item `lock_funds`
    /// calls.
    ///
    /// ## Batch failure semantics
    ///
    /// This operation is **strictly atomic** (all-or-nothing):
    ///
    /// 1. All items are validated in a single pass **before** any state is
    ///    mutated or any token transfer is initiated.
    /// 2. If *any* item fails validation the entire call reverts immediately.
    ///    No escrow record is written, no token is transferred, and every
    ///    "sibling" row in the same batch is left completely unaffected.
    /// 3. After a failed batch the contract is in exactly the same state as
    ///    before the call; subsequent operations behave as if this call never
    ///    happened.
    ///
    /// ## Ordering guarantee
    ///
    /// Items are processed in ascending `bounty_id` order regardless of the
    /// caller-supplied ordering. This ensures deterministic execution and
    /// eliminates ordering-based front-running attacks.
    ///
    /// ## Checks-Effects-Interactions (CEI)
    ///
    /// All escrow records and index updates are written in a first pass
    /// (Effects); external token transfers and event emissions happen in a
    /// second pass (Interactions). This ordering prevents reentrancy attacks.
    ///
    /// # Arguments
    /// * `items` - 1–[`MAX_BATCH_SIZE`] [`LockFundsItem`] entries (bounty_id,
    ///   depositor, amount, deadline).
    ///
    /// # Returns
    /// Number of bounties successfully locked (equals `items.len()` on success).
    ///
    /// # Errors
    /// * [`Error::InvalidBatchSize`] — batch is empty or exceeds `MAX_BATCH_SIZE`
    /// * [`Error::ContractDeprecated`] — contract has been killed via `set_deprecated`
    /// * [`Error::FundsPaused`] — lock operations are currently paused
    /// * [`Error::NotInitialized`] — `init` has not been called
    /// * [`Error::BountyExists`] — a `bounty_id` already exists in storage
    /// * [`Error::DuplicateBountyId`] — the same `bounty_id` appears more than once
    /// * [`Error::InvalidAmount`] — any item has `amount ≤ 0`
    /// * [`Error::ParticipantBlocked`] / [`Error::ParticipantNotAllowed`] — participant filter
    ///
    /// # Reentrancy
    /// Protected by the shared reentrancy guard (acquired before validation,
    /// released after all effects and interactions complete).
    pub fn batch_lock_funds(env: Env, items: Vec<LockFundsItem>) -> Result<u32, Error> {
        if Self::check_paused(&env, symbol_short!("lock")) {
            return Err(Error::FundsPaused);
        }

        // GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);
        // Snapshot resource meters for gas cap enforcement (test / testutils only).
        #[cfg(any(test, feature = "testutils"))]
        let gas_snapshot = gas_budget::capture(&env);
        let result: Result<u32, Error> = (|| {
            if Self::get_deprecation_state(&env).deprecated {
                return Err(Error::ContractDeprecated);
            }
            // Validate batch size
            let batch_size = items.len();
            if batch_size == 0 {
                return Err(Error::InvalidBatchSize);
            }
            if batch_size > MAX_BATCH_SIZE {
                return Err(Error::InvalidBatchSize);
            }

            if !env.storage().instance().has(&DataKey::Admin) {
                return Err(Error::NotInitialized);
            }

            let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
            let client = token::Client::new(&env, &token_addr);
            let contract_address = env.current_contract_address();
            let timestamp = env.ledger().timestamp();

            // Validate all items before processing (all-or-nothing approach)
            for item in items.iter() {
                // Participant filtering (blocklist-only / allowlist-only / disabled)
                Self::check_participant_filter(&env, item.depositor.clone())?;

                // Check if bounty already exists
                if env
                    .storage()
                    .persistent()
                    .has(&DataKey::Escrow(item.bounty_id))
                {
                    return Err(Error::BountyExists);
                }

                // Validate amount
                if item.amount <= 0 {
                    return Err(Error::InvalidAmount);
                }

                // Check for duplicate bounty_ids in the batch
                let mut count = 0u32;
                for other_item in items.iter() {
                    if other_item.bounty_id == item.bounty_id {
                        count += 1;
                    }
                }
                if count > 1 {
                    return Err(Error::DuplicateBountyId);
                }
            }

            let ordered_items = Self::order_batch_lock_items(&env, &items);

            // Collect unique depositors and require auth once for each
            // This prevents "frame is already authorized" errors when same depositor appears multiple times
            let mut seen_depositors: Vec<Address> = Vec::new(&env);
            for item in ordered_items.iter() {
                let mut found = false;
                for seen in seen_depositors.iter() {
                    if seen.clone() == item.depositor {
                        found = true;
                        break;
                    }
                }
                if !found {
                    seen_depositors.push_back(item.depositor.clone());
                    item.depositor.require_auth();
                }
            }

            // Process all items (atomic - all succeed or all fail)
            // First loop: write all state (escrow, indices). Second loop: transfers + events.
            let mut locked_count = 0u32;
            for item in ordered_items.iter() {
                let escrow = Escrow {
                    depositor: item.depositor.clone(),
                    amount: item.amount,
                    status: EscrowStatus::Locked,
                    deadline: item.deadline,
                    refund_history: vec![&env],
                    remaining_amount: item.amount,
                    archived: false,
                    archived_at: None,
                };

                env.storage()
                    .persistent()
                    .set(&DataKey::Escrow(item.bounty_id), &escrow);

                let mut index: Vec<u64> = env
                    .storage()
                    .persistent()
                    .get(&DataKey::EscrowIndex)
                    .unwrap_or(Vec::new(&env));
                index.push_back(item.bounty_id);
                env.storage()
                    .persistent()
                    .set(&DataKey::EscrowIndex, &index);

                let mut depositor_index: Vec<u64> = env
                    .storage()
                    .persistent()
                    .get(&DataKey::DepositorIndex(item.depositor.clone()))
                    .unwrap_or(Vec::new(&env));
                depositor_index.push_back(item.bounty_id);
                env.storage().persistent().set(
                    &DataKey::DepositorIndex(item.depositor.clone()),
                    &depositor_index,
                );
            }

            // INTERACTION: all external token transfers happen after state is finalized
            for item in ordered_items.iter() {
                client.transfer(&item.depositor, &contract_address, &item.amount);

                emit_funds_locked(
                    &env,
                    FundsLocked {
                        version: EVENT_VERSION_V2,
                        bounty_id: item.bounty_id,
                        amount: item.amount,
                        depositor: item.depositor.clone(),
                        deadline: item.deadline,
                    },
                );

                locked_count += 1;
            }

            emit_batch_funds_locked(
                &env,
                BatchFundsLocked {
                    count: locked_count,
                    total_amount: ordered_items
                        .iter()
                        .try_fold(0i128, |acc, i| acc.checked_add(i.amount))
                        .unwrap(),
                    timestamp,
                },
            );
            Ok(locked_count)
        })();

        // Gas budget cap enforcement (test / testutils only).
        #[cfg(any(test, feature = "testutils"))]
        if result.is_ok() {
            let gas_cfg = gas_budget::get_config(&env);
            if let Err(e) = gas_budget::check(
                &env,
                symbol_short!("b_lock"),
                &gas_cfg.batch_lock,
                &gas_snapshot,
                gas_cfg.enforce,
            ) {
                reentrancy_guard::release(&env);
                return Err(e);
            }
        }

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        result
    }

    /// Alias for batch_lock_funds to match the requested naming convention.
    pub fn batch_lock(env: Env, items: Vec<LockFundsItem>) -> Result<u32, Error> {
        Self::batch_lock_funds(env, items)
    }

    /// Batch release funds to multiple contributors in a single atomic transaction.
    ///
    /// Releases between 1 and [`MAX_BATCH_SIZE`] bounties in one admin-authorised
    /// call, reducing per-transaction overhead compared to repeated single-item
    /// `release_funds` calls.
    ///
    /// ## Batch failure semantics
    ///
    /// This operation is **strictly atomic** (all-or-nothing):
    ///
    /// 1. All items are validated in a single pass **before** any escrow status
    ///    is updated or any token transfer is initiated.
    /// 2. If *any* item fails validation the entire call reverts immediately.
    ///    No status is changed, no token leaves the contract, and every
    ///    "sibling" row in the same batch is left completely unaffected.
    /// 3. After a failed batch the contract is in exactly the same state as
    ///    before the call; subsequent operations behave as if this call never
    ///    happened.
    ///
    /// ## Ordering guarantee
    ///
    /// Items are processed in ascending `bounty_id` order regardless of the
    /// caller-supplied ordering, ensuring deterministic execution.
    ///
    /// ## Checks-Effects-Interactions (CEI)
    ///
    /// All escrow statuses are updated to `Released` in a first pass (Effects);
    /// external token transfers and event emissions happen in a second pass
    /// (Interactions).
    ///
    /// # Arguments
    /// * `items` - 1–[`MAX_BATCH_SIZE`] [`ReleaseFundsItem`] entries (bounty_id,
    ///   contributor address).
    ///
    /// # Returns
    /// Number of bounties successfully released (equals `items.len()` on success).
    ///
    /// # Errors
    /// * [`Error::InvalidBatchSize`] — batch is empty or exceeds `MAX_BATCH_SIZE`
    /// * [`Error::FundsPaused`] — release operations are currently paused
    /// * [`Error::NotInitialized`] — `init` has not been called
    /// * [`Error::Unauthorized`] — caller is not the admin
    /// * [`Error::BountyNotFound`] — a `bounty_id` does not exist in storage
    /// * [`Error::FundsNotLocked`] — a bounty's status is not `Locked`
    /// * [`Error::DuplicateBountyId`] — the same `bounty_id` appears more than once
    ///
    /// # Reentrancy
    /// Protected by the shared reentrancy guard (acquired before validation,
    /// released after all effects and interactions complete).
    pub fn batch_release_funds(env: Env, items: Vec<ReleaseFundsItem>) -> Result<u32, Error> {
        if Self::check_paused(&env, symbol_short!("release")) {
            return Err(Error::FundsPaused);
        }
        // GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);
        // Snapshot resource meters for gas cap enforcement (test / testutils only).
        #[cfg(any(test, feature = "testutils"))]
        let gas_snapshot = gas_budget::capture(&env);
        let result: Result<u32, Error> = (|| {
            // Validate batch size
            let batch_size = items.len();
            if batch_size == 0 {
                return Err(Error::InvalidBatchSize);
            }
            if batch_size > MAX_BATCH_SIZE {
                return Err(Error::InvalidBatchSize);
            }

            if !env.storage().instance().has(&DataKey::Admin) {
                return Err(Error::NotInitialized);
            }

            let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
            admin.require_auth();

            let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
            let client = token::Client::new(&env, &token_addr);
            let contract_address = env.current_contract_address();
            let timestamp = env.ledger().timestamp();

            // Validate all items before processing (all-or-nothing approach)
            let mut total_amount: i128 = 0;
            for item in items.iter() {
                // Check if bounty exists
                if !env
                    .storage()
                    .persistent()
                    .has(&DataKey::Escrow(item.bounty_id))
                {
                    return Err(Error::BountyNotFound);
                }

                let escrow: Escrow = env
                    .storage()
                    .persistent()
                    .get(&DataKey::Escrow(item.bounty_id))
                    .unwrap();

                Self::ensure_escrow_not_frozen(&env, item.bounty_id)?;
                Self::ensure_address_not_frozen(&env, &escrow.depositor)?;

                // Check if funds are locked
                if escrow.status != EscrowStatus::Locked {
                    return Err(Error::FundsNotLocked);
                }

                // Check for duplicate bounty_ids in the batch
                let mut count = 0u32;
                for other_item in items.iter() {
                    if other_item.bounty_id == item.bounty_id {
                        count += 1;
                    }
                }
                if count > 1 {
                    return Err(Error::DuplicateBountyId);
                }

                total_amount = total_amount
                    .checked_add(escrow.amount)
                    .ok_or(Error::InvalidAmount)?;
            }

            let ordered_items = Self::order_batch_release_items(&env, &items);

            // EFFECTS: update all escrow records before any external calls (CEI)
            // We collect (contributor, amount) pairs for the transfer pass.
            let mut release_pairs: Vec<(Address, i128)> = Vec::new(&env);
            let mut released_count = 0u32;
            for item in ordered_items.iter() {
                let mut escrow: Escrow = env
                    .storage()
                    .persistent()
                    .get(&DataKey::Escrow(item.bounty_id))
                    .unwrap();

                let amount = escrow.amount;
                escrow.status = EscrowStatus::Released;
                escrow.remaining_amount = 0;
                env.storage()
                    .persistent()
                    .set(&DataKey::Escrow(item.bounty_id), &escrow);

                release_pairs.push_back((item.contributor.clone(), amount));
                released_count += 1;
            }

            // INTERACTION: all external token transfers happen after state is finalized
            for (idx, item) in ordered_items.iter().enumerate() {
                let (ref contributor, amount) = release_pairs.get(idx as u32).unwrap();
                client.transfer(&contract_address, contributor, &amount);

                emit_funds_released(
                    &env,
                    FundsReleased {
                        version: EVENT_VERSION_V2,
                        bounty_id: item.bounty_id,
                        amount,
                        recipient: contributor.clone(),
                        timestamp,
                    },
                );
            }

            // Emit batch event
            emit_batch_funds_released(
                &env,
                BatchFundsReleased {
                    count: released_count,
                    total_amount,
                    timestamp,
                },
            );

            Ok(released_count)
        })();

        // Gas budget cap enforcement (test / testutils only).
        #[cfg(any(test, feature = "testutils"))]
        if result.is_ok() {
            let gas_cfg = gas_budget::get_config(&env);
            if let Err(e) = gas_budget::check(
                &env,
                symbol_short!("b_rls"),
                &gas_cfg.batch_release,
                &gas_snapshot,
                gas_cfg.enforce,
            ) {
                reentrancy_guard::release(&env);
                return Err(e);
            }
        }

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        result
    }
}

#[cfg(test)]
mod test_max_counts;
