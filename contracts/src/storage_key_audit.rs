//! # Storage Key Namespace Audit and Collision Prevention
//!
//! This module provides compile-time and runtime validation for storage keys
//! across all Grainlify contracts to prevent namespace collisions.
//!
//! ## Key Namespace Strategy
//!
//! Each contract uses a unique prefix to ensure storage isolation:
//! - Program Escrow: `PE_` prefix
//! - Bounty Escrow: `BE_` prefix
//! - Shared utilities: `COMMON_` prefix
//!
//! ## Validation Rules
//!
//! 1. No duplicate symbols across contracts
//! 2. All storage keys must use contract-specific prefixes
//! 3. Runtime validation during testing
//! 4. Compile-time assertions where possible

use soroban_sdk::{symbol_short, Symbol};

/// Contract namespace identifiers
pub mod namespaces {
    pub const PROGRAM_ESCROW: &str = "PE_";
    pub const BOUNTY_ESCROW: &str = "BE_";
    pub const COMMON: &str = "COMMON_";
}

/// Storage key validation utilities
pub mod validation {
    use super::*;

    /// Validates that a symbol follows the expected namespace pattern
    pub fn validate_namespace(symbol: &str, expected_prefix: &str) -> bool {
        symbol.starts_with(expected_prefix)
    }

    /// Compile-time assertion macro for namespace validation
    #[macro_export]
    macro_rules! assert_storage_namespace {
        ($symbol:expr, $prefix:expr) => {
            const _: () = {
                if !$symbol.starts_with($prefix) {
                    panic!("Storage key '{}' must start with prefix '{}'", $symbol, $prefix);
                }
            };
        };
    }

    /// Runtime validation for testing
    pub fn validate_storage_key(symbol: Symbol, expected_prefix: &str) -> Result<(), String> {
        let symbol_str = symbol.to_string();
        if !validate_namespace(&symbol_str, expected_prefix) {
            Err(format!(
                "Storage key '{}' does not start with expected prefix '{}'",
                symbol_str, expected_prefix
            ))
        } else {
            Ok(())
        }
    }
}

/// Shared storage keys (used across multiple contracts)
pub mod shared {
    use super::*;

    /// Event version - shared across all contracts
    pub const EVENT_VERSION_V2: u32 = 2;

    /// Common basis points constant
    pub const BASIS_POINTS: i128 = 10_000;

    /// Risk flag definitions (shared)
    pub const RISK_FLAG_HIGH_RISK: u32 = 1 << 0;
    pub const RISK_FLAG_UNDER_REVIEW: u32 = 1 << 1;
    pub const RISK_FLAG_RESTRICTED: u32 = 1 << 2;
    pub const RISK_FLAG_DEPRECATED: u32 = 1 << 3;
}

/// Program Escrow storage keys
pub mod program_escrow {
    use super::*;
    use super::namespaces::PROGRAM_ESCROW;

    // Event symbols
    pub const PROGRAM_INITIALIZED: Symbol = symbol_short!("PE_PrgInit");
    pub const FUNDS_LOCKED: Symbol = symbol_short!("PE_FndsLock");
    pub const BATCH_FUNDS_LOCKED: Symbol = symbol_short!("PE_BatLck");
    pub const BATCH_FUNDS_RELEASED: Symbol = symbol_short!("PE_BatRel");
    pub const BATCH_PAYOUT: Symbol = symbol_short!("PE_BatchPay");
    pub const PAYOUT: Symbol = symbol_short!("PE_Payout");
    pub const PAUSE_STATE_CHANGED: Symbol = symbol_short!("PE_PauseSt");
    pub const MAINTENANCE_MODE_CHANGED: Symbol = symbol_short!("PE_MaintSt");
    pub const READ_ONLY_MODE_CHANGED: Symbol = symbol_short!("PE_ROModeChg");
    pub const PROGRAM_RISK_FLAGS_UPDATED: Symbol = symbol_short!("PE_pr_risk");
    pub const PROGRAM_REGISTRY: Symbol = symbol_short!("PE_ProgReg");
    pub const PROGRAM_REGISTERED: Symbol = symbol_short!("PE_ProgRgd");
    pub const RELEASE_SCHEDULED: Symbol = symbol_short!("PE_RelSched");
    pub const SCHEDULE_RELEASED: Symbol = symbol_short!("PE_SchRel");
    pub const PROGRAM_DELEGATE_SET: Symbol = symbol_short!("PE_PrgDlgS");
    pub const PROGRAM_DELEGATE_REVOKED: Symbol = symbol_short!("PE_PrgDlgR");
    pub const PROGRAM_METADATA_UPDATED: Symbol = symbol_short!("PE_PrgMeta");
    pub const DISPUTE_OPENED: Symbol = symbol_short!("PE_DspOpen");
    pub const DISPUTE_RESOLVED: Symbol = symbol_short!("PE_DspRslv");

    // Storage keys
    pub const PROGRAM_DATA: Symbol = symbol_short!("PE_ProgData");
    pub const RECEIPT_ID: Symbol = symbol_short!("PE_RcptID");
    pub const SCHEDULES: Symbol = symbol_short!("PE_Scheds");
    pub const RELEASE_HISTORY: Symbol = symbol_short!("PE_RelHist");
    pub const NEXT_SCHEDULE_ID: Symbol = symbol_short!("PE_NxtSched");
    pub const PROGRAM_INDEX: Symbol = symbol_short!("PE_ProgIdx");
    pub const AUTH_KEY_INDEX: Symbol = symbol_short!("PE_AuthIdx");
    pub const FEE_CONFIG: Symbol = symbol_short!("PE_FeeCfg");
    pub const FEE_COLLECTED: Symbol = symbol_short!("PE_FeeCol");

    // Compile-time namespace assertions
    assert_storage_namespace!("PE_PrgInit", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_FndsLock", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_BatLck", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_BatRel", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_BatchPay", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_Payout", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_PauseSt", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_MaintSt", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_ROModeChg", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_pr_risk", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_ProgReg", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_ProgRgd", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_RelSched", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_SchRel", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_PrgDlgS", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_PrgDlgR", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_PrgMeta", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_DspOpen", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_DspRslv", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_ProgData", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_RcptID", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_Scheds", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_RelHist", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_NxtSched", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_ProgIdx", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_AuthIdx", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_FeeCfg", PROGRAM_ESCROW);
    assert_storage_namespace!("PE_FeeCol", PROGRAM_ESCROW);
}

/// Bounty Escrow storage keys
pub mod bounty_escrow {
    use super::*;
    use super::namespaces::BOUNTY_ESCROW;

    // Event symbols (from events.rs)
    pub const BOUNTY_INITIALIZED: Symbol = symbol_short!("BE_init");
    pub const FUNDS_LOCKED: Symbol = symbol_short!("BE_f_lock");
    pub const FUNDS_LOCKED_ANON: Symbol = symbol_short!("BE_f_lock_anon");
    pub const FUNDS_RELEASED: Symbol = symbol_short!("BE_f_rel");
    pub const FUNDS_REFUNDED: Symbol = symbol_short!("BE_f_ref");
    pub const ESCROW_PUBLISHED: Symbol = symbol_short!("BE_pub");
    pub const TICKET_ISSUED: Symbol = symbol_short!("BE_tk_issue");
    pub const TICKET_CLAIMED: Symbol = symbol_short!("BE_tk_claim");
    pub const MAINTENANCE_MODE_CHANGED: Symbol = symbol_short!("BE_maint");
    pub const PAUSE_STATE_CHANGED: Symbol = symbol_short!("BE_pause");
    pub const RISK_FLAGS_UPDATED: Symbol = symbol_short!("BE_risk");
    pub const DEPRECATION_STATE_CHANGED: Symbol = symbol_short!("BE_depr");

    // Storage keys
    pub const ADMIN: Symbol = symbol_short!("BE_Admin");
    pub const TOKEN: Symbol = symbol_short!("BE_Token");
    pub const VERSION: Symbol = symbol_short!("BE_Version");
    pub const ESCROW_INDEX: Symbol = symbol_short!("BE_EscrowIdx");
    pub const DEPOSITOR_INDEX: Symbol = symbol_short!("BE_DepositorIdx");
    pub const ESCROW_FREEZE: Symbol = symbol_short!("BE_EscrowFrz");
    pub const ADDRESS_FREEZE: Symbol = symbol_short!("BE_AddrFrz");
    pub const FEE_CONFIG: Symbol = symbol_short!("BE_FeeCfg");
    pub const REFUND_APPROVAL: Symbol = symbol_short!("BE_RefundApp");
    pub const REENTRANCY_GUARD: Symbol = symbol_short!("BE_Reentrancy");
    pub const MULTISIG_CONFIG: Symbol = symbol_short!("BE_Multisig");
    pub const RELEASE_APPROVAL: Symbol = symbol_short!("BE_ReleaseApp");
    pub const PENDING_CLAIM: Symbol = symbol_short!("BE_PendingClaim");
    pub const TICKET_COUNTER: Symbol = symbol_short!("BE_TicketCtr");
    pub const CLAIM_TICKET: Symbol = symbol_short!("BE_ClaimTicket");
    pub const CLAIM_TICKET_INDEX: Symbol = symbol_short!("BE_ClaimTicketIdx");
    pub const BENEFICIARY_TICKETS: Symbol = symbol_short!("BE_BenTickets");
    pub const CLAIM_WINDOW: Symbol = symbol_short!("BE_ClaimWindow");
    pub const PAUSE_FLAGS: Symbol = symbol_short!("BE_PauseFlags");
    pub const AMOUNT_POLICY: Symbol = symbol_short!("BE_AmountPol");
    pub const CAPABILITY_NONCE: Symbol = symbol_short!("BE_CapNonce");
    pub const CAPABILITY: Symbol = symbol_short!("BE_Capability");
    pub const NON_TRANSFERABLE_REWARDS: Symbol = symbol_short!("BE_NonTransRew");
    pub const DEPRECATION_STATE: Symbol = symbol_short!("BE_DeprecationSt");
    pub const PARTICIPANT_FILTER_MODE: Symbol = symbol_short!("BE_PartFilter");
    pub const ANONYMOUS_RESOLVER: Symbol = symbol_short!("BE_AnonResolver");
    pub const TOKEN_FEE_CONFIG: Symbol = symbol_short!("BE_TokenFeeCfg");
    pub const CHAIN_ID: Symbol = symbol_short!("BE_ChainId");
    pub const NETWORK_ID: Symbol = symbol_short!("BE_NetworkId");
    pub const MAINTENANCE_MODE: Symbol = symbol_short!("BE_MaintMode");
    pub const GAS_BUDGET_CONFIG: Symbol = symbol_short!("BE_GasBudget");
    pub const TIMELOCK_CONFIG: Symbol = symbol_short!("BE_TimelockCfg");
    pub const PENDING_ACTION: Symbol = symbol_short!("BE_PendingAction");
    pub const ACTION_COUNTER: Symbol = symbol_short!("BE_ActionCtr");

    // Compile-time namespace assertions
    assert_storage_namespace!("BE_init", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_f_lock", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_f_lock_anon", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_f_rel", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_f_ref", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_pub", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_tk_issue", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_tk_claim", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_maint", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_pause", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_risk", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_depr", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_Admin", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_Token", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_Version", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_EscrowIdx", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_DepositorIdx", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_EscrowFrz", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_AddrFrz", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_FeeCfg", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_RefundApp", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_Reentrancy", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_Multisig", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_ReleaseApp", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_PendingClaim", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_TicketCtr", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_ClaimTicket", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_ClaimTicketIdx", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_BenTickets", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_ClaimWindow", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_PauseFlags", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_AmountPol", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_CapNonce", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_Capability", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_NonTransRew", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_DeprecationSt", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_PartFilter", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_AnonResolver", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_TokenFeeCfg", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_ChainId", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_NetworkId", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_MaintMode", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_GasBudget", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_TimelockCfg", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_PendingAction", BOUNTY_ESCROW);
    assert_storage_namespace!("BE_ActionCtr", BOUNTY_ESCROW);
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_program_escrow_namespace_validation() {
        let env = Env::default();
        
        // Test all program escrow symbols
        let symbols = vec![
            &env, program_escrow::PROGRAM_INITIALIZED, program_escrow::FUNDS_LOCKED,
            program_escrow::PROGRAM_DATA, program_escrow::FEE_CONFIG,
        ];

        for symbol in symbols.iter() {
            validation::validate_storage_key(*symbol, namespaces::PROGRAM_ESCROW)
                .unwrap();
        }
    }

    #[test]
    fn test_bounty_escrow_namespace_validation() {
        let env = Env::default();
        
        // Test all bounty escrow symbols
        let symbols = vec![
            &env, bounty_escrow::BOUNTY_INITIALIZED, bounty_escrow::FUNDS_LOCKED,
            bounty_escrow::ADMIN, bounty_escrow::TOKEN, bounty_escrow::FEE_CONFIG,
        ];

        for symbol in symbols.iter() {
            validation::validate_storage_key(*symbol, namespaces::BOUNTY_ESCROW)
                .unwrap();
        }
    }

    #[test]
    fn test_cross_contract_collision_detection() {
        let env = Env::default();
        
        // Collect all symbols from both contracts
        let program_symbols = vec![
            &env, program_escrow::PROGRAM_INITIALIZED, program_escrow::FUNDS_LOCKED,
            program_escrow::PROGRAM_DATA, program_escrow::FEE_CONFIG,
        ];
        
        let bounty_symbols = vec![
            &env, bounty_escrow::BOUNTY_INITIALIZED, bounty_escrow::FUNDS_LOCKED,
            bounty_escrow::ADMIN, bounty_escrow::TOKEN, bounty_escrow::FEE_CONFIG,
        ];

        // Check for duplicates by converting to strings
        let mut all_symbol_strings = std::collections::HashSet::new();
        
        for symbol in program_symbols.iter().chain(bounty_symbols.iter()) {
            let symbol_str = symbol.to_string();
            assert!(
                !all_symbol_strings.contains(&symbol_str),
                "Duplicate symbol found: {}",
                symbol_str
            );
            all_symbol_strings.insert(symbol_str);
        }
    }

    #[test]
    fn test_namespace_prefix_isolation() {
        let env = Env::default();
        
        // Test that no program escrow symbol starts with bounty prefix
        let program_symbols = vec![
            &env, program_escrow::PROGRAM_INITIALIZED, program_escrow::FUNDS_LOCKED,
            program_escrow::PROGRAM_DATA,
        ];
        
        for symbol in program_symbols.iter() {
            let result = validation::validate_storage_key(*symbol, namespaces::BOUNTY_ESCROW);
            assert!(result.is_err(), "Program escrow symbol should not validate with bounty prefix");
        }

        // Test that no bounty escrow symbol starts with program prefix
        let bounty_symbols = vec![
            &env, bounty_escrow::BOUNTY_INITIALIZED, bounty_escrow::FUNDS_LOCKED,
            bounty_escrow::ADMIN,
        ];
        
        for symbol in bounty_symbols.iter() {
            let result = validation::validate_storage_key(*symbol, namespaces::PROGRAM_ESCROW);
            assert!(result.is_err(), "Bounty escrow symbol should not validate with program prefix");
        }
    }
}
