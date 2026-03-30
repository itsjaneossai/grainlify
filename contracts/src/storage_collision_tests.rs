//! # Storage Key Collision Tests
//!
//! Comprehensive test suite to ensure storage key namespace isolation
//! and prevent cross-contract storage collisions.

use soroban_sdk::{Env, Symbol};
use grainlify_contracts::storage_key_audit::{
    program_escrow, bounty_escrow, shared, validation, namespaces,
};

#[cfg(test)]
mod collision_tests {
    use super::*;

    /// Test that all program escrow symbols use correct namespace
    #[test]
    fn test_program_escrow_namespace_compliance() {
        let env = Env::default();
        
        let program_symbols = vec![
            &env,
            program_escrow::PROGRAM_INITIALIZED,
            program_escrow::FUNDS_LOCKED,
            program_escrow::BATCH_FUNDS_LOCKED,
            program_escrow::BATCH_FUNDS_RELEASED,
            program_escrow::BATCH_PAYOUT,
            program_escrow::PAYOUT,
            program_escrow::PAUSE_STATE_CHANGED,
            program_escrow::MAINTENANCE_MODE_CHANGED,
            program_escrow::READ_ONLY_MODE_CHANGED,
            program_escrow::PROGRAM_RISK_FLAGS_UPDATED,
            program_escrow::PROGRAM_REGISTRY,
            program_escrow::PROGRAM_REGISTERED,
            program_escrow::RELEASE_SCHEDULED,
            program_escrow::SCHEDULE_RELEASED,
            program_escrow::PROGRAM_DELEGATE_SET,
            program_escrow::PROGRAM_DELEGATE_REVOKED,
            program_escrow::PROGRAM_METADATA_UPDATED,
            program_escrow::DISPUTE_OPENED,
            program_escrow::DISPUTE_RESOLVED,
            program_escrow::PROGRAM_DATA,
            program_escrow::RECEIPT_ID,
            program_escrow::SCHEDULES,
            program_escrow::RELEASE_HISTORY,
            program_escrow::NEXT_SCHEDULE_ID,
            program_escrow::PROGRAM_INDEX,
            program_escrow::AUTH_KEY_INDEX,
            program_escrow::FEE_CONFIG,
            program_escrow::FEE_COLLECTED,
        ];

        for symbol in program_symbols.iter() {
            let result = validation::validate_storage_key(*symbol, namespaces::PROGRAM_ESCROW);
            assert!(result.is_ok(), 
                "Program escrow symbol {:?} should validate with PE_ prefix: {:?}", 
                symbol, result.err());
        }
    }

    /// Test that all bounty escrow symbols use correct namespace
    #[test]
    fn test_bounty_escrow_namespace_compliance() {
        let env = Env::default();
        
        let bounty_symbols = vec![
            &env,
            bounty_escrow::BOUNTY_INITIALIZED,
            bounty_escrow::FUNDS_LOCKED,
            bounty_escrow::FUNDS_LOCKED_ANON,
            bounty_escrow::FUNDS_RELEASED,
            bounty_escrow::FUNDS_REFUNDED,
            bounty_escrow::ESCRROW_PUBLISHED,
            bounty_escrow::TICKET_ISSUED,
            bounty_escrow::TICKET_CLAIMED,
            bounty_escrow::MAINTENANCE_MODE_CHANGED,
            bounty_escrow::PAUSE_STATE_CHANGED,
            bounty_escrow::RISK_FLAGS_UPDATED,
            bounty_escrow::DEPRECATION_STATE_CHANGED,
            bounty_escrow::ADMIN,
            bounty_escrow::TOKEN,
            bounty_escrow::VERSION,
            bounty_escrow::ESCRROW_INDEX,
            bounty_escrow::DEPOSITOR_INDEX,
            bounty_escrow::ESCRROW_FREEZE,
            bounty_escrow::ADDRESS_FREEZE,
            bounty_escrow::FEE_CONFIG,
            bounty_escrow::REFUND_APPROVAL,
            bounty_escrow::REENTRANCY_GUARD,
            bounty_escrow::MULTISIG_CONFIG,
            bounty_escrow::RELEASE_APPROVAL,
            bounty_escrow::PENDING_CLAIM,
            bounty_escrow::TICKET_COUNTER,
            bounty_escrow::CLAIM_TICKET,
            bounty_escrow::CLAIM_TICKET_INDEX,
            bounty_escrow::BENEFICIARY_TICKETS,
            bounty_escrow::CLAIM_WINDOW,
            bounty_escrow::PAUSE_FLAGS,
            bounty_escrow::AMOUNT_POLICY,
            bounty_escrow::CAPABILITY_NONCE,
            bounty_escrow::CAPABILITY,
            bounty_escrow::NON_TRANSFERABLE_REWARDS,
            bounty_escrow::DEPRECATION_STATE,
            bounty_escrow::PARTICIPANT_FILTER_MODE,
            bounty_escrow::ANONYMOUS_RESOLVER,
            bounty_escrow::TOKEN_FEE_CONFIG,
            bounty_escrow::CHAIN_ID,
            bounty_escrow::NETWORK_ID,
            bounty_escrow::MAINTENANCE_MODE,
            bounty_escrow::GAS_BUDGET_CONFIG,
            bounty_escrow::TIMELOCK_CONFIG,
            bounty_escrow::PENDING_ACTION,
            bounty_escrow::ACTION_COUNTER,
        ];

        for symbol in bounty_symbols.iter() {
            let result = validation::validate_storage_key(*symbol, namespaces::BOUNTY_ESCROW);
            assert!(result.is_ok(), 
                "Bounty escrow symbol {:?} should validate with BE_ prefix: {:?}", 
                symbol, result.err());
        }
    }

    /// Test cross-namespace isolation - no symbol should validate with wrong prefix
    #[test]
    fn test_cross_namespace_isolation() {
        let env = Env::default();
        
        // Program escrow symbols should NOT validate with bounty prefix
        let program_symbols = vec![
            &env,
            program_escrow::PROGRAM_INITIALIZED,
            program_escrow::PROGRAM_DATA,
            program_escrow::FEE_CONFIG,
        ];
        
        for symbol in program_symbols.iter() {
            let result = validation::validate_storage_key(*symbol, namespaces::BOUNTY_ESCROW);
            assert!(result.is_err(), 
                "Program escrow symbol {:?} should NOT validate with BE_ prefix", 
                symbol);
        }

        // Bounty escrow symbols should NOT validate with program prefix
        let bounty_symbols = vec![
            &env,
            bounty_escrow::BOUNTY_INITIALIZED,
            bounty_escrow::ADMIN,
            bounty_escrow::FEE_CONFIG,
        ];
        
        for symbol in bounty_symbols.iter() {
            let result = validation::validate_storage_key(*symbol, namespaces::PROGRAM_ESCROW);
            assert!(result.is_err(), 
                "Bounty escrow symbol {:?} should NOT validate with PE_ prefix", 
                symbol);
        }
    }

    /// Test for duplicate symbols across contracts
    #[test]
    fn test_no_duplicate_symbols() {
        let env = Env::default();
        
        // Collect all symbols as strings for comparison
        let mut all_symbols = std::collections::HashSet::new();
        
        // Program escrow symbols
        let program_symbols = vec![
            program_escrow::PROGRAM_INITIALIZED,
            program_escrow::FUNDS_LOCKED,
            program_escrow::PROGRAM_DATA,
            program_escrow::FEE_CONFIG,
        ];
        
        // Bounty escrow symbols  
        let bounty_symbols = vec![
            bounty_escrow::BOUNTY_INITIALIZED,
            bounty_escrow::FUNDS_LOCKED,
            bounty_escrow::ADMIN,
            bounty_escrow::FEE_CONFIG,
        ];

        // Check program escrow symbols for duplicates
        for symbol in program_symbols.iter() {
            let symbol_str = symbol.to_string();
            assert!(!all_symbols.contains(&symbol_str), 
                "Duplicate program escrow symbol found: {}", symbol_str);
            all_symbols.insert(symbol_str);
        }

        // Check bounty escrow symbols for duplicates
        for symbol in bounty_symbols.iter() {
            let symbol_str = symbol.to_string();
            assert!(!all_symbols.contains(&symbol_str), 
                "Duplicate bounty escrow symbol found: {}", symbol_str);
            all_symbols.insert(symbol_str);
        }
    }

    /// Test shared constants are consistent
    #[test]
    fn test_shared_constants_consistency() {
        assert_eq!(shared::EVENT_VERSION_V2, 2);
        assert_eq!(shared::BASIS_POINTS, 10_000);
        assert_eq!(shared::RISK_FLAG_HIGH_RISK, 1 << 0);
        assert_eq!(shared::RISK_FLAG_UNDER_REVIEW, 1 << 1);
        assert_eq!(shared::RISK_FLAG_RESTRICTED, 1 << 2);
        assert_eq!(shared::RISK_FLAG_DEPRECATED, 1 << 3);
    }

    /// Test namespace prefix validation
    #[test]
    fn test_namespace_prefix_validation() {
        assert!(validation::validate_namespace("PE_Test", namespaces::PROGRAM_ESCROW));
        assert!(!validation::validate_namespace("BE_Test", namespaces::PROGRAM_ESCROW));
        assert!(!validation::validate_namespace("Test", namespaces::PROGRAM_ESCROW));
        
        assert!(validation::validate_namespace("BE_Test", namespaces::BOUNTY_ESCROW));
        assert!(!validation::validate_namespace("PE_Test", namespaces::BOUNTY_ESCROW));
        assert!(!validation::validate_namespace("Test", namespaces::BOUNTY_ESCROW));
    }

    /// Test storage migration safety - ensure no key remapping during upgrades
    #[test]
    fn test_storage_migration_safety() {
        let env = Env::default();
        
        // Simulate storage keys that would be problematic during migration
        let problematic_keys = vec![
            "Admin",           // Too generic, could collide
            "Token",          // Too generic, could collide  
            "FeeConfig",       // Same name in both contracts (before namespacing)
            "PauseFlags",      // Same name in both contracts (before namespacing)
        ];
        
        // Ensure all actual keys are properly namespaced
        let program_keys = vec![
            program_escrow::PROGRAM_DATA,
            program_escrow::FEE_CONFIG,
            program_escrow::PAUSE_FLAGS,
        ];
        
        let bounty_keys = vec![
            bounty_escrow::ADMIN,
            bounty_escrow::TOKEN,
            bounty_escrow::FEE_CONFIG,
            bounty_escrow::PAUSE_FLAGS,
        ];
        
        // All keys should be properly namespaced
        for key in program_keys.iter().chain(bounty_keys.iter()) {
            let key_str = key.to_string();
            assert!(key_str.starts_with("PE_") || key_str.starts_with("BE_"), 
                "Key {} should be properly namespaced", key_str);
            
            // Should not match any problematic patterns
            for problematic in &problematic_keys {
                assert_ne!(key_str, *problematic, 
                    "Key {} matches problematic pattern {}", key_str, problematic);
            }
        }
    }

    /// Test symbol length constraints (Soroban limit is 9 bytes for symbol_short)
    #[test]
    fn test_symbol_length_constraints() {
        let env = Env::default();
        
        let all_symbols = vec![
            // Program escrow symbols
            program_escrow::PROGRAM_INITIALIZED,
            program_escrow::FUNDS_LOCKED,
            program_escrow::PROGRAM_DATA,
            program_escrow::FEE_CONFIG,
            
            // Bounty escrow symbols
            bounty_escrow::BOUNTY_INITIALIZED,
            bounty_escrow::FUNDS_LOCKED,
            bounty_escrow::ADMIN,
            bounty_escrow::FEE_CONFIG,
        ];
        
        for symbol in all_symbols.iter() {
            let symbol_str = symbol.to_string();
            assert!(symbol_str.len() <= 9, 
                "Symbol {} exceeds 9-byte limit: {} bytes", 
                symbol_str, symbol_str.len());
        }
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;

    /// Test that previously identified collision risks are resolved
    #[test]
    fn test_previous_collision_risks_resolved() {
        let env = Env::default();
        
        // These were the problematic keys before namespacing:
        // - Both contracts used "Admin", "Token", "FeeConfig", "PauseFlags"
        // - Both used similar event symbols without prefixes
        
        // Verify program escrow uses PE_ prefix
        let pe_admin = program_escrow::PROGRAM_DATA; // Was "ProgData" -> "PE_ProgData"
        let pe_fee_config = program_escrow::FEE_CONFIG;   // Was "FeeCfg" -> "PE_FeeCfg"
        
        assert!(validation::validate_storage_key(pe_admin, namespaces::PROGRAM_ESCROW).is_ok());
        assert!(validation::validate_storage_key(pe_fee_config, namespaces::PROGRAM_ESCROW).is_ok());
        
        // Verify bounty escrow uses BE_ prefix
        let be_admin = bounty_escrow::ADMIN;           // Was "Admin" -> "BE_Admin"
        let be_fee_config = bounty_escrow::FEE_CONFIG;   // Was "FeeConfig" -> "BE_FeeCfg"
        
        assert!(validation::validate_storage_key(be_admin, namespaces::BOUNTY_ESCROW).is_ok());
        assert!(validation::validate_storage_key(be_fee_config, namespaces::BOUNTY_ESCROW).is_ok());
        
        // Verify cross-pollination is prevented
        assert!(validation::validate_storage_key(pe_admin, namespaces::BOUNTY_ESCROW).is_err());
        assert!(validation::validate_storage_key(be_admin, namespaces::PROGRAM_ESCROW).is_err());
    }

    /// Test event symbol isolation
    #[test]
    fn test_event_symbol_isolation() {
        let env = Env::default();
        
        // Both contracts had similar event names before namespacing
        let pe_funds_locked = program_escrow::FUNDS_LOCKED;      // "PE_FndsLock"
        let be_funds_locked = bounty_escrow::FUNDS_LOCKED;      // "BE_f_lock"
        
        let pe_pause_changed = program_escrow::PAUSE_STATE_CHANGED;  // "PE_PauseSt"
        let be_pause_changed = bounty_escrow::PAUSE_STATE_CHANGED;  // "BE_pause"
        
        // Should be different symbols
        assert_ne!(pe_funds_locked, be_funds_locked);
        assert_ne!(pe_pause_changed, be_pause_changed);
        
        // Should validate with correct namespaces
        assert!(validation::validate_storage_key(pe_funds_locked, namespaces::PROGRAM_ESCROW).is_ok());
        assert!(validation::validate_storage_key(be_funds_locked, namespaces::BOUNTY_ESCROW).is_ok());
        assert!(validation::validate_storage_key(pe_pause_changed, namespaces::PROGRAM_ESCROW).is_ok());
        assert!(validation::validate_storage_key(be_pause_changed, namespaces::BOUNTY_ESCROW).is_ok());
        
        // Should not validate with wrong namespaces
        assert!(validation::validate_storage_key(pe_funds_locked, namespaces::BOUNTY_ESCROW).is_err());
        assert!(validation::validate_storage_key(be_funds_locked, namespaces::PROGRAM_ESCROW).is_err());
    }
}
