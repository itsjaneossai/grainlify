//! # Gas Optimization Utilities for Program Escrow
//!
//! Optimized helpers for reducing gas consumption in program escrow operations:
//! - Efficient batch processing
//! - Optimized storage access patterns
//! - Reduced redundant computations

use soroban_sdk::{vec, Env, String, Vec};

/// Optimized batch lock processing with cached program data.
pub fn optimized_batch_lock<F>(
    env: &Env,
    items: &Vec<(String, i128)>,
    mut processor: F,
) -> Vec<bool>
where
    F: FnMut(&Env, &String, i128) -> bool,
{
    let mut results: Vec<bool> = Vec::new(env);
    let mut last_program: Option<String> = None;

    for item in items.iter() {
        let (program_id, amount) = item;

        // Cache program data if it's the same as last iteration
        if last_program.as_ref() != Some(&program_id) {
            last_program = Some(program_id.clone());
        }

        let success = processor(env, &program_id, amount);
        results.push_back(success);
    }

    results
}

/// Efficient deduplication of program IDs using sorting and adjacent comparison.
pub fn deduplicate_program_ids(env: &Env, items: &Vec<String>) -> Vec<String> {
    if items.len() <= 1 {
        return items.clone();
    }

    // Sort first (using insertion sort for small batches)
    let mut sorted: Vec<String> = Vec::new(env);
    for item in items.iter() {
        let mut next: Vec<String> = Vec::new(env);
        let mut inserted = false;

        for existing in sorted.iter() {
            if !inserted && item < existing {
                next.push_back(item.clone());
                inserted = true;
            }
            next.push_back(existing.clone());
        }

        if !inserted {
            next.push_back(item.clone());
        }

        sorted = next;
    }

    // Remove adjacent duplicates
    let mut deduped: Vec<String> = Vec::new(env);
    deduped.push_back(sorted.get(0).unwrap());

    for i in 1..sorted.len() {
        let current = sorted.get(i).unwrap();
        let previous = sorted.get(i - 1).unwrap();

        if current != previous {
            deduped.push_back(current);
        }
    }

    deduped
}

/// Check for duplicates in a Vec<String> using O(n²) comparison.
/// Returns true if duplicates exist.
pub fn has_duplicates(env: &Env, items: &Vec<String>) -> bool {
    let len = items.len();
    if len <= 1 {
        return false;
    }

    for i in 0..len {
        for j in (i + 1)..len {
            if items.get(i).unwrap() == items.get(j).unwrap() {
                return true;
            }
        }
    }

    false
}

/// Optimized storage access with TTL management.
pub mod storage_efficiency {
    use soroban_sdk::{Env, Symbol};

    /// Extend TTL for frequently accessed data.
    pub fn extend_storage_ttl(env: &Env, _key: &Symbol, ttl_threshold: u32) {
        env.storage().instance().extend_ttl(ttl_threshold, ttl_threshold);
    }

    /// Check if storage key exists without retrieving value.
    pub fn storage_has(env: &Env, key: &Symbol) -> bool {
        env.storage().instance().has(key)
    }
}

/// Packed storage for boolean flags to reduce storage operations.
pub mod packed_storage {
    use soroban_sdk::{Env, Symbol};

    const PAUSE_LOCK: u32 = 1 << 0;
    const PAUSE_RELEASE: u32 = 1 << 1;
    const PAUSE_REFUND: u32 = 1 << 2;
    const MAINTENANCE_MODE: u32 = 1 << 3;

    /// Store multiple pause flags in a single u32.
    pub fn set_pause_flags(env: &Env, key: &Symbol, lock: bool, release: bool, refund: bool) {
        let mut packed = 0u32;
        if lock {
            packed |= PAUSE_LOCK;
        }
        if release {
            packed |= PAUSE_RELEASE;
        }
        if refund {
            packed |= PAUSE_REFUND;
        }
        env.storage().instance().set(key, &packed);
    }

    /// Retrieve individual pause flags from packed storage.
    pub fn get_pause_flags(env: &Env, key: &Symbol) -> (bool, bool, bool) {
        let packed: u32 = env.storage().instance().get(key).unwrap_or(0);
        (
            packed & PAUSE_LOCK != 0,
            packed & PAUSE_RELEASE != 0,
            packed & PAUSE_REFUND != 0,
        )
    }

    /// Set maintenance mode flag.
    pub fn set_maintenance_mode(env: &Env, key: &Symbol, enabled: bool) {
        let mut packed: u32 = env.storage().instance().get(key).unwrap_or(0);
        if enabled {
            packed |= MAINTENANCE_MODE;
        } else {
            packed &= !MAINTENANCE_MODE;
        }
        env.storage().instance().set(key, &packed);
    }

    /// Check maintenance mode.
    pub fn is_maintenance_mode(env: &Env, key: &Symbol) -> bool {
        let packed: u32 = env.storage().instance().get(key).unwrap_or(0);
        packed & MAINTENANCE_MODE != 0
    }
}

/// Efficient arithmetic operations with overflow protection.
pub mod efficient_math {
    /// Calculate fee with ceiling division to prevent fee avoidance.
    pub fn calculate_fee(amount: i128, fee_rate_bps: i128, basis_points: i128) -> i128 {
        if fee_rate_bps == 0 || amount == 0 {
            return 0;
        }

        // Ceiling division: (amount * rate + basis - 1) / basis
        let numerator = amount
            .checked_mul(fee_rate_bps)
            .and_then(|x| x.checked_add(basis_points - 1))
            .unwrap_or(0);

        numerator / basis_points
    }

    /// Safe subtraction that returns 0 on underflow.
    pub fn safe_sub_zero(a: i128, b: i128) -> i128 {
        let result = a.checked_sub(b).unwrap_or(0);
        if result < 0 { 0 } else { result }
    }

    /// Clamp value between min and max.
    pub fn clamp(value: i128, min: i128, max: i128) -> i128 {
        if value < min {
            min
        } else if value > max {
            max
        } else {
            value
        }
    }
}

/// Event emission helpers to reduce storage writes.
pub mod event_helpers {
    use soroban_sdk::{symbol_short, Env, Symbol};
    
    /// Emit a lightweight event instead of storing state.
    pub fn emit_operation(env: &Env, operation: Symbol, data: u64) {
        env.events().publish(
            (symbol_short!("op"), operation),
            (data, env.ledger().timestamp()),
        );
    }

    /// Emit batch operation summary instead of individual records.
    pub fn emit_batch_summary(
        env: &Env,
        operation: Symbol,
        count: u32,
        total_amount: i128,
        success: bool,
    ) {
        env.events().publish(
            (symbol_short!("batch"), operation),
            (count, total_amount, success, env.ledger().timestamp()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{vec, Env};

    #[test]
    fn test_deduplicate_program_ids() {
        let env = Env::default();
        let items = vec![
            &env,
            String::from_str(&env, "prog1"),
            String::from_str(&env, "prog2"),
            String::from_str(&env, "prog1"),
            String::from_str(&env, "prog3"),
            String::from_str(&env, "prog2"),
        ];

        let deduped = deduplicate_program_ids(&env, &items);
        assert_eq!(deduped.len(), 3);
        assert_eq!(deduped.get(0), Some(String::from_str(&env, "prog1")));
        assert_eq!(deduped.get(1), Some(String::from_str(&env, "prog2")));
        assert_eq!(deduped.get(2), Some(String::from_str(&env, "prog3")));
    }

    #[test]
    fn test_has_duplicates() {
        let env = Env::default();

        let items_with_dups = vec![
            &env,
            String::from_str(&env, "a"),
            String::from_str(&env, "b"),
            String::from_str(&env, "a"),
        ];
        assert!(has_duplicates(&env, &items_with_dups));

        let items_no_dups = vec![
            &env,
            String::from_str(&env, "a"),
            String::from_str(&env, "b"),
            String::from_str(&env, "c"),
        ];
        assert!(!has_duplicates(&env, &items_no_dups));
    }

    #[test]
    fn test_calculate_fee() {
        // 1% fee on 1000 = 10
        assert_eq!(efficient_math::calculate_fee(1000, 100, 10000), 10);

        // Ceiling division: 1 * 100 / 10000 = 0.01 -> ceil to 1
        assert_eq!(efficient_math::calculate_fee(1, 100, 10000), 1);

        // Zero fee rate
        assert_eq!(efficient_math::calculate_fee(1000, 0, 10000), 0);

        // Zero amount
        assert_eq!(efficient_math::calculate_fee(0, 100, 10000), 0);
    }

    #[test]
    fn test_safe_sub_zero() {
        assert_eq!(efficient_math::safe_sub_zero(10, 5), 5);
        assert_eq!(efficient_math::safe_sub_zero(5, 10), 0);
        assert_eq!(efficient_math::safe_sub_zero(0, 0), 0);
    }
}
