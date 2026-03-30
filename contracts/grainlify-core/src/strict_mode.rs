//! # Strict Mode for Development and Staging Networks
//!
//! Provides additional invariant checks, assertions, and diagnostic events
//! that are enabled at compile time via the `strict-mode` Cargo feature flag.
//!
//! **Purpose**: Catch risky patterns (missing invariants, untested branches,
//! suspicious state transitions) early in dev/staging before they reach mainnet.
//!
//! **Gas considerations**: All strict-mode logic is compiled out when the feature
//! is disabled, so mainnet builds pay zero extra gas.
//!
//! ## Usage
//!
//! ```toml
//! # Build for testnet/staging (strict checks enabled):
//! cargo build --target wasm32-unknown-unknown --release --features strict-mode
//!
//! # Build for mainnet (strict checks compiled out):
//! cargo build --target wasm32-unknown-unknown --release
//! ```

use soroban_sdk::{Env, Symbol};

// ============================================================================
// Compile-time feature detection
// ============================================================================

/// Returns `true` when the contract was compiled with `strict-mode` enabled.
///
/// This is a zero-cost check: the compiler resolves it at build time.
#[inline(always)]
pub const fn is_enabled() -> bool {
    cfg!(feature = "strict-mode")
}

// ============================================================================
// Strict assertions (compiled out in production)
// ============================================================================

/// Panics with `message` when `condition` is false **and** strict mode is enabled.
///
/// In production builds this is a no-op and costs zero gas.
#[inline(always)]
pub fn strict_assert(condition: bool, message: &str) {
    #[cfg(feature = "strict-mode")]
    {
        if !condition {
            panic!("{}", message);
        }
    }
    #[cfg(not(feature = "strict-mode"))]
    {
        let _ = condition;
        let _ = message;
    }
}

/// Panics with a formatted message when `condition` is false and strict mode is
/// enabled. Use for invariant checks that include runtime context.
///
/// In production builds this is a no-op and costs zero gas.
#[inline(always)]
pub fn strict_assert_eq<T: PartialEq + core::fmt::Debug>(left: T, right: T, context: &str) {
    #[cfg(feature = "strict-mode")]
    {
        if left != right {
            panic!(
                "Strict mode assertion failed ({}): {:?} != {:?}",
                context, left, right
            );
        }
    }
    #[cfg(not(feature = "strict-mode"))]
    {
        let _ = left;
        let _ = right;
        let _ = context;
    }
}

// ============================================================================
// Strict diagnostic events (compiled out in production)
// ============================================================================

/// Emits a diagnostic event under the `("strict", <tag>)` topic pair.
///
/// Off-chain indexers on dev/staging networks can subscribe to the `"strict"`
/// topic to surface warnings without halting the contract.
///
/// In production builds this is a no-op.
#[inline(always)]
pub fn strict_emit(env: &Env, tag: Symbol, message: Symbol) {
    #[cfg(feature = "strict-mode")]
    {
        use soroban_sdk::symbol_short;
        env.events()
            .publish((symbol_short!("strict"), tag), message);
    }
    #[cfg(not(feature = "strict-mode"))]
    {
        let _ = env;
        let _ = tag;
        let _ = message;
    }
}

// ============================================================================
// Balance / financial invariants
// ============================================================================

/// Asserts that `remaining <= total` and both are non-negative.
///
/// Designed for escrow-style contracts where the remaining balance must never
/// exceed the total locked amount. Compiled out in production.
#[inline(always)]
pub fn strict_assert_balance_sane(total: i128, remaining: i128, context: &str) {
    #[cfg(feature = "strict-mode")]
    {
        if total < 0 {
            panic!(
                "Strict mode: total balance is negative ({}) in {}",
                total, context
            );
        }
        if remaining < 0 {
            panic!(
                "Strict mode: remaining balance is negative ({}) in {}",
                remaining, context
            );
        }
        if remaining > total {
            panic!(
                "Strict mode: remaining ({}) exceeds total ({}) in {}",
                remaining, total, context
            );
        }
    }
    #[cfg(not(feature = "strict-mode"))]
    {
        let _ = total;
        let _ = remaining;
        let _ = context;
    }
}

/// Asserts that an amount delta will not cause an overflow when added to `current`.
///
/// Compiled out in production (release profile already has `overflow-checks = true`,
/// but strict mode catches this with a clear diagnostic message).
#[inline(always)]
pub fn strict_assert_no_overflow(current: i128, delta: i128, context: &str) {
    #[cfg(feature = "strict-mode")]
    {
        if current.checked_add(delta).is_none() {
            panic!(
                "Strict mode: overflow detected ({} + {}) in {}",
                current, delta, context
            );
        }
    }
    #[cfg(not(feature = "strict-mode"))]
    {
        let _ = current;
        let _ = delta;
        let _ = context;
    }
}

// ============================================================================
// State transition guards
// ============================================================================

/// Emits a warning event when a state transition looks suspicious but isn't
/// necessarily invalid. For example, re-initializing an already-active program.
///
/// In production this is a no-op.
#[inline(always)]
pub fn strict_warn(env: &Env, warning: Symbol) {
    #[cfg(feature = "strict-mode")]
    {
        use soroban_sdk::symbol_short;
        env.events()
            .publish((symbol_short!("strict"), symbol_short!("warn")), warning);
    }
    #[cfg(not(feature = "strict-mode"))]
    {
        let _ = env;
        let _ = warning;
    }
}
