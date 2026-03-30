#![cfg(test)]

use crate::strict_mode;

#[test]
fn test_is_enabled_reflects_feature_flag() {
    // In test builds without --features strict-mode, this should be false.
    // When built with --features strict-mode, this should be true.
    // This test validates that the function is callable and returns a bool.
    let _enabled = strict_mode::is_enabled();
}

#[test]
fn test_strict_assert_passes_on_true() {
    // Should not panic regardless of strict mode being enabled or not.
    strict_mode::strict_assert(true, "this should never fire");
}

#[test]
fn test_strict_assert_eq_passes_on_equal() {
    strict_mode::strict_assert_eq(42u32, 42u32, "values are equal");
    strict_mode::strict_assert_eq(0i128, 0i128, "zeros are equal");
}

#[test]
fn test_strict_assert_balance_sane_valid() {
    // Valid balances should never panic.
    strict_mode::strict_assert_balance_sane(100, 50, "test_valid");
    strict_mode::strict_assert_balance_sane(100, 100, "test_full");
    strict_mode::strict_assert_balance_sane(100, 0, "test_empty");
    strict_mode::strict_assert_balance_sane(0, 0, "test_zero");
}

#[test]
fn test_strict_assert_no_overflow_valid() {
    strict_mode::strict_assert_no_overflow(100, 200, "test_add");
    strict_mode::strict_assert_no_overflow(0, 0, "test_zero");
    strict_mode::strict_assert_no_overflow(i128::MAX - 1, 1, "test_boundary");
}

// The following tests verify strict mode behavior when the feature IS enabled.
// They are gated on the strict-mode feature flag so they only run when
// built with: cargo test --features strict-mode

#[cfg(feature = "strict-mode")]
mod strict_enabled {
    use crate::strict_mode;

    #[test]
    fn test_is_enabled_returns_true() {
        assert!(strict_mode::is_enabled());
    }

    #[test]
    #[should_panic(expected = "Strict mode assertion failed")]
    fn test_strict_assert_eq_panics_on_mismatch() {
        strict_mode::strict_assert_eq(1u32, 2u32, "mismatch");
    }

    #[test]
    #[should_panic(expected = "remaining")]
    fn test_strict_assert_balance_sane_panics_on_remaining_exceeds_total() {
        strict_mode::strict_assert_balance_sane(100, 200, "test");
    }

    #[test]
    #[should_panic(expected = "negative")]
    fn test_strict_assert_balance_sane_panics_on_negative_total() {
        strict_mode::strict_assert_balance_sane(-1, 0, "test");
    }

    #[test]
    #[should_panic(expected = "negative")]
    fn test_strict_assert_balance_sane_panics_on_negative_remaining() {
        strict_mode::strict_assert_balance_sane(100, -1, "test");
    }

    #[test]
    #[should_panic(expected = "overflow")]
    fn test_strict_assert_no_overflow_panics() {
        strict_mode::strict_assert_no_overflow(i128::MAX, 1, "test");
    }

    #[test]
    #[should_panic(expected = "test failure")]
    fn test_strict_assert_panics_on_false() {
        strict_mode::strict_assert(false, "test failure");
    }
}

// The following tests verify that strict mode is a no-op when disabled.
#[cfg(not(feature = "strict-mode"))]
mod strict_disabled {
    use crate::strict_mode;

    #[test]
    fn test_is_enabled_returns_false() {
        assert!(!strict_mode::is_enabled());
    }

    #[test]
    fn test_strict_assert_does_not_panic_on_false() {
        // When strict mode is disabled, false conditions should NOT panic.
        strict_mode::strict_assert(false, "should not fire");
    }

    #[test]
    fn test_strict_assert_eq_does_not_panic_on_mismatch() {
        strict_mode::strict_assert_eq(1u32, 2u32, "should not fire");
    }

    #[test]
    fn test_strict_assert_balance_sane_does_not_panic_on_invalid() {
        strict_mode::strict_assert_balance_sane(100, 200, "should not fire");
        strict_mode::strict_assert_balance_sane(-1, 0, "should not fire");
    }

    #[test]
    fn test_strict_assert_no_overflow_does_not_panic() {
        strict_mode::strict_assert_no_overflow(i128::MAX, 1, "should not fire");
    }
}
