//! # Dispute Resolution Finality Tests
//!
//! This module validates the **finality guarantees** of the bounty escrow:
//!
//! - Resolved disputes cannot be reopened.
//! - Funds cannot move in a direction that violates the resolution outcome.
//! - Role separation is enforced on `escalate_dispute` and `resolve_dispute`.
//! - Duplicate resolve attempts are always rejected with [`EscrowError::AlreadyResolved`].
//!
//! ## Security Assumptions Validated
//!
//! | Assumption | Test |
//! |---|---|
//! | Only arbiter resolves | `test_non_arbiter_cannot_resolve_*` |
//! | Only funder escalates | `test_non_funder_cannot_escalate_*` |
//! | Resolution is single-write | `test_duplicate_resolve_*` |
//! | Post-resolution fund movement locked | `test_funds_locked_after_resolve_*` |
//! | Hunter cannot claim on ForFunder outcome | `test_hunter_cannot_claim_resolved_for_funder` |
//! | Funder cannot refund on ForHunter outcome | `test_funder_cannot_refund_resolved_for_hunter` |

#[cfg(test)]
mod tests {
    use crate::{AccountId, Balance, Escrow, EscrowError, EscrowState, Resolution, Timestamp};

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    const FUNDER: AccountId = 1;
    const HUNTER: AccountId = 2;
    const ARBITER: AccountId = 3;
    const STRANGER: AccountId = 99;
    const AMOUNT: Balance = 1_000_000;
    const FUTURE: Timestamp = u64::MAX / 2; // far future expiry
    const PAST: Timestamp = 1; // already expired

    /// Build an escrow that has been funded and accepted (ready to dispute).
    fn accepted_escrow() -> Escrow {
        let mut e = Escrow::new(FUNDER, HUNTER, ARBITER, AMOUNT, FUTURE).unwrap();
        e.fund_at(FUNDER, 0).unwrap();
        e.accept_at(HUNTER, 0).unwrap();
        e
    }

    /// Build an escrow that is in `Disputed` state.
    fn disputed_escrow() -> Escrow {
        let mut e = accepted_escrow();
        e.escalate_dispute_at(FUNDER, 0).unwrap();
        e
    }

    /// Build an escrow resolved for the hunter.
    fn resolved_for_hunter() -> Escrow {
        let mut e = disputed_escrow();
        e.resolve_dispute_at(ARBITER, Resolution::ForHunter, 1)
            .unwrap();
        e
    }

    /// Build an escrow resolved for the funder.
    fn resolved_for_funder() -> Escrow {
        let mut e = disputed_escrow();
        e.resolve_dispute_at(ARBITER, Resolution::ForFunder, 1)
            .unwrap();
        e
    }

    // =========================================================================
    // 1. Role separation: escalate_dispute
    // =========================================================================

    #[test]
    fn test_only_funder_can_escalate() {
        let mut e = accepted_escrow();
        assert_eq!(
            e.escalate_dispute_at(HUNTER, 0),
            Err(EscrowError::Unauthorized),
            "hunter must not be able to self-escalate"
        );
        assert_eq!(
            e.escalate_dispute_at(ARBITER, 0),
            Err(EscrowError::Unauthorized),
            "arbiter must not pre-emptively open disputes"
        );
        assert_eq!(
            e.escalate_dispute_at(STRANGER, 0),
            Err(EscrowError::Unauthorized),
            "stranger must be rejected"
        );
        // Funder succeeds
        assert!(e.escalate_dispute_at(FUNDER, 0).is_ok());
        assert_eq!(e.state, EscrowState::Disputed);
    }

    #[test]
    fn test_cannot_escalate_from_funded_state() {
        let mut e = Escrow::new(FUNDER, HUNTER, ARBITER, AMOUNT, FUTURE).unwrap();
        e.fund_at(FUNDER, 0).unwrap();
        assert_eq!(
            e.escalate_dispute_at(FUNDER, 0),
            Err(EscrowError::InvalidStateTransition),
            "cannot escalate from Funded; hunter must accept first"
        );
    }

    #[test]
    fn test_cannot_escalate_from_created_state() {
        let mut e = Escrow::new(FUNDER, HUNTER, ARBITER, AMOUNT, FUTURE).unwrap();
        assert_eq!(
            e.escalate_dispute_at(FUNDER, 0),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    // =========================================================================
    // 2. Role separation: resolve_dispute
    // =========================================================================

    #[test]
    fn test_only_arbiter_can_resolve() {
        let mut e = disputed_escrow();
        assert_eq!(
            e.resolve_dispute_at(FUNDER, Resolution::ForFunder, 1),
            Err(EscrowError::Unauthorized),
            "funder must not self-resolve"
        );

        let mut e = disputed_escrow();
        assert_eq!(
            e.resolve_dispute_at(HUNTER, Resolution::ForHunter, 1),
            Err(EscrowError::Unauthorized),
            "hunter must not self-resolve"
        );

        let mut e = disputed_escrow();
        assert_eq!(
            e.resolve_dispute_at(STRANGER, Resolution::ForHunter, 1),
            Err(EscrowError::Unauthorized),
            "stranger must be rejected"
        );

        // Arbiter succeeds
        let mut e = disputed_escrow();
        assert!(e
            .resolve_dispute_at(ARBITER, Resolution::ForHunter, 1)
            .is_ok());
    }

    #[test]
    fn test_cannot_resolve_when_not_in_dispute() {
        // From Accepted state
        let mut e = accepted_escrow();
        assert_eq!(
            e.resolve_dispute_at(ARBITER, Resolution::ForHunter, 1),
            Err(EscrowError::NotInDispute)
        );
    }

    #[test]
    fn test_cannot_resolve_from_funded_state() {
        let mut e = Escrow::new(FUNDER, HUNTER, ARBITER, AMOUNT, FUTURE).unwrap();
        e.fund_at(FUNDER, 0).unwrap();
        assert_eq!(
            e.resolve_dispute_at(ARBITER, Resolution::ForHunter, 1),
            Err(EscrowError::NotInDispute)
        );
    }

    // =========================================================================
    // 3. Dispute resolution finality — cannot reopen after resolution
    // =========================================================================

    #[test]
    fn test_duplicate_resolve_for_hunter_returns_already_resolved() {
        let mut e = resolved_for_hunter();
        // Second resolve attempt with the same outcome
        assert_eq!(
            e.resolve_dispute_at(ARBITER, Resolution::ForHunter, 2),
            Err(EscrowError::AlreadyResolved),
            "duplicate same-outcome resolve must be rejected"
        );
    }

    #[test]
    fn test_duplicate_resolve_different_outcome_returns_already_resolved() {
        let mut e = resolved_for_hunter();
        // Attempt to flip the outcome to ForFunder
        assert_eq!(
            e.resolve_dispute_at(ARBITER, Resolution::ForFunder, 2),
            Err(EscrowError::AlreadyResolved),
            "outcome flip must be rejected after finality"
        );
        // State must be unchanged
        assert_eq!(e.state, EscrowState::ResolvedForHunter);
        assert_eq!(e.resolution, Some(Resolution::ForHunter));
    }

    #[test]
    fn test_cannot_escalate_after_resolution() {
        let mut e = resolved_for_hunter();
        assert_eq!(
            e.escalate_dispute_at(FUNDER, 10),
            Err(EscrowError::AlreadyResolved),
            "cannot re-open a resolved dispute"
        );

        let mut e = resolved_for_funder();
        assert_eq!(
            e.escalate_dispute_at(FUNDER, 10),
            Err(EscrowError::AlreadyResolved),
            "cannot re-open a resolved dispute (for funder)"
        );
    }

    #[test]
    fn test_resolve_after_funds_released_returns_already_resolved() {
        let mut e = resolved_for_hunter();
        e.release_funds(HUNTER).unwrap();
        assert_eq!(e.state, EscrowState::Released);
        // All further resolve attempts must fail
        assert_eq!(
            e.resolve_dispute_at(ARBITER, Resolution::ForHunter, 5),
            Err(EscrowError::AlreadyResolved)
        );
        assert_eq!(
            e.resolve_dispute_at(ARBITER, Resolution::ForFunder, 5),
            Err(EscrowError::AlreadyResolved)
        );
    }

    #[test]
    fn test_resolve_after_refund_to_funder_returns_already_resolved() {
        let mut e = resolved_for_funder();
        e.refund_funder_at(FUNDER, 100).unwrap();
        assert_eq!(e.state, EscrowState::Refunded);
        assert_eq!(
            e.resolve_dispute_at(ARBITER, Resolution::ForFunder, 5),
            Err(EscrowError::AlreadyResolved)
        );
        assert_eq!(
            e.resolve_dispute_at(ARBITER, Resolution::ForHunter, 5),
            Err(EscrowError::AlreadyResolved)
        );
    }

    // =========================================================================
    // 4. Post-resolution fund movement locks
    // =========================================================================

    #[test]
    fn test_hunter_can_claim_after_resolved_for_hunter() {
        let mut e = resolved_for_hunter();
        let payout = e.release_funds(HUNTER).unwrap();
        assert_eq!(payout, AMOUNT, "hunter should receive full bounty amount");
        assert_eq!(e.state, EscrowState::Released);
    }

    #[test]
    fn test_hunter_cannot_claim_resolved_for_funder() {
        let mut e = resolved_for_funder();
        assert_eq!(
            e.release_funds(HUNTER),
            Err(EscrowError::InvalidStateTransition),
            "hunter must not claim funds when arbiter ruled for funder"
        );
        // State must remain unchanged
        assert_eq!(e.state, EscrowState::ResolvedForFunder);
    }

    #[test]
    fn test_funder_cannot_refund_resolved_for_hunter() {
        let mut e = resolved_for_hunter();
        // Funder attempts to grab funds after losing the dispute
        assert_eq!(
            e.refund_funder_at(FUNDER, 100),
            Err(EscrowError::InvalidStateTransition),
            "funder must not reclaim funds when arbiter ruled for hunter"
        );
        assert_eq!(e.state, EscrowState::ResolvedForHunter);
    }

    #[test]
    fn test_funder_can_refund_after_resolved_for_funder() {
        let mut e = resolved_for_funder();
        let refund = e.refund_funder_at(FUNDER, 100).unwrap();
        assert_eq!(refund, AMOUNT);
        assert_eq!(e.state, EscrowState::Refunded);
    }

    #[test]
    fn test_stranger_cannot_trigger_release_after_resolution() {
        let mut e = resolved_for_hunter();
        assert_eq!(
            e.release_funds(STRANGER),
            Err(EscrowError::Unauthorized),
            "stranger must not trigger release"
        );
    }

    #[test]
    fn test_arbiter_can_trigger_release_for_hunter() {
        // Arbiter may operationally push the release on behalf of the hunter.
        let mut e = resolved_for_hunter();
        assert!(e.release_funds(ARBITER).is_ok());
        assert_eq!(e.state, EscrowState::Released);
    }

    #[test]
    fn test_stranger_cannot_trigger_refund_after_resolution() {
        let mut e = resolved_for_funder();
        assert_eq!(
            e.refund_funder_at(STRANGER, 100),
            Err(EscrowError::Unauthorized)
        );
    }

    // =========================================================================
    // 5. Double-spend guards on terminal states
    // =========================================================================

    #[test]
    fn test_cannot_release_twice() {
        let mut e = resolved_for_hunter();
        e.release_funds(HUNTER).unwrap();
        // Attempt a second release
        assert_eq!(
            e.release_funds(HUNTER),
            Err(EscrowError::InvalidStateTransition),
            "funds must not be released twice"
        );
        assert_eq!(
            e.release_funds(ARBITER),
            Err(EscrowError::InvalidStateTransition),
            "arbiter double-release must also fail"
        );
    }

    #[test]
    fn test_cannot_refund_twice() {
        let mut e = resolved_for_funder();
        e.refund_funder_at(FUNDER, 100).unwrap();
        assert_eq!(
            e.refund_funder_at(FUNDER, 200),
            Err(EscrowError::InvalidStateTransition),
            "funder must not be refunded twice"
        );
    }

    // =========================================================================
    // 6. Resolution metadata integrity
    // =========================================================================

    #[test]
    fn test_resolution_field_set_correctly_for_hunter() {
        let e = resolved_for_hunter();
        assert_eq!(e.resolution, Some(Resolution::ForHunter));
        assert!(e.resolved_at.is_some(), "resolved_at timestamp must be set");
    }

    #[test]
    fn test_resolution_field_set_correctly_for_funder() {
        let e = resolved_for_funder();
        assert_eq!(e.resolution, Some(Resolution::ForFunder));
        assert!(e.resolved_at.is_some(), "resolved_at timestamp must be set");
    }

    #[test]
    fn test_resolution_field_none_before_resolution() {
        let e = disputed_escrow();
        assert_eq!(e.resolution, None);
        assert!(e.resolved_at.is_none());
    }

    #[test]
    fn test_disputed_at_timestamp_recorded() {
        let mut e = accepted_escrow();
        e.escalate_dispute_at(FUNDER, 42).unwrap();
        assert_eq!(e.disputed_at, Some(42));
    }

    #[test]
    fn test_resolved_at_timestamp_recorded() {
        let mut e = disputed_escrow();
        e.resolve_dispute_at(ARBITER, Resolution::ForHunter, 99)
            .unwrap();
        assert_eq!(e.resolved_at, Some(99));
    }

    // =========================================================================
    // 7. State machine integrity — invalid path combinations
    // =========================================================================

    #[test]
    fn test_cannot_fund_after_resolution() {
        let mut e = resolved_for_hunter();
        assert_eq!(
            e.fund_at(FUNDER, 0),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn test_cannot_accept_after_resolution() {
        let mut e = resolved_for_hunter();
        assert_eq!(
            e.accept_at(HUNTER, 0),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn test_cannot_accept_after_dispute() {
        let mut e = disputed_escrow();
        assert_eq!(
            e.accept_at(HUNTER, 0),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn test_cannot_fund_after_dispute() {
        let mut e = disputed_escrow();
        assert_eq!(
            e.fund_at(FUNDER, 0),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    // =========================================================================
    // 8. is_resolved and is_terminal helpers
    // =========================================================================

    #[test]
    fn test_is_resolved_states() {
        assert!(!EscrowState::Created.is_resolved());
        assert!(!EscrowState::Funded.is_resolved());
        assert!(!EscrowState::Accepted.is_resolved());
        assert!(!EscrowState::Disputed.is_resolved());
        assert!(EscrowState::ResolvedForHunter.is_resolved());
        assert!(EscrowState::ResolvedForFunder.is_resolved());
        assert!(EscrowState::Released.is_resolved());
        assert!(EscrowState::Refunded.is_resolved());
    }

    #[test]
    fn test_is_terminal_states() {
        assert!(!EscrowState::Created.is_terminal());
        assert!(!EscrowState::ResolvedForHunter.is_terminal());
        assert!(!EscrowState::ResolvedForFunder.is_terminal());
        assert!(EscrowState::Released.is_terminal());
        assert!(EscrowState::Refunded.is_terminal());
    }

    // =========================================================================
    // 9. Zero-amount guard
    // =========================================================================

    #[test]
    fn test_zero_amount_rejected_at_construction() {
        assert_eq!(
            Escrow::new(FUNDER, HUNTER, ARBITER, 0, FUTURE),
            Err(EscrowError::InvalidAmount)
        );
    }
}
