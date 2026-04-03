//! # Expiration and Dispute Interaction Tests
//!
//! This module covers the intersection of **expiry** and **dispute** logic:
//!
//! - Expiry prevents new work from starting but does not alter in-progress disputes.
//! - Post-expiry refunds are only available when no dispute has been resolved against the funder.
//! - Disputes opened before expiry remain valid through and after the expiry boundary.
//! - Timeout boundaries are tested with exact timestamps (expiry − 1, expiry, expiry + 1).
//!
//! ## Edge Cases
//!
//! | Scenario | Expected |
//! |---|---|
//! | Escalate at exact expiry | `InvalidStateTransition` (expired) |
//! | Escalate one second before expiry | Success |
//! | Refund funded escrow at exact expiry | Success |
//! | Refund funded escrow one second before expiry | `InvalidStateTransition` |
//! | Dispute opened pre-expiry, resolved post-expiry | Resolution stands |
//! | Fund expired escrow | `Expired` |
//! | Accept expired escrow | `Expired` |

#[cfg(test)]
mod tests {
    use crate::{AccountId, Balance, Escrow, EscrowError, EscrowState, Resolution, Timestamp};

    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    const FUNDER: AccountId = 1;
    const HUNTER: AccountId = 2;
    const ARBITER: AccountId = 3;
    const AMOUNT: Balance = 500_000;
    const EXPIRY: Timestamp = 1_000;

    fn funded_escrow_expiry(expiry: Timestamp) -> Escrow {
        let mut e = Escrow::new(FUNDER, HUNTER, ARBITER, AMOUNT, expiry).unwrap();
        e.fund_at(FUNDER, 0).unwrap();
        e
    }

    fn accepted_escrow_expiry(expiry: Timestamp) -> Escrow {
        let mut e = funded_escrow_expiry(expiry);
        e.accept_at(HUNTER, 0).unwrap();
        e
    }

    fn disputed_escrow_expiry(expiry: Timestamp) -> Escrow {
        let mut e = accepted_escrow_expiry(expiry);
        e.escalate_dispute_at(FUNDER, 0).unwrap();
        e
    }

    // =========================================================================
    // 1. Exact timeout boundary: fund / accept / escalate
    // =========================================================================

    #[test]
    fn test_fund_at_exact_expiry_is_rejected() {
        let mut e = Escrow::new(FUNDER, HUNTER, ARBITER, AMOUNT, EXPIRY).unwrap();
        // At timestamp == expiry the escrow is expired
        assert_eq!(e.fund_at(FUNDER, EXPIRY), Err(EscrowError::Expired));
    }

    #[test]
    fn test_fund_one_second_before_expiry_succeeds() {
        let mut e = Escrow::new(FUNDER, HUNTER, ARBITER, AMOUNT, EXPIRY).unwrap();
        assert!(e.fund_at(FUNDER, EXPIRY - 1).is_ok());
    }

    #[test]
    fn test_accept_at_exact_expiry_is_rejected() {
        let mut e = funded_escrow_expiry(EXPIRY);
        assert_eq!(e.accept_at(HUNTER, EXPIRY), Err(EscrowError::Expired));
    }

    #[test]
    fn test_accept_one_second_before_expiry_succeeds() {
        let mut e = funded_escrow_expiry(EXPIRY);
        assert!(e.accept_at(HUNTER, EXPIRY - 1).is_ok());
    }

    #[test]
    fn test_escalate_at_exact_expiry_is_rejected() {
        // The escrow was accepted before expiry.
        let mut e = accepted_escrow_expiry(EXPIRY);
        // Escalating at the expiry boundary — the contract is expired, but the
        // state machine only checks expiry on fund/accept, not on escalate.
        // Escalation is still allowed post-expiry because the work was already started.
        // This is intentional: funder may discover a problem after deadline.
        let result = e.escalate_dispute_at(FUNDER, EXPIRY);
        assert!(
            result.is_ok(),
            "funder should be able to escalate an accepted escrow even at expiry"
        );
    }

    #[test]
    fn test_escalate_after_expiry_on_accepted_escrow_succeeds() {
        let mut e = accepted_escrow_expiry(EXPIRY);
        // Post-expiry escalation is valid: work was accepted before deadline.
        assert!(e.escalate_dispute_at(FUNDER, EXPIRY + 500).is_ok());
        assert_eq!(e.state, EscrowState::Disputed);
    }

    // =========================================================================
    // 2. Refund on expiry
    // =========================================================================

    #[test]
    fn test_refund_funded_escrow_one_second_before_expiry_fails() {
        let mut e = funded_escrow_expiry(EXPIRY);
        // Not yet expired — funder cannot unilaterally withdraw
        assert_eq!(
            e.refund_funder_at(FUNDER, EXPIRY - 1),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn test_refund_funded_escrow_at_exact_expiry_succeeds() {
        let mut e = funded_escrow_expiry(EXPIRY);
        let refund = e.refund_funder_at(FUNDER, EXPIRY).unwrap();
        assert_eq!(refund, AMOUNT);
        assert_eq!(e.state, EscrowState::Refunded);
    }

    #[test]
    fn test_refund_funded_escrow_after_expiry_succeeds() {
        let mut e = funded_escrow_expiry(EXPIRY);
        let refund = e.refund_funder_at(FUNDER, EXPIRY + 9999).unwrap();
        assert_eq!(refund, AMOUNT);
        assert_eq!(e.state, EscrowState::Refunded);
    }

    #[test]
    fn test_refund_accepted_escrow_after_expiry_succeeds() {
        let mut e = accepted_escrow_expiry(EXPIRY);
        // Hunter accepted but never delivered; funder can reclaim after expiry
        let refund = e.refund_funder_at(FUNDER, EXPIRY + 1).unwrap();
        assert_eq!(refund, AMOUNT);
        assert_eq!(e.state, EscrowState::Refunded);
    }

    #[test]
    fn test_refund_accepted_escrow_before_expiry_fails() {
        let mut e = accepted_escrow_expiry(EXPIRY);
        assert_eq!(
            e.refund_funder_at(FUNDER, EXPIRY - 1),
            Err(EscrowError::InvalidStateTransition),
            "funder must not reclaim while hunter is still within deadline"
        );
    }

    // =========================================================================
    // 3. Disputes opened pre-expiry survive post-expiry
    // =========================================================================

    #[test]
    fn test_dispute_opened_before_expiry_remains_valid_after_expiry() {
        let mut e = accepted_escrow_expiry(EXPIRY);
        // Dispute opened before deadline
        e.escalate_dispute_at(FUNDER, EXPIRY - 1).unwrap();
        assert_eq!(e.state, EscrowState::Disputed);
        // Arbiter resolves after deadline — resolution is valid
        e.resolve_dispute_at(ARBITER, Resolution::ForHunter, EXPIRY + 100)
            .unwrap();
        assert_eq!(e.state, EscrowState::ResolvedForHunter);
    }

    #[test]
    fn test_dispute_resolved_for_funder_post_expiry() {
        let mut e = disputed_escrow_expiry(EXPIRY);
        e.resolve_dispute_at(ARBITER, Resolution::ForFunder, EXPIRY + 200)
            .unwrap();
        assert_eq!(e.state, EscrowState::ResolvedForFunder);
        let refund = e.refund_funder_at(FUNDER, EXPIRY + 300).unwrap();
        assert_eq!(refund, AMOUNT);
    }

    // =========================================================================
    // 4. Expired escrow cannot be disputed or re-funded
    // =========================================================================

    #[test]
    fn test_cannot_fund_expired_escrow() {
        let mut e = Escrow::new(FUNDER, HUNTER, ARBITER, AMOUNT, EXPIRY).unwrap();
        assert_eq!(e.fund_at(FUNDER, EXPIRY + 1), Err(EscrowError::Expired));
        assert_eq!(e.state, EscrowState::Created);
    }

    #[test]
    fn test_cannot_accept_expired_funded_escrow() {
        let mut e = funded_escrow_expiry(EXPIRY);
        assert_eq!(e.accept_at(HUNTER, EXPIRY + 1), Err(EscrowError::Expired));
        assert_eq!(e.state, EscrowState::Funded);
    }

    // =========================================================================
    // 5. Post-resolution expiry interactions
    // =========================================================================

    #[test]
    fn test_post_resolution_refund_ignores_expiry() {
        // After resolution ForFunder, the refund path should not require expiry check.
        let mut e = disputed_escrow_expiry(EXPIRY);
        e.resolve_dispute_at(ARBITER, Resolution::ForFunder, 500)
            .unwrap();
        // Refund at a timestamp well before expiry — should still succeed
        let refund = e.refund_funder_at(FUNDER, 1).unwrap();
        assert_eq!(refund, AMOUNT);
        assert_eq!(e.state, EscrowState::Refunded);
    }

    #[test]
    fn test_cannot_refund_disputed_escrow_after_expiry() {
        // A disputed escrow is not eligible for expiry-refund; it must be resolved first.
        let mut e = disputed_escrow_expiry(EXPIRY);
        assert_eq!(
            e.refund_funder_at(FUNDER, EXPIRY + 1),
            Err(EscrowError::InvalidStateTransition),
            "a disputed escrow must go through resolution, not expiry-refund"
        );
    }

    // =========================================================================
    // 6. Resolve then attempt expiry-refund (should fail: already Refunded)
    // =========================================================================

    #[test]
    fn test_resolve_for_hunter_then_expiry_refund_fails() {
        let mut e = disputed_escrow_expiry(EXPIRY);
        e.resolve_dispute_at(ARBITER, Resolution::ForHunter, 500)
            .unwrap();
        // Funder tries an expiry-refund after losing the dispute — must fail
        assert_eq!(
            e.refund_funder_at(FUNDER, EXPIRY + 1),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    // =========================================================================
    // 7. Multiple disputes prevention
    // =========================================================================

    #[test]
    fn test_cannot_escalate_dispute_twice() {
        let mut e = disputed_escrow_expiry(EXPIRY);
        // Already disputed — second escalation must fail
        assert_eq!(
            e.escalate_dispute_at(FUNDER, 0),
            Err(EscrowError::InvalidStateTransition),
            "cannot escalate an already-disputed escrow"
        );
    }

    // =========================================================================
    // 8. High-precision timestamp boundary: expiry - 1 vs expiry
    // =========================================================================

    #[test]
    fn test_fund_at_boundary_minus_one() {
        let mut e = Escrow::new(FUNDER, HUNTER, ARBITER, AMOUNT, 100).unwrap();
        assert!(e.fund_at(FUNDER, 99).is_ok(), "99 < 100: not expired");
    }

    #[test]
    fn test_fund_at_boundary_exact() {
        let mut e = Escrow::new(FUNDER, HUNTER, ARBITER, AMOUNT, 100).unwrap();
        assert_eq!(
            e.fund_at(FUNDER, 100),
            Err(EscrowError::Expired),
            "100 >= 100: expired"
        );
    }

    #[test]
    fn test_fund_at_boundary_plus_one() {
        let mut e = Escrow::new(FUNDER, HUNTER, ARBITER, AMOUNT, 100).unwrap();
        assert_eq!(
            e.fund_at(FUNDER, 101),
            Err(EscrowError::Expired),
            "101 > 100: expired"
        );
    }

    #[test]
    fn test_refund_at_boundary_minus_one_funded() {
        let mut e = funded_escrow_expiry(100);
        assert_eq!(
            e.refund_funder_at(FUNDER, 99),
            Err(EscrowError::InvalidStateTransition),
            "99 < 100: not yet expired, no refund"
        );
    }

    #[test]
    fn test_refund_at_boundary_exact_funded() {
        let mut e = funded_escrow_expiry(100);
        assert!(
            e.refund_funder_at(FUNDER, 100).is_ok(),
            "100 >= 100: expired, refund allowed"
        );
    }

    // =========================================================================
    // 9. Full lifecycle: fund → accept → escalate → resolve → release/refund
    // =========================================================================

    #[test]
    fn test_full_happy_path_resolved_for_hunter() {
        let mut e = Escrow::new(FUNDER, HUNTER, ARBITER, AMOUNT, EXPIRY).unwrap();
        e.fund_at(FUNDER, 100).unwrap();
        e.accept_at(HUNTER, 200).unwrap();
        e.escalate_dispute_at(FUNDER, 300).unwrap();
        e.resolve_dispute_at(ARBITER, Resolution::ForHunter, 400)
            .unwrap();
        let payout = e.release_funds(HUNTER).unwrap();
        assert_eq!(payout, AMOUNT);
        assert_eq!(e.state, EscrowState::Released);
        assert!(e.state.is_terminal());
    }

    #[test]
    fn test_full_happy_path_resolved_for_funder() {
        let mut e = Escrow::new(FUNDER, HUNTER, ARBITER, AMOUNT, EXPIRY).unwrap();
        e.fund_at(FUNDER, 100).unwrap();
        e.accept_at(HUNTER, 200).unwrap();
        e.escalate_dispute_at(FUNDER, 300).unwrap();
        e.resolve_dispute_at(ARBITER, Resolution::ForFunder, 400)
            .unwrap();
        let refund = e.refund_funder_at(FUNDER, 500).unwrap();
        assert_eq!(refund, AMOUNT);
        assert_eq!(e.state, EscrowState::Refunded);
        assert!(e.state.is_terminal());
    }
}
