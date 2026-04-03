//! # Bounty Escrow Contract
//!
//! A secure escrow contract for managing bounty payouts with dispute resolution finality.
//!
//! ## Finality Rules
//!
//! Once a dispute reaches **final resolution**, the escrow enters an immutable terminal state:
//!
//! 1. **No Reopening**: A resolved dispute cannot be escalated or re-resolved under any
//!    circumstances. Calling [`resolve_dispute`] or [`escalate_dispute`] on a resolved escrow
//!    returns [`EscrowError::AlreadyResolved`].
//!
//! 2. **Funds Locked to Outcome**: After resolution, only [`release_funds`] (for
//!    `ResolvedForHunter`) or [`refund_funder`] (for `ResolvedForFunder`) succeed.
//!    All other fund-movement calls return [`EscrowError::InvalidStateTransition`].
//!
//! 3. **Role Separation**: Only designated arbiters may call [`resolve_dispute`].
//!    Only the original funder may call [`escalate_dispute`]. Violations return
//!    [`EscrowError::Unauthorized`].
//!
//! 4. **Expiration Guards**: An escrow that has expired cannot be funded or accepted;
//!    it can only be refunded to the funder or escalated to dispute before expiry.
//!
//! ## State Machine
//!
//! ```text
//!  ┌─────────┐  fund()   ┌────────┐  accept()  ┌──────────┐
//!  │ Created │ ────────► │ Funded │ ──────────► │ Accepted │
//!  └─────────┘           └────────┘             └──────────┘
//!                            │                       │
//!                     expire │               dispute │ escalate_dispute()
//!                            ▼                       ▼
//!                       ┌─────────┐           ┌──────────┐
//!                       │ Expired │           │ Disputed │
//!                       └─────────┘           └──────────┘
//!                            │                       │ resolve_dispute()
//!                     refund │               ┌───────┴────────┐
//!                            ▼               ▼                ▼
//!                       ┌─────────┐  ┌────────────┐  ┌──────────────┐
//!                       │Refunded │  │ResolvedFor │  │ ResolvedFor  │
//!                       └─────────┘  │  Hunter    │  │   Funder     │
//!                                    └────────────┘  └──────────────┘
//!                                          │                 │
//!                               release_  │         refund_ │
//!                               funds()   ▼         funder()▼
//!                                    ┌──────────┐  ┌──────────────┐
//!                                    │ Released │  │   Refunded   │
//!                                    └──────────┘  └──────────────┘
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
#[path = "test_dispute_resolution.rs"]
mod test_dispute_resolution;

#[cfg(test)]
#[path = "test_expiration_and_dispute.rs"]
mod test_expiration_and_dispute;

/// Errors returned by the escrow contract.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EscrowError {
    /// The requested state transition is not valid from the current state.
    InvalidStateTransition,
    /// The caller does not have permission to perform this action.
    Unauthorized,
    /// The dispute has already been resolved and cannot be modified.
    AlreadyResolved,
    /// The escrow has expired and cannot proceed.
    Expired,
    /// The escrow has not yet expired; expiry-only actions cannot proceed.
    NotExpired,
    /// The provided amount is invalid (zero or overflow).
    InvalidAmount,
    /// The escrow is not in a disputed state.
    NotInDispute,
    /// Arithmetic overflow occurred.
    Overflow,
}

impl std::fmt::Display for EscrowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStateTransition => write!(f, "invalid state transition"),
            Self::Unauthorized => write!(f, "unauthorized caller"),
            Self::AlreadyResolved => write!(f, "dispute already resolved"),
            Self::Expired => write!(f, "escrow has expired"),
            Self::NotExpired => write!(f, "escrow has not expired"),
            Self::InvalidAmount => write!(f, "invalid amount"),
            Self::NotInDispute => write!(f, "escrow is not in dispute"),
            Self::Overflow => write!(f, "arithmetic overflow"),
        }
    }
}

/// Outcome of a resolved dispute.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Resolution {
    /// Funds are awarded to the bounty hunter.
    ForHunter,
    /// Funds are returned to the funder.
    ForFunder,
}

/// The lifecycle state of the escrow.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EscrowState {
    /// Escrow created but not yet funded.
    Created,
    /// Funder has deposited funds; awaiting hunter acceptance.
    Funded,
    /// Hunter has accepted; work is in progress.
    Accepted,
    /// Escrow has passed its expiry timestamp without completion.
    Expired,
    /// A dispute has been opened; awaiting arbiter resolution.
    Disputed,
    /// Arbiter has resolved in favour of the hunter; funds pending release.
    ResolvedForHunter,
    /// Arbiter has resolved in favour of the funder; refund pending.
    ResolvedForFunder,
    /// Funds have been released to the hunter (terminal state).
    Released,
    /// Funds have been refunded to the funder (terminal state).
    Refunded,
}

impl EscrowState {
    /// Returns `true` if this is a terminal state with no further transitions.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Released | Self::Refunded)
    }

    /// Returns `true` if the dispute has reached final resolution.
    pub fn is_resolved(&self) -> bool {
        matches!(
            self,
            Self::ResolvedForHunter | Self::ResolvedForFunder | Self::Released | Self::Refunded
        )
    }
}

/// Unique identifier for a participant.
pub type AccountId = u64;

/// Unix timestamp in seconds.
pub type Timestamp = u64;

/// Token amount.
pub type Balance = u128;

/// The escrow contract state.
#[derive(Debug)]
pub struct Escrow {
    /// Account that funded the bounty.
    pub funder: AccountId,
    /// Account eligible to claim the bounty.
    pub hunter: AccountId,
    /// Designated arbiter who may resolve disputes.
    ///
    /// # Security
    /// The arbiter is set at construction and is immutable. This prevents
    /// dispute-resolution capture by a malicious funder or hunter.
    pub arbiter: AccountId,
    /// Locked bounty amount.
    pub amount: Balance,
    /// Unix timestamp after which the escrow is considered expired.
    pub expiry: Timestamp,
    /// Current lifecycle state.
    pub state: EscrowState,
    /// Immutable record of the dispute resolution outcome, set once.
    pub resolution: Option<Resolution>,
    /// Timestamp at which the dispute was opened, if any.
    pub disputed_at: Option<Timestamp>,
    /// Timestamp at which the dispute was resolved, if any.
    pub resolved_at: Option<Timestamp>,
}

impl Escrow {
    /// Creates a new escrow in [`EscrowState::Created`].
    ///
    /// # Arguments
    /// * `funder`  – account depositing funds.
    /// * `hunter`  – account eligible to receive the bounty.
    /// * `arbiter` – account authorised to resolve disputes.
    /// * `amount`  – locked token amount (must be > 0).
    /// * `expiry`  – unix timestamp after which no new work may begin.
    ///
    /// # Errors
    /// Returns [`EscrowError::InvalidAmount`] if `amount` is zero.
    pub fn new(
        funder: AccountId,
        hunter: AccountId,
        arbiter: AccountId,
        amount: Balance,
        expiry: Timestamp,
    ) -> Result<Self, EscrowError> {
        if amount == 0 {
            return Err(EscrowError::InvalidAmount);
        }
        Ok(Self {
            funder,
            hunter,
            arbiter,
            amount,
            expiry,
            state: EscrowState::Created,
            resolution: None,
            disputed_at: None,
            resolved_at: None,
        })
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    fn now() -> Timestamp {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn is_expired_at(&self, now: Timestamp) -> bool {
        now >= self.expiry
    }

    // -------------------------------------------------------------------------
    // Public entrypoints
    // -------------------------------------------------------------------------

    /// Transitions the escrow from `Created` → `Funded`.
    ///
    /// Only the funder may call this.
    ///
    /// # Errors
    /// - [`EscrowError::Unauthorized`] if caller is not the funder.
    /// - [`EscrowError::InvalidStateTransition`] if state is not `Created`.
    /// - [`EscrowError::Expired`] if expiry has already passed.
    pub fn fund(&mut self, caller: AccountId) -> Result<(), EscrowError> {
        self.fund_at(caller, Self::now())
    }

    pub fn fund_at(&mut self, caller: AccountId, now: Timestamp) -> Result<(), EscrowError> {
        if caller != self.funder {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != EscrowState::Created {
            return Err(EscrowError::InvalidStateTransition);
        }
        if self.is_expired_at(now) {
            return Err(EscrowError::Expired);
        }
        self.state = EscrowState::Funded;
        Ok(())
    }

    /// Transitions the escrow from `Funded` → `Accepted`.
    ///
    /// Only the hunter may call this.
    ///
    /// # Errors
    /// - [`EscrowError::Unauthorized`] if caller is not the hunter.
    /// - [`EscrowError::InvalidStateTransition`] if state is not `Funded`.
    /// - [`EscrowError::Expired`] if expiry has passed.
    pub fn accept(&mut self, caller: AccountId) -> Result<(), EscrowError> {
        self.accept_at(caller, Self::now())
    }

    pub fn accept_at(&mut self, caller: AccountId, now: Timestamp) -> Result<(), EscrowError> {
        if caller != self.hunter {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != EscrowState::Funded {
            return Err(EscrowError::InvalidStateTransition);
        }
        if self.is_expired_at(now) {
            return Err(EscrowError::Expired);
        }
        self.state = EscrowState::Accepted;
        Ok(())
    }

    /// Opens a dispute, transitioning `Accepted` → `Disputed`.
    ///
    /// Only the funder may escalate a dispute.
    ///
    /// # Security
    /// Role separation: the hunter cannot self-escalate to force arbitration.
    /// The arbiter cannot pre-emptively open disputes.
    ///
    /// # Errors
    /// - [`EscrowError::Unauthorized`] if caller is not the funder.
    /// - [`EscrowError::InvalidStateTransition`] if state is not `Accepted`.
    /// - [`EscrowError::AlreadyResolved`] if dispute was already resolved.
    pub fn escalate_dispute(&mut self, caller: AccountId) -> Result<(), EscrowError> {
        self.escalate_dispute_at(caller, Self::now())
    }

    pub fn escalate_dispute_at(
        &mut self,
        caller: AccountId,
        now: Timestamp,
    ) -> Result<(), EscrowError> {
        if caller != self.funder {
            return Err(EscrowError::Unauthorized);
        }
        if self.state.is_resolved() {
            return Err(EscrowError::AlreadyResolved);
        }
        if self.state != EscrowState::Accepted {
            return Err(EscrowError::InvalidStateTransition);
        }
        self.state = EscrowState::Disputed;
        self.disputed_at = Some(now);
        Ok(())
    }

    /// Resolves a dispute with a final, immutable outcome.
    ///
    /// Only the arbiter may call this entrypoint.
    ///
    /// # Finality Guarantee
    /// This method may be called **at most once**. After resolution the
    /// [`EscrowState`] transitions to either [`EscrowState::ResolvedForHunter`]
    /// or [`EscrowState::ResolvedForFunder`] and all subsequent calls return
    /// [`EscrowError::AlreadyResolved`].
    ///
    /// # Security
    /// - Only the arbiter (set at construction) may resolve.
    /// - The funder and hunter cannot influence or override the resolution.
    ///
    /// # Errors
    /// - [`EscrowError::Unauthorized`] if caller is not the arbiter.
    /// - [`EscrowError::AlreadyResolved`] if dispute has already been resolved.
    /// - [`EscrowError::NotInDispute`] if state is not `Disputed`.
    pub fn resolve_dispute(
        &mut self,
        caller: AccountId,
        resolution: Resolution,
    ) -> Result<(), EscrowError> {
        self.resolve_dispute_at(caller, resolution, Self::now())
    }

    pub fn resolve_dispute_at(
        &mut self,
        caller: AccountId,
        resolution: Resolution,
        now: Timestamp,
    ) -> Result<(), EscrowError> {
        if caller != self.arbiter {
            return Err(EscrowError::Unauthorized);
        }
        // Finality check: reject any attempt to re-resolve.
        if self.state.is_resolved() {
            return Err(EscrowError::AlreadyResolved);
        }
        if self.state != EscrowState::Disputed {
            return Err(EscrowError::NotInDispute);
        }
        self.resolution = Some(resolution);
        self.resolved_at = Some(now);
        self.state = match resolution {
            Resolution::ForHunter => EscrowState::ResolvedForHunter,
            Resolution::ForFunder => EscrowState::ResolvedForFunder,
        };
        Ok(())
    }

    /// Releases funds to the hunter after a `ResolvedForHunter` outcome.
    ///
    /// # Errors
    /// - [`EscrowError::InvalidStateTransition`] if state is not `ResolvedForHunter`.
    pub fn release_funds(&mut self, caller: AccountId) -> Result<Balance, EscrowError> {
        // Any authorised party may trigger the release; we allow the hunter to self-claim.
        if caller != self.hunter && caller != self.arbiter {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != EscrowState::ResolvedForHunter {
            return Err(EscrowError::InvalidStateTransition);
        }
        self.state = EscrowState::Released;
        Ok(self.amount)
    }

    /// Refunds the funder after a `ResolvedForFunder` outcome **or** after expiry.
    ///
    /// # Errors
    /// - [`EscrowError::InvalidStateTransition`] if neither condition is met.
    /// - [`EscrowError::Unauthorized`] if caller is not the funder.
    pub fn refund_funder(&mut self, caller: AccountId) -> Result<Balance, EscrowError> {
        self.refund_funder_at(caller, Self::now())
    }

    pub fn refund_funder_at(
        &mut self,
        caller: AccountId,
        now: Timestamp,
    ) -> Result<Balance, EscrowError> {
        if caller != self.funder {
            return Err(EscrowError::Unauthorized);
        }
        let allowed = self.state == EscrowState::ResolvedForFunder
            || (self.state == EscrowState::Funded && self.is_expired_at(now))
            || (self.state == EscrowState::Accepted && self.is_expired_at(now));
        if !allowed {
            return Err(EscrowError::InvalidStateTransition);
        }
        self.state = EscrowState::Refunded;
        Ok(self.amount)
    }
}
