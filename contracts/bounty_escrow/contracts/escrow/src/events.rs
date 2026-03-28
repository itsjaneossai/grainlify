//! # Bounty Escrow — Event Definitions
//!
//! All events emitted by [`BountyEscrowContract`] conform to **EVENT_VERSION_V2**,
//! the canonical Grainlify event envelope.
//!
//! ## EVENT_VERSION_V2 Contract
//!
//! Every event payload carries a `version: u32` field set to the
//! [`EVENT_VERSION_V2`] constant (`2`).  The **first** topic slot is always a
//! domain `Symbol` that names the event category; the second topic (where
//! present) is the `bounty_id` so indexers can filter by both category *and*
//! bounty without decoding the payload.
//!
//! ```text
//! topics : (category_symbol [, bounty_id: u64])
//! data   : <EventStruct>   ← always carries version: u32 = 2
//! ```
//!
//! ## Why topic-level versioning?
//!
//! Soroban events are permanently archived.  Placing the version in the payload
//! (rather than a topic) would force indexers to decode every event body just to
//! determine whether the schema is relevant.  Placing it in `topics[0]` allows
//! cheap prefix-filter queries at the RPC/Horizon layer.
//!
//! ## Security invariants
//!
//! * Events are emitted **after** all state mutations and token transfers
//!   (Checks-Effects-Interactions ordering) so they accurately reflect final
//!   on-chain state.
//! * No PII, KYC data, or private keys are ever emitted.
//! * All `symbol_short!` strings are ≤ 9 bytes — Soroban rejects longer values,
//!   which would corrupt topic-based filtering.
use crate::CapabilityAction;
use soroban_sdk::{contracttype, symbol_short, Address, BytesN, Env, Symbol};

// ── Version constant ─────────────────────────────────────────────────────────

/// Canonical event schema version included in **every** event payload.
///
/// Increment this value  and update all emitter functions whenever the
/// payload schema changes in a breaking way.  Non-breaking additions that is new
/// optional fields do not require a version bump.
pub const EVENT_VERSION_V2: u32 = 2;

// ═══════════════════════════════════════════════════════════════════════════════
// INITIALIZATION EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_bounty_initialized`] event.
///
/// Emitted **exactly once** when [`BountyEscrowContract::init`] succeeds.
/// Indexers can treat the presence of this event as proof that the contract
/// was legitimately initialised with a specific admin or token pair.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"init"` |
///
/// ### Data fields
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `version` | `u32` | Always [`EVENT_VERSION_V2`] |
/// | `admin` | `Address` | Initial admin address |
/// | `token` | `Address` | Reward token contract |
/// | `timestamp` | `u64` | Ledger time of initialization |
///
/// ### Security notes
/// - This event is replay-safe: the contract enforces
///   `AlreadyInitialized` on subsequent `init` calls, so this event is
///   emitted at most once per deployed contract instance.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BountyEscrowInitialized {
    pub version: u32,
    pub admin: Address, // address granted admin authority over this contract.
    pub token: Address, // Soroban compatible token contract address (SAC or SEP-41).
    pub timestamp: u64,
}

/// Emit [`BountyEscrowInitialized`].
///
/// # Arguments
/// * `env`   — Soroban execution environment.
/// * `event` — Pre constructed event payload.
///
/// # Panics
/// Never panics; publishing is infallible in Soroban.
pub fn emit_bounty_initialized(env: &Env, event: BountyEscrowInitialized) {
    let topics = (symbol_short!("init"),);
    env.events().publish(topics, event.clone());
}

// ═══════════════════════════════════════════════════════════════════════════════
// FUNDS LOCK , RELEASE and  REFUND EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_funds_locked`] event.
///
/// Emitted after a successful [`BountyEscrowContract::lock_funds`] call.
/// The `amount` field reflects the **gross** deposit (before fee deduction).
/// Net escrowed principal can be derived as `amount - lock_fee`.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"f_lock"` |
/// | 1 | `bounty_id: u64` |
///
/// ### Security notes
/// - Emitted after the token transfer succeeds, so the event reliably
///   represents funds that are already in the escrow contract.
/// - `deadline` is stored on-chain; this field is purely informational
///   for off-chain consumers.
#[contracttype]
#[derive(Clone, Debug)]
pub struct FundsLocked {
    pub version: u32,
    pub bounty_id: u64,     // a unique bounty identifier assigned by the backend
    pub amount: i128,       //  gross amount deposited
    pub depositor: Address, // address that does the deposit
    pub deadline: u64,
}

/// Emit [`FundsLocked`].
///
/// # Arguments
/// * `env`   — Soroban execution environment.
/// * `event` — Pre-constructed event payload; `bounty_id` is also published
///   as `topics[1]` for cheap indexed filtering.
pub fn emit_funds_locked(env: &Env, event: FundsLocked) {
    let topics = (symbol_short!("f_lock"), event.bounty_id);
    env.events().publish(topics, event.clone());
}

/// Payload for the [`emit_funds_released`] event.
///
/// Emitted after a successful fund release to a contributor, including
/// [`BountyEscrowContract::release_funds`], `partial_release`, and
/// `release_with_capability` paths.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"f_rel"` |
/// | 1 | `bounty_id: u64` |
///
/// ### Security notes
/// - For `partial_release`, this event is emitted per call.  Consumers
///   should sum all `FundsReleased` events to reconstruct total payout.
/// - `amount` is the net payout after any release fee.
#[contracttype]
#[derive(Clone, Debug)]
pub struct FundsReleased {
    pub version: u32,
    pub bounty_id: u64,
    pub amount: i128,       // amount transferred to `recipient`
    pub recipient: Address, // the contributor wallet address that received the funds.
    pub timestamp: u64,
}

/// Emit [`FundsReleased`].
pub fn emit_funds_released(env: &Env, event: FundsReleased) {
    let topics = (symbol_short!("f_rel"), event.bounty_id);
    env.events().publish(topics, event.clone());
}

// ── Refund trigger type ───────────────────────────────────────────────────────

/// Discriminator indicating which code path triggered a refund.
///
/// Carried in [`FundsRefunded`] and [`RefundRecord`] so that indexers and
/// auditors can distinguish between the three refund mechanisms without
/// inspecting storage or transaction inputs.
///
/// | Variant | Trigger |
/// |---------|---------|
/// | `AdminApproval` | Admin called `approve_refund` then `refund` (existing dual-auth path). |
/// | `DeadlineExpired` | `auto_refund` called permissionlessly after the deadline passed. |
/// | `OracleAttestation` | Configured oracle called `oracle_refund` to attest a dispute outcome. |
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefundTriggerType {
    /// Admin-approved refund (existing dual-auth behavior).
    AdminApproval,
    /// Time-based auto-refund after deadline (permissionless).
    DeadlineExpired,
    /// Oracle-attested refund (dispute resolved in favor of depositor).
    OracleAttestation,
}

/// Payload for the [`emit_funds_refunded`] event.
///
/// Emitted after a successful refund via [`BountyEscrowContract::refund`],
/// `refund_resolved` (anonymous escrow path), `oracle_refund`, or
/// `auto_refund`.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"f_ref"` |
/// | 1 | `bounty_id: u64` |
///
/// ### Security notes
/// - `refund_to` may differ from the original depositor when an admin
///   approval overrides the recipient (e.g. custom partial-refund target).
/// - For anonymous escrows the depositor identity is never revealed; only
///   the on-chain resolver-approved `recipient` is used.
/// - `trigger_type` identifies which refund path was taken so downstream
///   consumers can distinguish oracle-attested from time-based refunds.
#[contracttype]
#[derive(Clone, Debug)]
pub struct FundsRefunded {
    pub version: u32,
    pub bounty_id: u64,
    pub amount: i128,
    pub refund_to: Address,
    pub timestamp: u64,
    /// Which code path triggered this refund.
    pub trigger_type: RefundTriggerType,
}

/// Emit [`FundsRefunded`].
pub fn emit_funds_refunded(env: &Env, event: FundsRefunded) {
    let topics = (symbol_short!("f_ref"), event.bounty_id);
    env.events().publish(topics, event.clone());
}

// ── Oracle config event ───────────────────────────────────────────────────────

/// Payload for the [`emit_oracle_config_updated`] event.
///
/// Emitted when the admin configures or updates the oracle address via
/// [`BountyEscrowContract::set_oracle`].
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"orc_cfg"` |
///
/// ### Security notes
/// - Only the admin can call `set_oracle`; this event serves as an
///   on-chain audit trail of oracle configuration changes.
/// - When `enabled = false` the oracle address is stored but
///   `oracle_refund` calls will be rejected until re-enabled.
#[contracttype]
#[derive(Clone, Debug)]
pub struct OracleConfigUpdated {
    pub version: u32,
    pub oracle_address: Address,
    pub enabled: bool,
    pub admin: Address,
    pub timestamp: u64,
}

/// Emit [`OracleConfigUpdated`].
pub fn emit_oracle_config_updated(env: &Env, event: OracleConfigUpdated) {
    let topics = (symbol_short!("orc_cfg"),);
    env.events().publish(topics, event.clone());
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEE EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Discriminator for fee-collection operations.
///
/// Used in [`FeeCollected`] to distinguish lock-time fees from
/// release-time fees without requiring separate event types.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeeOperationType {
    /// Fee collected at lock time (`lock_funds` / `batch_lock_funds`).
    Lock,
    /// Fee collected at release time (`release_funds` / `batch_release_funds`).
    Release,
}

/// Payload for the [`emit_fee_collected`] event.
///
/// Emitted whenever a non-zero fee is transferred to `recipient`.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"fee"` |
///
/// ### Security notes
/// - Fee amounts use **ceiling division** (`⌈amount × rate / 10_000⌉`)
///   to prevent principal drain via dust-splitting.
/// - Both `amount` (actual fee transferred) and `fee_rate` (basis points)
///   are published so auditors can verify correctness off-chain.
#[contracttype]
#[derive(Clone, Debug)]
pub struct FeeCollected {
    pub operation_type: FeeOperationType, // determines if the fee was collected on lock or release.
    pub amount: i128,                     // actual fee amount transferred
    pub fee_rate: i128,                   // fee rate applied in basis points (1 bp = 0.01 %).
    pub fee_fixed: i128,                  // flat fee component
    pub recipient: Address,
    pub timestamp: u64, // Ledger timestamp.
}

/// Emit [`FeeCollected`]
pub fn emit_fee_collected(env: &Env, event: FeeCollected) {
    let topics = (symbol_short!("fee"),);
    env.events().publish(topics, event.clone());
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_batch_funds_locked`] event.
///
/// Emitted once per successful [`BountyEscrowContract::batch_lock_funds`]
/// call, after all individual [`FundsLocked`] events.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"b_lock"` |
///
/// ### Security notes
/// - `count` and `total_amount` are derived from the ordered, validated
///   item list so they match the sum of the per-item `FundsLocked` events
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchFundsLocked {
    pub count: u32,         //  numbers of escrows created in this batch.
    pub total_amount: i128, // the sum of all locked amounts in this batch.
    pub timestamp: u64,
}

/// Emit [`BatchFundsLocked`]
pub fn emit_batch_funds_locked(env: &Env, event: BatchFundsLocked) {
    let topics = (symbol_short!("b_lock"),);
    env.events().publish(topics, event.clone());
}

/// Payload for the [`emit_fee_config_updated`] event.
///
/// Emitted when the global fee configuration is changed by the admin.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"fee_cfg"` |
#[contracttype]
#[derive(Clone, Debug)]
pub struct FeeConfigUpdated {
    /// New lock fee rate in basis points.
    pub lock_fee_rate: i128,
    /// New release fee rate in basis points.
    pub release_fee_rate: i128,
    /// New lock fixed fee.
    pub lock_fixed_fee: i128,
    /// New release fixed fee.
    pub release_fixed_fee: i128,
    /// Address designated to receive fees.
    pub fee_recipient: Address,
    /// Whether fee collection is active after this update.
    pub fee_enabled: bool,
    /// Ledger timestamp.
    pub timestamp: u64,
}

/// Emit [`FeeConfigUpdated`]
pub fn emit_fee_config_updated(env: &Env, event: FeeConfigUpdated) {
    let topics = (symbol_short!("fee_cfg"),);
    env.events().publish(topics, event.clone());
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct EscrowArchived {
    pub version: u32,
    pub bounty_id: u64,
    pub timestamp: u64,
}

pub fn emit_archived(env: &Env, bounty_id: u64, timestamp: u64) {
    let topics = (symbol_short!("archive"), bounty_id);
    env.events().publish(
        topics,
        EscrowArchived {
            version: EVENT_VERSION_V2,
            bounty_id,
            timestamp,
        },
    );
}

/// Payload for the [`emit_fee_routing_updated`] event.
///
/// Emitted when a bounty-specific fee routing rule is set or changed.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"fee_rte"` |
/// | 1 | `bounty_id: u64` |
#[contracttype]
#[derive(Clone, Debug)]
pub struct FeeRoutingUpdated {
    /// Bounty this routing config applies to.
    pub bounty_id: u64,
    /// Primary treasury recipient.
    pub treasury_recipient: Address,
    /// Treasury share in basis points.
    pub treasury_bps: i128,
    /// Optional partner/referral recipient.
    pub partner_recipient: Option<Address>,
    /// Partner share in basis points.
    pub partner_bps: i128,
    /// Ledger timestamp.
    pub timestamp: u64,
}

/// Emit [`FeeRoutingUpdated`]
pub fn emit_fee_routing_updated(env: &Env, event: FeeRoutingUpdated) {
    let topics = (symbol_short!("fee_rte"), event.bounty_id);
    env.events().publish(topics, event.clone());
}

/// Payload for the [`emit_fee_routed`] event
///
/// Emitted when a split fee is distributed to multiple recipients.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"fee_rt"` |
/// | 1 | `bounty_id: u64` |
#[contracttype]
#[derive(Clone, Debug)]
pub struct FeeRouted {
    /// Bounty this fee was collected for.
    pub bounty_id: u64,
    /// Whether this was a lock or release fee.
    pub operation_type: FeeOperationType,
    /// Original deposit amount before fee.
    pub gross_amount: i128,
    /// Total fee collected.
    pub total_fee: i128,
    /// Rate applied in basis points.
    pub fee_rate: i128,
    /// Treasury address.
    pub treasury_recipient: Address,
    /// Portion sent to treasury.
    pub treasury_fee: i128,
    /// Optional partner address.
    pub partner_recipient: Option<Address>,
    /// Portion sent to partner.
    pub partner_fee: i128,
    /// Ledger timestamp.
    pub timestamp: u64,
}

/// Emit [`FeeRouted`]
pub fn emit_fee_routed(env: &Env, event: FeeRouted) {
    let topics = (symbol_short!("fee_rt"), event.bounty_id);
    env.events().publish(topics, event.clone());
}

/// Payload for the [`emit_batch_funds_released`] event.
///
/// Emitted once per successful [`BountyEscrowContract::batch_release_funds`]
/// call, after all individual [`FundsReleased`] events.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"b_rel"` |
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchFundsReleased {
    pub count: u32,
    pub total_amount: i128,
    pub timestamp: u64,
}

/// Emit [`BatchFundsReleased`]
pub fn emit_batch_funds_released(env: &Env, event: BatchFundsReleased) {
    let topics = (symbol_short!("b_rel"),);
    env.events().publish(topics, event.clone());
}

// ═══════════════════════════════════════════════════════════════════════════════
// APPROVAL & CLAIM EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_approval_added`] event.
///
/// Emitted when a multisig signer approves a large-amount release.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"approval"` |
/// | 1 | `bounty_id: u64` |
#[contracttype]
#[derive(Clone, Debug)]
pub struct ApprovalAdded {
    pub bounty_id: u64,       // requiring multisig approval.
    pub contributor: Address, // intended contributor recipient
    pub approver: Address,    // signer who submitted this approval
    pub timestamp: u64,
}

/// Emit [`ApprovalAdded`]
pub fn emit_approval_added(env: &Env, event: ApprovalAdded) {
    let topics = (symbol_short!("approval"), event.bounty_id);
    env.events().publish(topics, event.clone());
}

/// Payload emitted when a pending claim is created via `authorize_claim`.
///
/// ### Topics
/// `("claim", "created")`
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimCreated {
    pub bounty_id: u64, // use program_id+schedule_id equivalent in program-escrow
    pub recipient: Address,
    pub amount: i128,
    pub expires_at: u64,
}

/// Payload emitted when a claim is successfully executed.
///
/// ### Topics
/// `("claim", "done")`/// Payload emitted when a claim is successfully executed.
///
/// ### Topics
/// `("claim", "done")`
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimExecuted {
    pub bounty_id: u64,
    pub recipient: Address,
    pub amount: i128,
    pub claimed_at: u64,
}

/// Payload emitted when an admin cancels a pending claim.
///
/// ### Topics
/// `("claim", "cancel")`
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimCancelled {
    pub bounty_id: u64,
    pub recipient: Address,
    pub amount: i128,
    pub cancelled_at: u64,
    pub cancelled_by: Address,
}

/// Discriminator used in [`record_receipt`]-style internal bookkeeping.
///
/// Not emitted directly as a standalone event; embedded in receipt payloads.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CriticalOperationOutcome {
    /// Funds were successfully released to a contributor.
    Released,
    /// Funds were successfully refunded to the depositor.
    Refunded,
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETERMINISTIC SELECTION EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_deterministic_selection`] event.
///
/// Emitted when a winner is chosen via
/// [`BountyEscrowContract::issue_claim_ticket_deterministic`].
/// Publishing the `seed_hash` and `winner_score` allows any observer to
/// reproduce and verify the selection off-chain.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"prng_sel"` |
/// | 1 | `bounty_id: u64` |
///
/// ### Security notes
/// - This is **deterministic pseudo-randomness**, not cryptographically
///   unpredictable.  Callers who control `external_seed` or ledger state
///   can influence the result.  Use only for low-stakes selections.
/// - `seed_hash` and `winner_score` are published on-chain so that the
///   selection is publicly verifiable even if the inputs are private.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicSelectionDerived {
    /// Bounty for which a winner was selected.
    pub bounty_id: u64,
    /// Zero-based index into the `candidates` slice that was chosen.
    pub selected_index: u32,
    /// Total number of candidates considered.
    pub candidate_count: u32,
    /// Address that was selected as the winner.
    pub selected_beneficiary: Address,
    /// Hash of the combined seed material (for verification).
    pub seed_hash: BytesN<32>,
    /// Per-candidate score byte string that determined the winner.
    pub winner_score: BytesN<32>,
    /// Ledger timestamp.
    pub timestamp: u64,
}

/// Emit [`DeterministicSelectionDerived`]
pub fn emit_deterministic_selection(env: &Env, event: DeterministicSelectionDerived) {
    let topics = (symbol_short!("prng_sel"), event.bounty_id);
    env.events().publish(topics, event);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANONYMOUS ESCROW EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_funds_locked_anon`] event.
///
/// Emitted by [`BountyEscrowContract::lock_funds_anonymous`].
/// The depositor's address is **not** stored on-chain; only the 32-byte
/// commitment is recorded.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"f_lkanon"` |
/// | 1 | `bounty_id: u64` |
///
/// ### Security notes
/// - Commitment must be computed off-chain using a collision-resistant
///   hash function.  The contract does not validate commitment format.
/// - Refunds for anonymous escrows require the configured
///   `AnonymousResolver` to call `refund_resolved`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FundsLockedAnon {
    pub version: u32,
    pub bounty_id: u64,
    pub amount: i128,
    pub depositor_commitment: BytesN<32>,
    pub deadline: u64,
}
/// Emit [`FundsLockedAnon`]
pub fn emit_funds_locked_anon(env: &Env, event: FundsLockedAnon) {
    let topics = (symbol_short!("f_lkanon"), event.bounty_id);
    env.events().publish(topics, event);
}

// ═══════════════════════════════════════════════════════════════════════════════
// OPERATIONAL STATE EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_deprecation_state_changed`] event.
///
/// Emitted when the admin activates or deactivates the contract kill-switch.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"deprec"` |
///
/// ### Security notes
/// - When `deprecated = true`, all `lock_funds` and `batch_lock_funds`
///   calls will fail with `ContractDeprecated`.
/// - Existing escrows continue to release or refund normally.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeprecationStateChanged {
    pub deprecated: bool,
    pub migration_target: Option<Address>, // optional address of the replacement contract for migration.
    pub admin: Address,
    /// admin address that triggered the change.
    pub timestamp: u64,
}

/// Emit [`DeprecationStateChanged`].
pub fn emit_deprecation_state_changed(env: &Env, event: DeprecationStateChanged) {
    let topics = (symbol_short!("deprec"),);
    env.events().publish(topics, event);
}

/// Payload for the [`emit_maintenance_mode_changed`] event.
///
/// Emitted when maintenance mode is toggled by the admin.
/// When enabled, `lock_funds` returns `FundsPaused` (as if `lock_paused`
/// were true).
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"maint"` |
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceModeChanged {
    pub enabled: bool,
    pub admin: Address,
    pub timestamp: u64,
}

/// Emit [`MaintenanceModeChanged`]
pub fn emit_maintenance_mode_changed(env: &Env, event: MaintenanceModeChanged) {
    let topics = (symbol_short!("maint"),);
    env.events().publish(topics, event);
}

/// Payload for the [`emit_participant_filter_mode_changed`] event.
///
/// Emitted when the admin changes the participant filter mode.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"pf_mode"` |
///
/// ### Security notes
/// - Transitioning modes does not clear list data; only the active mode
///   is enforced on subsequent `lock_funds` calls.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantFilterModeChanged {
    pub previous_mode: crate::ParticipantFilterMode,
    pub new_mode: crate::ParticipantFilterMode,
    pub admin: Address,
    pub timestamp: u64,
}

/// Emit [`ParticipantFilterModeChanged`]
pub fn emit_participant_filter_mode_changed(env: &Env, event: ParticipantFilterModeChanged) {
    let topics = (symbol_short!("pf_mode"),);
    env.events().publish(topics, event);
}

// ═══════════════════════════════════════════════════════════════════════════════
// RISK FLAG EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_risk_flags_updated`] event.
///
/// Emitted when an admin sets or clears risk flags on a bounty's metadata.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"risk"` |
/// | 1 | `bounty_id: u64` |
///
/// ### Defined risk flag bits
/// | Bit | Constant | Meaning |
/// |-----|----------|---------|
/// | 0 | `RISK_FLAG_HIGH_RISK` | Elevated risk profile |
/// | 1 | `RISK_FLAG_UNDER_REVIEW` | Under active review |
/// | 2 | `RISK_FLAG_RESTRICTED` | Payout restricted pending investigation |
/// | 3 | `RISK_FLAG_DEPRECATED` | Bounty marked deprecated |
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskFlagsUpdated {
    pub version: u32,
    pub bounty_id: u64,
    pub previous_flags: u32,
    pub new_flags: u32,
    pub admin: Address,
    pub timestamp: u64,
}

/// Emit [`RiskFlagsUpdated`]
pub fn emit_risk_flags_updated(env: &Env, event: RiskFlagsUpdated) {
    let topics = (symbol_short!("risk"), event.bounty_id);
    env.events().publish(topics, event);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLAIM TICKET EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_ticket_issued`] event.
///
/// Emitted when the admin issues a single-use claim ticket via
/// [`BountyEscrowContract::issue_claim_ticket`].
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"ticket_i"` |
/// | 1 | `ticket_id: u64` |
///
/// ### Security notes
/// - Ticket IDs are monotonically increasing; gaps indicate revocations
///   or failed issuance attempts (which do not emit this event).
/// - The `beneficiary` field allows off-chain indexers to build a
///   per-address ticket inbox without scanning all tickets.

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationPreferencesUpdated {
    pub version: u32,
    pub bounty_id: u64,
    pub previous_prefs: u32,
    pub new_prefs: u32,
    pub actor: Address,
    pub created: bool,
    pub timestamp: u64,
}

pub fn emit_notification_preferences_updated(env: &Env, event: NotificationPreferencesUpdated) {
    let topics = (symbol_short!("npref"), event.bounty_id);
    env.events().publish(topics, event);
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketIssued {
    pub ticket_id: u64,
    pub bounty_id: u64,
    pub beneficiary: Address,
    pub amount: i128,
    pub expires_at: u64,
    pub issued_at: u64,
}

/// Emit [`TicketIssued`]
pub fn emit_ticket_issued(env: &Env, event: TicketIssued) {
    let topics = (symbol_short!("ticket_i"), event.ticket_id);
    env.events().publish(topics, event);
}

/// Payload for the [`emit_ticket_claimed`] event.
///
/// Emitted when a claim ticket is successfully redeemed.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"ticket_c"` |
/// | 1 | `ticket_id: u64` |
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketClaimed {
    pub ticket_id: u64,
    /// Ticket that was redeemed.
    pub bounty_id: u64,
    /// Bounty the ticket was issued against.
    pub claimer: Address,
    /// Address that redeemed the ticket.
    pub claimed_at: u64,
}

/// Emit [`TicketClaimed`]
pub fn emit_ticket_claimed(env: &Env, event: TicketClaimed) {
    let topics = (symbol_short!("ticket_c"), event.ticket_id);
    env.events().publish(topics, event);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAUSE & EMERGENCY EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Emit a pause-state-changed event for a single operation type.
///
/// This function is called for `lock`, `release`, and `refund` operations
/// individually when [`BountyEscrowContract::set_paused`] is invoked.
///
/// ### Topics
/// `("pause", operation_symbol)`
pub fn emit_pause_state_changed(env: &Env, event: crate::PauseStateChanged) {
    let topics = (symbol_short!("pause"), event.operation.clone());
    env.events().publish(topics, event);
}

/// Payload for the [`emit_emergency_withdraw`] event.
///
/// Emitted when the admin drains all token balances from the contract via
/// [`BountyEscrowContract::emergency_withdraw`].
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"em_wtd"` |
///
/// ### Security notes
/// - This function can only be called when `lock_paused = true`,
///   ensuring depositors have visible warning before a drain is possible.
/// - The `amount` field reflects the **entire** contract balance at the
///   time of withdrawal, which may cover multiple open escrows.

#[contracttype]
#[derive(Clone, Debug)]
pub struct EmergencyWithdrawEvent {
    pub admin: Address,
    pub recipient: Address,
    pub amount: i128,
    pub timestamp: u64,
}

/// Emit [`EmergencyWithdrawEvent`]
pub fn emit_emergency_withdraw(env: &Env, event: EmergencyWithdrawEvent) {
    let topics = (symbol_short!("em_wtd"),);
    env.events().publish(topics, event.clone());
}

// ═══════════════════════════════════════════════════════════════════════════════
// CAPABILITY EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_capability_issued`] event.
///
/// Emitted when the admin or an authorized party creates a new capability
/// token via [`BountyEscrowContract::issue_capability`].
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"cap_new"` |
/// | 1 | `capability_id: u64` |
///
/// ### Security notes
/// - Capabilities are scoped to a specific `(action, bounty_id,
///   amount_limit)` triplet at issuance time.
/// - An owner cannot issue a capability whose `amount_limit` exceeds
///   their own authority over the referenced escrow.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityIssued {
    /// Unique cryptographically secure capability identifier.
    pub capability_id: BytesN<32>,
    /// Address that created and vouches for this capability.
    pub owner: Address,
    /// Address authorised to exercise this capability.
    pub holder: Address,
    /// Permitted action (`Claim`, `Release`, or `Refund`).
    pub action: CapabilityAction,
    /// Bounty this capability is scoped to.
    pub bounty_id: u64,
    /// Maximum token amount the holder may exercise in total.
    pub amount_limit: i128,
    /// Unix timestamp past which the capability is invalid.
    pub expires_at: u64,
    /// Maximum number of times the holder may exercise this capability.
    pub max_uses: u32,
    /// Ledger timestamp of issuance.
    pub timestamp: u64,
}

/// Emit [`CapabilityIssued`]
pub fn emit_capability_issued(env: &Env, event: CapabilityIssued) {
    let topics = (symbol_short!("cap_new"), event.capability_id.clone());
    env.events().publish(topics, event);
}

/// Payload for the [`emit_capability_used`] event.
///
/// Emitted each time a capability is partially or fully consumed.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"cap_use"` |
/// | 1 | `capability_id: u64` |
///
/// ### Security notes
/// - `remaining_amount` and `remaining_uses` after this event reflect
///   the persisted on-chain values.
/// - When both reach zero, the capability is effectively exhausted;
///   subsequent calls will return `CapabilityUsesExhausted` or
///   `CapabilityAmountExceeded`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityUsed {
    /// Capability that was exercised.
    pub capability_id: BytesN<32>,
    /// Address that exercised the capability.
    pub holder: Address,
    /// Action that was performed.
    pub action: CapabilityAction,
    /// Bounty the action was applied to.
    pub bounty_id: u64,
    /// Token amount consumed in this exercise.
    pub amount_used: i128,
    /// Remaining token allowance after this exercise.
    pub remaining_amount: i128,
    /// Remaining use count after this exercise.
    pub remaining_uses: u32,
    /// Ledger timestamp.
    pub used_at: u64,
}

/// Emit [`CapabilityUsed`]
pub fn emit_capability_used(env: &Env, event: CapabilityUsed) {
    let topics = (symbol_short!("cap_use"), event.capability_id.clone());
    env.events().publish(topics, event);
}

/// Payload for the [`emit_capability_revoked`] event.
///
/// Emitted when the owner revokes a previously issued capability.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"cap_rev"` |
/// | 1 | `capability_id: u64` |
///
/// ### Security notes
/// - Revocation is permanent and idempotent.  A revoked capability cannot
///   be re-enabled.
/// - After revocation, any attempt by the holder to exercise the
///   capability will fail with `CapabilityRevoked`
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRevoked {
    /// Capability that was revoked
    pub capability_id: BytesN<32>,
    pub owner: Address,
    pub revoked_at: u64,
}

/// Emit [`CapabilityRevoked`]
pub fn emit_capability_revoked(env: &Env, event: CapabilityRevoked) {
    let topics = (symbol_short!("cap_rev"), event.capability_id.clone());
    env.events().publish(topics, event);
}

/// Emitted when an operation's measured resource usage approaches the
/// configured cap (at or above `WARNING_THRESHOLD_BPS / 10_000` of the cap).
/// Only emitted in test / testutils builds; see `gas_budget` module docs.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GasBudgetCapApproached {
    /// Canonical operation symbol (e.g. `symbol_short!("lock")`).
    pub operation: Symbol,
    /// Measured CPU instructions consumed by this call.
    pub cpu_used: u64,
    /// Measured memory bytes consumed by this call.
    pub mem_used: u64,
    /// Configured CPU instruction cap (`0` = uncapped).
    pub cpu_cap: u64,
    /// Configured memory byte cap (`0` = uncapped).
    pub mem_cap: u64,
    /// The warning threshold that was crossed, in basis points.
    pub threshold_bps: u32,
    /// Ledger timestamp at the time of the check.
    pub timestamp: u64,
}

/// Emitted when an operation's measured resource usage exceeds the configured
/// cap. When `GasBudgetConfig::enforce` is `true` this accompanies a
/// transaction revert. Only emitted in test / testutils builds.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GasBudgetCapExceeded {
    /// Canonical operation symbol (e.g. `symbol_short!("lock")`).
    pub operation: Symbol,
    /// Measured CPU instructions consumed by this call.
    pub cpu_used: u64,
    /// Measured memory bytes consumed by this call.
    pub mem_used: u64,
    /// Configured CPU instruction cap (`0` = uncapped).
    pub cpu_cap: u64,
    /// Configured memory byte cap (`0` = uncapped).
    pub mem_cap: u64,
    /// Ledger timestamp at the time of the check.
    pub timestamp: u64,
}

// ═══════════════════════════════════════════════════════════════════════════════
// TIMELOCK EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for the [`emit_timelock_configured`] event.
///
/// Emitted when the admin configures the timelock settings.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"timelock_cfg"` |
///
/// ### Data fields
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `version` | `u32` | Always [`EVENT_VERSION_V2`] |
/// | `delay` | `u64` | Configured timelock delay in seconds |
/// | `is_enabled` | `bool` | Whether timelock is enabled |
/// | `configured_by` | `Address` | Admin who configured the timelock |
/// | `timestamp` | `u64` | Ledger time of configuration |
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelockConfigured {
    pub version: u32,
    pub delay: u64,
    pub is_enabled: bool,
    pub configured_by: Address,
    pub timestamp: u64,
}

/// Emit [`TimelockConfigured`].
pub fn emit_timelock_configured(env: &Env, event: TimelockConfigured) {
    let topics = (symbol_short!("tmlk_cfg"),);
    env.events().publish(topics, event);
}

/// Payload for the [`emit_admin_action_proposed`] event.
///
/// Emitted when an admin proposes a delayed action.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"act_prop"` |
/// | 1 | `action_id: u64` |
///
/// ### Data fields
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `version` | `u32` | Always [`EVENT_VERSION_V2`] |
/// | `action_type` | `ActionType` | Type of admin action |
/// | `execute_after` | `u64` | Timestamp when action becomes executable |
/// | `proposed_by` | `Address` | Admin who proposed the action |
/// | `timestamp` | `u64` | Ledger time of proposal |
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminActionProposed {
    pub version: u32,
    pub action_type: crate::ActionType,
    pub execute_after: u64,
    pub proposed_by: Address,
    pub timestamp: u64,
}

/// Emit [`AdminActionProposed`].
pub fn emit_admin_action_proposed(env: &Env, event: AdminActionProposed) {
    let topics = (symbol_short!("act_prop"),);
    env.events().publish(topics, event);
}

/// Payload for the [`emit_admin_action_executed`] event.
///
/// Emitted when a proposed admin action is executed.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"act_exec"` |
/// | 1 | `action_id: u64` |
///
/// ### Data fields
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `version` | `u32` | Always [`EVENT_VERSION_V2`] |
/// | `action_type` | `ActionType` | Type of admin action |
/// | `executed_by` | `Address` | Address that executed the action |
/// | `executed_at` | `u64` | Ledger time of execution |
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminActionExecuted {
    pub version: u32,
    pub action_type: crate::ActionType,
    pub executed_by: Address,
    pub executed_at: u64,
}

/// Emit [`AdminActionExecuted`].
pub fn emit_admin_action_executed(env: &Env, event: AdminActionExecuted) {
    let topics = (symbol_short!("act_exec"),);
    env.events().publish(topics, event);
}

/// Payload for the [`emit_admin_action_cancelled`] event.
///
/// Emitted when an admin cancels a pending action.
///
/// ### Topics
/// | Index | Value |
/// |-------|-------|
/// | 0 | `"act_cncl"` |
/// | 1 | `action_id: u64` |
///
/// ### Data fields
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `version` | `u32` | Always [`EVENT_VERSION_V2`] |
/// | `action_type` | `ActionType` | Type of admin action |
/// | `cancelled_by` | `Address` | Admin who cancelled the action |
/// | `cancelled_at` | `u64` | Ledger time of cancellation |
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminActionCancelled {
    pub version: u32,
    pub action_type: crate::ActionType,
    pub cancelled_by: Address,
    pub cancelled_at: u64,
}

/// Emit [`AdminActionCancelled`].
pub fn emit_admin_action_cancelled(env: &Env, event: AdminActionCancelled) {
    let topics = (symbol_short!("act_cncl"),);
    env.events().publish(topics, event);
}
