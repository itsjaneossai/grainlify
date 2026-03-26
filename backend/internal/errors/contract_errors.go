// Package errors provides a centralised mapping from on-chain contract error
// codes to human-readable messages.  With the unified error registry,
// error codes are non-overlapping across all Grainlify contracts.
package errors

import "fmt"

// ContractKind identifies which contract produced the error for diagnostic logging,
// though numeric codes are now unique across the entire project.
type ContractKind string

const (
	BountyEscrow   ContractKind = "bounty_escrow"
	Governance     ContractKind = "governance"
	CircuitBreaker ContractKind = "circuit_breaker"
	ProgramEscrow  ContractKind = "program_escrow"
)

type contractErrorEntry struct {
	Name    string // e.g. "AlreadyInitialized"
	Message string // human-readable explanation
}

// ---------------------------------------------------------------------------
// Unified Error Registry
// (Source: contracts/grainlify-core/src/errors.rs)
// ---------------------------------------------------------------------------

var unifiedErrors = map[uint32]contractErrorEntry{
	// 1-99: Common Errors
	1:  {"AlreadyInitialized", "Contract is already initialized"},
	2:  {"NotInitialized", "Contract has not been initialized"},
	3:  {"Unauthorized", "Unauthorized: caller does not have permission"},
	4:  {"InvalidAmount", "Amount is invalid (must be greater than zero)"},
	5:  {"InsufficientFunds", "Insufficient funds for this operation"},
	6:  {"DeadlineNotPassed", "Deadline has not passed yet"},
	7:  {"InvalidDeadline", "Deadline is invalid (in the past or too far in the future)"},
	8:  {"ContractDeprecated", "Contract is deprecated; new operations are blocked"},
	9:  {"MaintenanceMode", "Contract is currently in maintenance mode"},
	10: {"Paused", "Operations are currently paused"},
	11: {"Overflow", "Numeric overflow occurred during calculation"},
	12: {"Underflow", "Numeric underflow occurred during calculation"},
	13: {"InvalidState", "Contract is in an invalid state for this operation"},
	14: {"NotPaused", "Operation requires the contract to be paused"},
	15: {"InvalidAssetId", "Invalid asset identifier"},

	// 100-199: Governance Errors
	101: {"ThresholdNotMet", "Governance threshold has not been reached"},
	102: {"ProposalNotFound", "Proposal not found"},
	103: {"InvalidThreshold", "Governance threshold value is invalid"},
	104: {"ThresholdTooLow", "Governance threshold is too low"},
	105: {"InsufficientStake", "Insufficient stake to perform this governance action"},
	106: {"ProposalsNotFound", "No proposals found"},
	107: {"ProposalNotActive", "Proposal is not currently active"},
	108: {"VotingNotStarted", "Voting has not started yet for this proposal"},
	109: {"VotingEnded", "Voting period has ended for this proposal"},
	110: {"VotingStillActive", "Voting is still active; cannot execute proposal yet"},
	111: {"AlreadyVoted", "You have already voted on this proposal"},
	112: {"ProposalNotApproved", "Proposal has not been approved"},
	113: {"ExecutionDelayNotMet", "Execution delay period has not elapsed yet"},
	114: {"ProposalExpired", "Proposal has expired"},

	// 200-299: Escrow Errors
	201: {"BountyExists", "A bounty with this ID already exists"},
	202: {"BountyNotFound", "Bounty not found"},
	203: {"FundsNotLocked", "Bounty funds have not been locked yet"},
	204: {"InvalidFeeRate", "Fee rate is invalid"},
	205: {"FeeRecipientNotSet", "Fee recipient address has not been configured"},
	206: {"InvalidBatchSize", "Batch size is invalid"},
	207: {"BatchSizeMismatch", "Batch size mismatch (e.g. IDs vs recipients)"},
	208: {"DuplicateBountyId", "Duplicate bounty ID found"},
	209: {"RefundNotApproved", "Refund has not been approved by an admin"},
	210: {"AmountBelowMinimum", "Amount is below the configured minimum"},
	211: {"AmountAboveMaximum", "Amount exceeds the configured maximum"},
	212: {"ClaimPending", "Operation blocked by a pending claim or dispute"},
	213: {"TicketNotFound", "Claim ticket not found"},
	214: {"TicketAlreadyUsed", "Claim ticket has already been used"},
	215: {"TicketExpired", "Claim ticket has expired"},
	216: {"ParticipantBlocked", "Participant is blocklisted and cannot participate"},
	217: {"ParticipantNotAllowed", "Participant is not on the allowlist"},
	218: {"NotAnonymousEscrow", "Bounty exists but is not an anonymous escrow"},
	219: {"InvalidSelectionInput", "Input for deterministic selection is invalid"},
	220: {"UpgradeSafetyCheckFailed", "Upgrade safety check failed"},
	221: {"BountyAlreadyInitialized", "Bounty escrow contract is already initialized"},
	222: {"AnonymousRefundRequiresResolution", "Refund for anonymous escrow requires resolution"},
	223: {"AnonymousResolverNotSet", "Anonymous resolver address not set"},
	224: {"NotAnonymousEscrowVariant", "Escrow type mismatch: expected anonymous variant"},
	225: {"UseGetEscrowInfoV2ForAnonymous", "Please use get_escrow_info_v2 for anonymous escrows"},

	// 300-399: Identity / KYC Errors
	301: {"InvalidSignature", "Identity claim signature is invalid"},
	302: {"ClaimExpired", "Identity claim has expired"},
	303: {"UnauthorizedIssuer", "Claim issuer is not authorized"},
	304: {"InvalidClaimFormat", "Identity claim format is invalid"},
	305: {"TransactionExceedsLimit", "Transaction amount exceeds identity-based limit"},
	306: {"InvalidRiskScore", "Risk score is invalid or exceeds threshold"},
	307: {"InvalidTier", "Identity tier is invalid"},

	// 400-499: Program Escrow specific
	401: {"ProgramAlreadyExists", "A program with this ID already exists"},
	402: {"DuplicateProgramId", "Duplicate program ID found in batch"},
	403: {"InvalidBatchSizeProgram", "Batch size for program initialization is invalid"},
	
	// 1000+: Circuit Breaker
	1001: {"CircuitOpen", "Circuit breaker is open; operation rejected"},
}

// ContractErrorMessage returns a human-readable message for the given numeric error code.
func ContractErrorMessage(kind ContractKind, code uint32) string {
	if entry, ok := unifiedErrors[code]; ok {
		return entry.Message
	}
	return fmt.Sprintf("Unknown %s contract error (code %d)", kind, code)
}

// ContractErrorName returns the Rust enum variant name for logging and debugging.
func ContractErrorName(kind ContractKind, code uint32) string {
	if entry, ok := unifiedErrors[code]; ok {
		return entry.Name
	}
	return fmt.Sprintf("Unknown(%d)", code)
}

// AllCodes returns every registered numeric code.
func AllCodes(kind ContractKind) []uint32 {
	codes := make([]uint32, 0, len(unifiedErrors))
	for c := range unifiedErrors {
		codes = append(codes, c)
	}
	return codes
}
