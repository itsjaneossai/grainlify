# Front-Running and Ordering Tests

## Overview
This test suite validates that the bounty escrow contract properly handles race conditions and front-running scenarios where multiple parties attempt to perform operations on the same escrow simultaneously.

## Race Assumptions
- Soroban state transitions are atomic per transaction.
- A "race" is represented by two or more transactions targeting the same `bounty_id` in close succession.
- Ordering is transaction-order dependent: the first successful state transition is authoritative.
- Security invariant: once escrow state moves out of `Locked`, later conflicting operations must fail and must not move funds.

## Test Scenarios

### 1. Release Races
**Tests**: `test_release_race_first_recipient_wins_order_ab`, `test_release_race_first_recipient_wins_order_ba`

Validates that when multiple parties attempt to release the same bounty:
- First release succeeds
- Second release fails with `FundsNotLocked`
- Only the first recipient receives funds
- Final state is `Released`

### 2. Auto-Refund Race
**Test**: `test_auto_refund_race_first_caller_wins`

Validates that when multiple parties attempt to trigger auto-refund after deadline:
- First refund succeeds
- Second refund fails with `FundsNotLocked`
- Funds return to original depositor
- No funds go to callers who triggered refund
- Final state is `Refunded`

### 3. Partial Release Double-Spend Prevention
**Test**: `test_partial_release_race_prevents_double_spend`

Validates that partial releases properly track `remaining_amount`:
- First partial release succeeds and updates remaining_amount
- Attempt to release more than remaining fails with `InsufficientFunds`
- Recipient balance reflects only successful releases
- Prevents over-payment

### 4. Batch Release Atomicity
**Test**: `test_batch_release_prevents_double_release`

Validates that batch operations are atomic:
- First batch release succeeds for all items
- Second batch release fails with `FundsNotLocked`
- Recipients receive funds exactly once
- No double-payment occurs

### 5. Refund vs Release Race
**Test**: `test_refund_vs_release_race_first_wins`

Validates mutual exclusivity of refund and release:
- First operation (refund) succeeds
- Second operation (release) fails with `FundsNotLocked`
- Funds go to depositor, not recipient
- Final state is `Refunded`

### 6. Authorize Claim Race
**Test**: `test_authorize_claim_race_last_authorization_wins`

Validates claim authorization behavior:
- Multiple authorizations can occur
- Last authorization overwrites previous ones
- Only the last authorized recipient can claim
- Claim succeeds for authorized recipient

### 7. Unauthorized Claim Prevention
**Test**: `test_claim_race_unauthorized_fails`

Validates that only authorized claimants can claim:
- Authorized claimant successfully claims
- Unauthorized parties cannot claim
- Funds go only to authorized recipient

### 8. Release vs Late Claim Authorization
**Test**: `test_authorize_claim_after_release_fails_deterministically`

Validates deterministic rejection when release wins first:
- Release succeeds first and transitions escrow to `Released`
- Later `authorize_claim` attempt fails with `FundsNotLocked`
- No funds move to the late claimant

## Key Protections

1. **Idempotency**: Operations that should only happen once (release, refund) properly reject duplicate attempts
2. **State Consistency**: `remaining_amount` and status are always consistent
3. **Atomicity**: Batch operations either fully succeed or fully fail
4. **Authorization**: Only authorized parties can perform sensitive operations
5. **First-Wins**: For competing operations, first transaction wins and subsequent ones fail with deterministic errors

## Running Tests
```bash
cargo test test_front_running --lib
```

## Test Results
All 9 tests pass, confirming proper handling of race conditions and front-running scenarios.
