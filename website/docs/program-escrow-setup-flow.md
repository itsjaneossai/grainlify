---
description: Design guide for program escrow organizer setup and lock UX.
---

# Program Escrow Organizer Setup Flow

This page documents the organizer-facing UX for creating or configuring a program, wiring the authorized payout key, and locking a prize pool into escrow.

## Why this flow exists

Program organizers need a clear path from:

- program setup,
- to payout authority confirmation,
- to actual funds locked in an on-chain escrow.

The goal is to reduce ambiguity around:

- who can request payouts,
- which keys are authorized,
- what the remaining balance is,
- and what the chain actually guarantees.

## 1. Multi-step flow

### Step 1 — Program details

- Program name
- Program description
- Program category / theme
- Selected token asset
- Optional program metadata

Desktop: form with a left-side progress indicator and a right-side preview.
Mobile: stacked stepper with collapsible summary sections.

### Step 2 — Payout authority

- Display the authorized payout key address
- Show a friendly label for the payout authority (backend / service)
- Add explicit security copy:
  - “Only this payout key can request funds from the escrow contract.”
  - “Confirm you control this key before continuing.”

### Step 3 — Prize pool lock preview

- Amount to lock
- Wallet balance
- Selected asset
- Remaining balance after lock
- Network / wallet status

Security note: do not imply Grainlify custody. Use copy like:

- “Funds are held in the on-chain escrow contract.”
- “Once locked, only the authorized payout key can move them.”

### Step 4 — Confirm and lock funds

Confirmation content should include:

- Program ID
- Token
- Locked amount
- Authorized payout key
- Contract address or escrow identifier

Add a required confirmation checkbox or statement:

- “I confirm that I control the authorized payout key for this program.”

### Step 5 — Locked status

After successful lock:

- show total locked
- show remaining balance
- show on-chain escrow status
- show next actions (create bounties, invite maintainers, view program)

## 2. Copy deck

### Primary action copy

- `Review program escrow settings before locking funds.`
- `Lock funds into escrow`
- `Confirm and lock` 

### Security-sensitive copy

- `Only the authorized payout key can trigger payouts from this program escrow.`
- `The wallet listed here is the only key that can request funds from the contract.`
- `Grainlify does not custody funds; the contract does.`
- `This is not a guarantee of payout timing.`

### Non-guarantee phrasing

Avoid terms like `guaranteed payout` or `we will pay.`
Prefer:

- `Funds are escrowed on-chain.`
- `Only the authorized payout key can request payout transactions.`
- `Payouts happen when the backend submits a valid on-chain instruction.`

### Success state

- `Prize pool locked successfully.`
- `Remaining balance is fetched from the escrow contract.`

### Error states

- Wrong network:
  - `Your wallet is connected to the wrong network. Switch to [Network Name] before locking funds.`
- Insufficient balance:
  - `Your wallet balance is too low to lock the requested amount.`
- Re-init blocked:
  - `This program is already initialized. Update the existing program or create a new one.`
- Unauthorized payout key:
  - `The selected payout key is not authorized for this program.`
- Contract state mismatch:
  - `On-chain data differs from your selected settings. Refresh and try again.`

## 3. Screen-to-contract mapping

| Screen element | Contract concept | Source |
|---|---|---|
| Program ID | `program_id` | Chain-derived |
| Token asset | `asset` / `token` | Chain-derived |
| Authorized payout key | `authorized_payout_key` | Chain-derived |
| Locked amount | `lock_program_funds` input | Client-side prep |
| Total locked | escrow contract state | Chain-derived |
| Remaining balance | `remaining_balance` view | Chain-derived |
| Contract address | contract instance | Chain-derived |
| Program title / description | UI metadata | Client-side |

## 4. Client-side vs chain-derived fields

### Client-side

- Program title and description
- Selected token asset
- Desired lock amount
- Wallet connection status
- User-entered labels / notes
- Confirmation checkbox state

### Chain-derived

- Program identifier
- Authorized payout key
- Total funds locked into escrow
- Remaining balance
- Contract or program lock status
- Transaction hash / receipt

## 5. Risk: confirm you control payout key

Use a dedicated risk pattern on the payout authority step:

- Header: `Confirm you control the payout key`
- Body:
  - `The payout key below is the only key that can move funds from this escrow.`
  - `If you do not control this key, ask your security team before proceeding.`
- Action copy:
  - `I confirm I control the authorized payout key`

This is a critical security checkpoint that should not be hidden in smaller text.

## 6. Edge cases and validation notes

- Wrong network:
  - detect wallet network mismatch before submit
- Insufficient balance:
  - validate wallet balance and show live error
- Program already initialized:
  - use contract state to prevent duplicate init
- Unauthorized payout key mismatch:
  - validate on-chain `authorized_payout_key` before locking
- Wallet disconnect during submit:
  - show recoverable error and keep form state

### Validation guidance for engineers

- Query the contract for `remaining_balance` and `authorized_payout_key` at each relevant step.
- Do not treat user-entered payout key labels as authorization guarantees.
- Use on-chain values as the source of truth for locked and remaining amounts.
- Surface only the minimal security-sensitive fields needed to make the decision.

## 7. Accessibility notes

- Use semantic stepper markup and `aria-current` for current step.
- Announce validation errors using `aria-live="assertive"`.
- Label fields clearly and include helper text for security-sensitive fields.
- Ensure the confirm checkbox and submit button remain keyboard-accessible.
- On mobile, keep the current step visible in a sticky header.
- Provide a live region for transaction progress and final result.

## 8. Figma / exported frames

A design review should include:

- desktop stepper mockups,
- mobile flow screens,
- confirmation and error states,
- an explicit program escrow summary screen.

> TODO: attach Figma link or exported frames in the PR.
