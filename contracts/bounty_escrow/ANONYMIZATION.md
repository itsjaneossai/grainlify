# Optional Anonymization and Pseudonymization (Issue #680)

This document describes the optional anonymization and pseudonymization of on-chain data in the bounty escrow contract: storing hashed or committed identifiers instead of plaintext addresses where required for privacy and compliance.

## Overview

- **Privacy / compliance**: Reduce PII on-chain by storing a 32-byte **commitment** (e.g. hash of beneficiary/depositor address) instead of the plain address where desired.
- **Verification**: Hashed or committed values still allow authorized parties to verify or resolve off-chain (e.g. off-chain lookup by commitment).
- **Resolution path**: Refunds for anonymous escrows are performed via a configured **anonymous resolver** that submits the resolved recipient (signed instruction pattern).

## Components

### 1. Anonymous depositor (lock)

- **Entrypoint**: `lock_funds_anonymous(env, depositor, depositor_commitment, bounty_id, amount, deadline)`
- **Behavior**: The `depositor` must authorize and transfer tokens; only `depositor_commitment` (32 bytes) is stored on-chain. The depositor address is used only for the transfer in this call and is **not** stored.
- **Events**: `FundsLockedAnon` is emitted with `depositor_commitment` (no address).
- **Index**: Anonymous escrows are **not** added to `DepositorIndex(Address)` (no address to index).

### 2. Views

- **`get_escrow_info(bounty_id)`**: For anonymous bounties returns `UseGetEscrowInfoV2ForAnonymous`. Use the v2 view instead.
- **`get_escrow_info_v2(bounty_id)`**: Returns `EscrowInfo` with `depositor: AnonymousParty`:
  - `AnonymousParty::Address(addr)` for normal escrows
  - `AnonymousParty::Commitment(BytesN<32>)` for anonymous escrows

### 3. Release (unchanged for anonymity)

- **Release** (full, partial, or with capability): Still takes a **contributor/recipient address** as argument. Funds are sent to that address. No change for anonymous escrows; the contract does not need to know the depositor to release to an admin-designated contributor.

### 4. Refund and resolution

- **Normal escrow**: `refund(bounty_id)` sends funds back to the stored depositor address.
- **Anonymous escrow**: `refund(bounty_id)` returns `AnonymousRefundNeedsResolver`. Refund is only possible via:
  - **`refund_resolved(env, bounty_id, recipient)`**
    - Callable only by the configured **anonymous resolver** (admin sets it with `set_anonymous_resolver`).
    - Resolver is expected to resolve the commitment off-chain (e.g. backend lookup or ZK proof) and pass the true `recipient` address.
    - Contract transfers to `recipient` and emits `FundsRefunded` with that recipient.

### 5. Claim tickets

- Anonymous **depositor** escrows still support **claim tickets**: admin can issue tickets to a concrete beneficiary address; the beneficiary claims as usual. Only the depositor identity is hidden on-chain.

## Trust model and resolution path

1. **Anonymous resolver**
   - A single address, set by admin via `set_anonymous_resolver(Some(resolver_address))`.
   - Only this address may call `refund_resolved(bounty_id, recipient)`.
   - Trust: the resolver must correctly map commitment → real depositor and pass the correct `recipient`; the contract does not verify the mapping.

2. **Resolution options**
   - **Authorized backend**: Resolver is a backend service that holds the mapping (commitment → address) and calls `refund_resolved` with the resolved address after verifying the depositor (e.g. KYC or signed request).
   - **Zero-knowledge**: In the future, resolution could be implemented via a ZK proof that the recipient corresponds to the commitment, with the contract verifying the proof; current design uses a trusted resolver.

3. **Commitment format**
   - `depositor_commitment` is an opaque 32-byte value (e.g. `hash(depositor_address)` or `hash(depositor_address || nonce)`). The contract does not interpret it; off-chain systems define how commitments are generated and resolved.

## Configuration

- **Set resolver**: Admin calls `set_anonymous_resolver(env, Some(resolver_address))`.
- **Clear resolver**: Admin calls `set_anonymous_resolver(env, None)`.

## Errors

- `AnonymousRefundNeedsResolver`: Refund was attempted with `refund(bounty_id)` on an anonymous escrow; use `refund_resolved(bounty_id, recipient)` with resolver auth.
- `NotAnonymousResolver`: Caller is not the configured anonymous resolver.
- `NotAnonymousEscrow`: `refund_resolved` was called for a non-anonymous bounty (use `refund` instead).
- `AnonymousResolverNotSet`: No resolver configured; cannot call `refund_resolved`.
- `UseGetEscrowInfoV2ForAnonymous`: Use `get_escrow_info_v2` for this bounty (depositor is a commitment).

## Privacy and compliance notes

- With anonymous lock, no depositor address is stored or emitted; only the commitment appears in storage and in `FundsLockedAnon`.
- Refunds still route to the correct party via the resolver’s signed call (`refund_resolved` with resolver auth), which acts as the signed instruction.
- Release and claim flows already use admin-designated or ticket beneficiary addresses; they do not expose depositor identity.
