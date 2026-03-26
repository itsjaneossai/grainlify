# Frozen Balance Behavior

This contract supports explicit admin freezes at two levels:

- `freeze_escrow(bounty_id, reason)` blocks release and refund actions for one escrow id.
- `freeze_address(address, reason)` blocks release and refund actions for escrows owned by that depositor.

Read-only queries continue to work while a freeze is active:

- `get_escrow_info`
- `get_escrow_freeze_record`
- `get_address_freeze_record`

Security notes:

- Freeze checks run before any outbound token transfer.
- Escrow-level freezes return `Error::EscrowFrozen`.
- Address-level freezes return `Error::AddressFrozen`.
- These checks are enforced on single-release, partial-release, batch-release, claim, and refund paths.
- Contract-level freeze errors are returned before the code reaches token transfer calls, so token-interface errors are not masked by late state transitions.
