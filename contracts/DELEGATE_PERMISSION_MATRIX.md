# Delegate Permission Matrix

This repository now supports optional per-resource delegates with scoped permissions.

## Role boundaries

Global admin:
- Separate from escrow depositors and program owners
- Can assign or revoke delegates
- Does not become the beneficiary or recipient implicitly

Escrow owner:
- Escrow depositor
- Can assign or revoke a delegate for that escrow

Program owner:
- `authorized_payout_key` for the program
- Can assign or revoke a delegate for that program

Delegate:
- Scoped to a single escrow or a single program
- Can act only when the relevant permission bit is present

## Permission bits

`DELEGATE_PERMISSION_RELEASE`
- Escrow: can call delegated release entrypoints
- Program: can call delegated payout and schedule release entrypoints

`DELEGATE_PERMISSION_REFUND`
- Escrow: can call delegated refund entrypoints
- Program: reserved for future refund-style flows

`DELEGATE_PERMISSION_UPDATE_META`
- Escrow: can update escrow metadata only
- Program: can update program metadata only

## Entry points

Escrow:
- `set_delegate`
- `revoke_delegate`
- `release_funds_by`
- `refund_by`
- `update_metadata`

Program:
- `set_program_delegate`
- `revoke_program_delegate`
- `single_payout_by`
- `batch_payout_by`
- `create_program_release_schedule_by`
- `trigger_program_releases_by`
- `release_program_schedule_manual_by`
- `update_program_metadata`