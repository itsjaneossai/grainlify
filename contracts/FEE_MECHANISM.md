# Escrow fee mechanism

This document describes how platform fees work in the two Soroban escrow contracts under `contracts/`.

## Bounty escrow (`bounty_escrow/contracts/escrow`)

### Configuration (instance storage)

- **`FeeConfig`** (global): `lock_fee_rate`, `release_fee_rate`, `lock_fixed_fee`, `release_fixed_fee`, `fee_recipient`, `fee_enabled`.
- **`TokenFeeConfig(Address)`** (optional): same shape per token; overrides the global config for escrows using that token.

Rates are **basis points** (`10_000` = 100%). Maximum rate is **`MAX_FEE_RATE`** (5_000 = 50%) for percentage components.

### Calculation

For a principal or payout amount `A`:

- Percentage component: `ceil(A * rate / 10_000)` (ceiling division so small deposits cannot zero out the fee).
- **Total fee** = `min(A, percentage_component + fixed_fee)` when `fee_enabled` is true.

### Where fees are collected

| Operation        | Basis for fee        | Notes                                      |
|-----------------|----------------------|--------------------------------------------|
| `lock_funds`    | Gross deposit        | Net escrow principal = deposit − fee      |
| `release_funds` | Full escrow principal| Contributor receives principal − fee        |
| `partial_release` | Gross payout line | Fee recipient + contributor split payout    |

### Admin / interface

- `update_fee_config(...)` — optional fields; unchanged parameters passed as `None`.
- `set_token_fee_config(token, ...)` — per-token override including fixed fees.
- `get_fee_config()` — read global config.

### Events

- `FeeCollected` includes `fee_rate`, `fee_fixed` (configured flat component), and total `amount` (fee actually transferred).
- `FeeConfigUpdated` includes all config fields after an update.

### Tests

- `combined_fee_pub` / `test_combined_fee_percentage_plus_fixed_capped` and `test_lock_and_release_fixed_fee_collection` in `src/test.rs`.

### Serialization goldens

`FeeConfig`, `FeeCollected`, and `FeeConfigUpdated` XDR layouts include fixed-fee fields. The serialization compatibility test (`serialization_compatibility_public_types_and_events`) validates these layouts. To regenerate `serialization_goldens.rs` after schema changes:

```bash
# From repo root (Unix-style env; adjust for your shell)
GRAINLIFY_PRINT_SERIALIZATION_GOLDENS=1 cargo test -p bounty-escrow --lib serialization_compatibility_public_types_and_events -- --nocapture
```

Copy the printed `EXPECTED` block into `serialization_goldens.rs`. See the module-level documentation in that file for schema versioning guidelines.

---

## Program escrow (`program-escrow`)

### Configuration

- **`FeeConfig`** in instance storage under `FeeCfg`: `lock_fee_rate`, `payout_fee_rate`, `lock_fixed_fee`, `payout_fixed_fee`, `fee_recipient`, `fee_enabled`.
- Default is **fees off**; `fee_recipient` defaults to the contract address until an admin sets it.

Rates use the same basis-point convention; **`MAX_FEE_RATE` = 1_000 (10%)** for this contract.

### Calculation

Same combined rule as bounty escrow: ceiling percentage plus fixed, capped to the gross amount for that operation.

### Where fees are collected

| Operation              | Basis                         |
|------------------------|-------------------------------|
| `initialize_program`   | Gross `initial_liquidity`     |
| `lock_program_funds`   | Gross lock amount             |
| `single_payout` / `batch_payout` | Gross per payout line |

Accounting: **`remaining_balance` decreases by the gross payout**; the winner receives **net** after fee. `PayoutRecord.amount` stores **net** paid to the recipient.

### Admin

- `update_fee_config(...)` — admin-only; invalid rates or negative fixed fees **panic** (consistent with other program-escrow admin entrypoints).
- `get_fee_config()` — read-only.

### Events

- **`FeeCol`** (`FeeCollectedEvent`): `operation` (`lock` or `payout`), `fee_amount`, `fee_rate_bps`, `fee_fixed`, `recipient`.

### Tests

See `program-escrow/src/test.rs`: `test_program_fee_zero_by_default_*`, `test_program_payout_fee_percentage_and_fixed`, `test_program_lock_fixed_fee_reduces_credited_balance`, `test_program_update_fee_config_disables_fees`.
