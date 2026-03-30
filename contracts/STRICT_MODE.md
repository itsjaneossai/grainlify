# Strict Mode Configuration

Strict mode enables additional invariant checks, balance assertions, and diagnostic
events for development and staging networks. All strict-mode logic is compiled out
in production builds, so mainnet contracts pay zero extra gas.

## How It Works

Strict mode is controlled by the `strict-mode` Cargo feature flag. When enabled:

- **Balance invariants** are checked after every mutation (`lock_program_funds`,
  `batch_payout`, `single_payout`, `init_program`).
- **Pre-upgrade health checks** verify contract invariants before WASM upgrades.
- **Diagnostic events** are emitted under the `("strict", <tag>)` topic pair for
  off-chain monitoring.
- **Post-init assertions** verify the contract state is consistent after
  initialization.

When disabled (the default), all of the above are compiled out completely -- they
do not exist in the WASM binary and cost zero gas.

## Building

```bash
# Development / staging (strict checks enabled):
cargo build --target wasm32-unknown-unknown --release --features strict-mode

# Or using stellar CLI:
stellar contract build -- --features strict-mode

# Production / mainnet (strict checks compiled out):
cargo build --target wasm32-unknown-unknown --release

# Using the Makefile (bounty_escrow):
make build-strict   # dev/staging
make build           # mainnet
```

## Deployment Configuration

The `STRICT_MODE` variable in the deployment config files controls whether the
deploy script warns about or blocks strict-mode builds:

| File | `STRICT_MODE` | Purpose |
|------|--------------|---------|
| `scripts/config/testnet.env` | `"true"` | Enable extra checks on testnet |
| `scripts/config/mainnet.env` | `"false"` | Disabled -- deploy script will block mainnet deployment if enabled |

The deploy script (`scripts/deploy.sh`) will **refuse to deploy** to mainnet if
`STRICT_MODE="true"`, preventing accidental deployment of debug builds.

## Querying Strict Mode On-Chain

After deployment, call `is_strict_mode()` on the grainlify-core contract to verify
whether strict mode is active:

```bash
stellar contract invoke --id <contract_id> -- is_strict_mode
# Returns: true (testnet) or false (mainnet)
```

## What Gets Checked

### grainlify-core
- Post-`init_admin`: verifies contract is correctly initialized
- Pre-`upgrade`: runs `check_invariants()` and blocks upgrade if unhealthy
- `verify_invariants`: emits diagnostic events on invariant violations

### program-escrow
- `init_program`: asserts `total_funds == remaining_balance` after init
- `lock_program_funds`: asserts balance sane (`remaining <= total`, both >= 0)
- `single_payout`: asserts balance sane after payout
- `batch_payout`: asserts balance sane after batch payout

### bounty_escrow
- `assert_escrow`: emits diagnostic event on each successful invariant check
- `strict_assert_escrow` (strict-mode only): deep balance validation with
  detailed error messages

## Shared Utilities (`grainlify_core::strict_mode`)

| Function | Purpose |
|----------|---------|
| `is_enabled()` | Compile-time check: returns `true` when strict mode is on |
| `strict_assert(condition, msg)` | Panics if `condition` is false (no-op in production) |
| `strict_assert_eq(left, right, ctx)` | Panics if `left != right` (no-op in production) |
| `strict_assert_balance_sane(total, remaining, ctx)` | Validates escrow balance invariants |
| `strict_assert_no_overflow(current, delta, ctx)` | Validates addition won't overflow |
| `strict_emit(env, tag, message)` | Emits `("strict", tag)` diagnostic event |
| `strict_warn(env, warning)` | Emits `("strict", "warn")` warning event |
