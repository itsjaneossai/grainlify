# Storage Key Namespace Audit and Collision Prevention

This document describes the storage key namespace system implemented to prevent storage collisions across Grainlify smart contracts.

## Overview

The Grainlify protocol uses multiple smart contracts that could potentially share storage namespaces. To prevent accidental storage collisions during contract upgrades and refactors, we implemented a comprehensive namespace isolation system.

## Namespace Strategy

### Contract Prefixes

Each contract uses a unique 2-3 character prefix followed by an underscore:

- **`PE_`** - Program Escrow contract
- **`BE_`** - Bounty Escrow contract  
- **`COMMON_`** - Shared constants and utilities

### Symbol Length Constraints

All symbols must fit within Soroban's 9-byte limit for `symbol_short!`:
- `PE_PrgData` (8 bytes) ✓
- `BE_FeeCfg` (8 bytes) ✓
- `COMMON_EVENT_VERSION_V2` (would exceed limit) ✗

## Storage Key Mapping

### Program Escrow (PE_ prefix)

| Symbol | Purpose | Original Name |
|--------|---------|---------------|
| `PE_PrgInit` | Program initialized event | `PrgInit` |
| `PE_FndsLock` | Funds locked event | `FndsLock` |
| `PE_BatLck` | Batch funds locked event | `BatLck` |
| `PE_BatRel` | Batch funds released event | `BatRel` |
| `PE_BatchPay` | Batch payout event | `BatchPay` |
| `PE_Payout` | Single payout event | `Payout` |
| `PE_PauseSt` | Pause state changed event | `PauseSt` |
| `PE_MaintSt` | Maintenance mode changed event | `MaintSt` |
| `PE_ROModeChg` | Read-only mode changed event | `ROModeChg` |
| `PE_pr_risk` | Risk flags updated event | `pr_risk` |
| `PE_PrgReg` | Program registry event | `ProgReg` |
| `PE_PrgRgd` | Program registered event | `ProgRgd` |
| `PE_RelSched` | Release scheduled event | `RelSched` |
| `PE_SchRel` | Schedule released event | `SchRel` |
| `PE_PrgDlgS` | Program delegate set event | `PrgDlgS` |
| `PE_PrgDlgR` | Program delegate revoked event | `PrgDlgR` |
| `PE_PrgMeta` | Program metadata updated event | `PrgMeta` |
| `PE_DspOpen` | Dispute opened event | `DspOpen` |
| `PE_DspRslv` | Dispute resolved event | `DspRslv` |
| `PE_ProgData` | Program data storage | `ProgData` |
| `PE_RcptID` | Receipt ID counter | `RcptID` |
| `PE_Scheds` | Release schedules storage | `Scheds` |
| `PE_RelHist` | Release history storage | `RelHist` |
| `PE_NxtSched` | Next schedule ID | `NxtSched` |
| `PE_ProgIdx` | Program index | `ProgIdx` |
| `PE_AuthIdx` | Authorization key index | `AuthIdx` |
| `PE_FeeCfg` | Fee configuration | `FeeCfg` |
| `PE_FeeCol` | Fee collected tracking | `FeeCol` |

### Bounty Escrow (BE_ prefix)

| Symbol | Purpose | Original Name |
|--------|---------|---------------|
| `BE_init` | Bounty initialized event | `init` |
| `BE_f_lock` | Funds locked event | `f_lock` |
| `BE_f_lock_anon` | Anonymous funds locked event | `f_lock_anon` |
| `BE_f_rel` | Funds released event | `f_rel` |
| `BE_f_ref` | Funds refunded event | `f_ref` |
| `BE_pub` | Escrow published event | `pub` |
| `BE_tk_issue` | Claim ticket issued event | `tk_issue` |
| `BE_tk_claim` | Claim ticket claimed event | `tk_claim` |
| `BE_maint` | Maintenance mode changed event | `maint` |
| `BE_pause` | Pause state changed event | `pause` |
| `BE_risk` | Risk flags updated event | `risk` |
| `BE_depr` | Deprecation state changed event | `depr` |
| `BE_Admin` | Contract administrator | `Admin` |
| `BE_Token` | Reward token contract | `Token` |
| `BE_Version` | Contract version | `Version` |
| `BE_EscrowIdx` | Global escrow index | `EscrowIndex` |
| `BE_DepositorIdx` | Depositor address index | `DepositorIndex` |
| `BE_EscrowFrz` | Escrow freeze records | `EscrowFreeze` |
| `BE_AddrFrz` | Address freeze records | `AddressFreeze` |
| `BE_FeeCfg` | Fee configuration | `FeeConfig` |
| `BE_RefundApp` | Refund approvals | `RefundApproval` |
| `BE_Reentrancy` | Reentrancy guard state | `ReentrancyGuard` |
| `BE_Multisig` | Multisig configuration | `MultisigConfig` |
| `BE_ReleaseApp` | Release approvals | `ReleaseApproval` |
| `BE_PendingClaim` | Pending claim records | `PendingClaim` |
| `BE_TicketCtr` | Claim ticket counter | `TicketCounter` |
| `BE_ClaimTicket` | Individual claim tickets | `ClaimTicket` |
| `BE_ClaimTicketIdx` | Claim ticket index | `ClaimTicketIndex` |
| `BE_BenTickets` | Beneficiary ticket mapping | `BeneficiaryTickets` |
| `BE_ClaimWindow` | Claim window configuration | `ClaimWindow` |
| `BE_PauseFlags` | Pause state flags | `PauseFlags` |
| `BE_AmountPol` | Amount policy limits | `AmountPolicy` |
| `BE_CapNonce` | Capability nonce counter | `CapabilityNonce` |
| `BE_Capability` | Capability token storage | `Capability` |
| `BE_NonTransRew` | Non-transferable rewards flag | `NonTransferableRewards` |
| `BE_DeprecationSt` | Deprecation state | `DeprecationState` |
| `BE_PartFilter` | Participant filter mode | `ParticipantFilterMode` |
| `BE_AnonResolver` | Anonymous escrow resolver | `AnonymousResolver` |
| `BE_TokenFeeCfg` | Per-token fee configuration | `TokenFeeConfig` |
| `BE_ChainId` | Chain identifier | `ChainId` |
| `BE_NetworkId` | Network identifier | `NetworkId` |
| `BE_MaintMode` | Maintenance mode flag | `MaintenanceMode` |
| `BE_GasBudget` | Gas budget configuration | `GasBudgetConfig` |
| `BE_TimelockCfg` | Timelock configuration | `TimelockConfig` |
| `BE_PendingAction` | Pending timelock actions | `PendingAction` |
| `BE_ActionCtr` | Action counter | `ActionCounter` |

## Shared Constants

Constants shared across contracts use the `shared` module:

```rust
pub const EVENT_VERSION_V2: u32 = 2;
pub const BASIS_POINTS: i128 = 10_000;
pub const RISK_FLAG_HIGH_RISK: u32 = 1 << 0;
pub const RISK_FLAG_UNDER_REVIEW: u32 = 1 << 1;
pub const RISK_FLAG_RESTRICTED: u32 = 1 << 2;
pub const RISK_FLAG_DEPRECATED: u32 = 1 << 3;
```

## Collision Prevention Mechanisms

### 1. Compile-Time Assertions

The `assert_storage_namespace!` macro validates prefixes at compile time:

```rust
assert_storage_namespace!("PE_PrgData", "PE_");  // ✓ Compiles
assert_storage_namespace!("BE_Admin", "BE_");     // ✓ Compiles
assert_storage_namespace!("Admin", "PE_");        // ✗ Compile error
```

### 2. Runtime Validation

The `validate_storage_key()` function checks namespace compliance during testing:

```rust
let result = validation::validate_storage_key(symbol, "PE_");
assert!(result.is_ok());
```

### 3. Comprehensive Test Suite

The test suite validates:
- Namespace compliance for all symbols
- Cross-namespace isolation
- Duplicate symbol detection
- Symbol length constraints
- Migration safety scenarios

## Migration Safety

### Upgrade Checklist

When adding new storage keys:

1. **Use Correct Prefix**: Always use the appropriate contract prefix (`PE_` or `BE_`)
2. **Check Length**: Ensure symbol fits within 9-byte limit
3. **Update Tests**: Add new keys to test suite
4. **Documentation**: Update the key mapping table
5. **Version Control**: Consider storage schema version implications

### Backward Compatibility

- Existing keys maintain their original namespace
- New keys must follow namespace rules
- Storage migrations should preserve namespace isolation

## Security Benefits

1. **Collision Prevention**: No accidental storage key overlap between contracts
2. **Upgrade Safety**: Clear namespace rules prevent migration errors
3. **Audit Trail**: Comprehensive documentation of all storage keys
4. **Testing Coverage**: Automated validation of namespace compliance
5. **Developer Clarity**: Clear naming conventions reduce errors

## Implementation Details

### File Structure

```
contracts/
├── src/
│   ├── lib.rs                    # Main library entry point
│   ├── storage_key_audit.rs       # Namespace system implementation
│   └── storage_collision_tests.rs # Comprehensive test suite
├── program-escrow/
│   └── src/lib.rs              # Uses PE_ prefixed keys
└── bounty_escrow/
    └── contracts/escrow/src/lib.rs # Uses BE_ prefixed keys
```

### Dependencies

```toml
[dependencies]
grainlify-contracts = { path = "../" }
```

### Usage

```rust
use grainlify_contracts::storage_key_audit::{
    program_escrow, bounty_escrow, shared, validation,
};

// Use namespaced keys
let program_data_key = program_escrow::PROGRAM_DATA;
let bounty_admin_key = bounty_escrow::ADMIN;
let event_version = shared::EVENT_VERSION_V2;

// Validate namespace compliance
validation::validate_storage_key(program_data_key, "PE_")?;
```

## Testing

Run the collision test suite:

```bash
cd contracts
cargo test storage_collision_tests
```

Key test categories:
- `test_program_escrow_namespace_compliance`
- `test_bounty_escrow_namespace_compliance`
- `test_cross_namespace_isolation`
- `test_no_duplicate_symbols`
- `test_storage_migration_safety`
- `test_symbol_length_constraints`

## Future Considerations

1. **Additional Contracts**: New contracts should use unique prefixes (e.g., `GE_` for Governance)
2. **Dynamic Namespaces**: Consider runtime namespace registration for extensibility
3. **Cross-Chain Support**: Ensure namespace isolation across different chains
4. **Tooling**: Develop CLI tools for namespace validation and key generation

## Conclusion

This namespace system provides robust protection against storage key collisions while maintaining developer productivity through clear conventions and automated validation.
