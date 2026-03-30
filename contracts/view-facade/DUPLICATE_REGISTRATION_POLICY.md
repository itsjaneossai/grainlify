# View Facade — Duplicate Registration Policy #953

## Overview

This document specifies the behavior of the View Facade contract when `register()` is called with an address that is already in the registry. This closes **Issue #953**.

## Decision: Update Policy

**Policy:** When `register(address, kind, version)` is called with an address that already exists in the registry, the existing entry is **updated** with the new `kind` and `version` values, rather than creating a duplicate entry.

### Rationale

1. **Single-Source-of-Truth**: Each contract address appears exactly once in the registry
2. **Consistent Queries**: All view functions (`get_contract`, `list_contracts`, `contract_count`) return consistent results
3. **Operational Efficiency**: Admin can update version/kind without explicit deregister
4. **Insertion Order Preservation**: Updated entries retain their original position, maintaining deterministic registry ordering

## Implementation Details

### Modified `register()` Function

Location: [view-facade/src/lib.rs](view-facade/src/lib.rs)

**Key Changes:**
- Added O(n) lookup loop to search for existing address entries
- If found: updates the entry in-place via `registry.set(i, ...)`
- If not found: appends new entry via `registry.push_back(...)`
- Preserves insertion order (updated entries don't move to the end)

**Security Invariants Maintained:**
- ✅ Admin-only mutation: `admin.require_auth()` enforced
- ✅ No state corruption: vector operations are atomic
- ✅ No delegated privileges: only the immutable admin can register
- ✅ Initialization guard: `NotInitialized` error if called before `init()`

### Documentation

**Module Level** ([lib.rs](view-facade/src/lib.rs#L1-L45)):
- Added "Duplicate Registration Policy" section
- Explains single-source-of-truth guarantee
- Details query consistency semantics

**Function Level** ([register()` docs](view-facade/src/lib.rs#L260-L325)):
- Added "Duplicate Registration Policy" subsection
- Concrete examples showing update behavior
- Explicit semantics: "updated (not duplicated)"

## Test Coverage

**Total Tests: 22 (all passing)**

### Coverage Summary

| Category | Tests | Coverage Details |
|----------|-------|------------------|
| **Initialization** | 4 | init, get_admin, double-init, event emission |
| **Registration** | 6 | basic, all kinds, before init, admin auth, non-admin rejection |
| **Duplicate Handling** | 4 | update entry, update kind, update version, insertion order |
| **Listing/Counting** | 2 | initial count, list/count consistency |
| **Lookup** | 2 | found, not found |
| **Deregistration** | 3 | single, nonexistent (no-op), before init |
| **Authorization** | 2 | admin auth, non-admin rejection |
| **Edge Cases** | 1 | deregister then re-register |

### New Tests (Issue #953)

1. **`test_duplicate_register_updates_existing_entry`**
   - Verifies that registering the same address twice results in a single updated entry
   - Confirms count stays at 1 (no duplicate)
   - Validates new metadata is reflected

2. **`test_duplicate_register_updates_kind`**
   - Registers same address with different kinds
   - Verifies kind is updated while address/version consistency is maintained

3. **`test_duplicate_register_updates_version`**
   - Registers same address with different versions
   - Confirms version increments without affecting kind

4. **`test_duplicate_register_maintains_insertion_order`**
   - Registers 3 addresses (c1, c2, c3)
   - Re-registers c2 with new metadata
   - Verifies order remains c1, c2 (updated), c3 (not reordered)

5. **`test_deregister_then_register_appends_to_end`**
   - Edge case: deregister c1, then re-register c1
   - Confirms c1 appears at the end (treated as new after removal)
   - Validates deterministic behavior

## Security Analysis

### Admin-Only Enforcement

- `admin.require_auth()` is called before any mutation
- Non-admin signatures fail with explicit panic (validated in test)
- Admin address is immutable post-initialization

### State Invariants

- **Uniqueness**: Each address appears at most once in the registry
- **Ordering**: Insertion order is deterministic and preserved
- **Consistency**: `list_contracts()` and `contract_count()` agree on registry size
- **Atomicity**: Updates are single transaction operations

### Known Limitations

- O(n) scan required to find existing entries (acceptable for small registry, ~10-20 entries)
- If scalability > 1000 entries becomes a requirement, refactor to HashMap-based lookup

## Query Behavior After Update

### Example Workflow

```rust
// 1. Initial registration
register(ADDR_A, BountyEscrow, v1)
list_contracts() → [(ADDR_A, BountyEscrow, 1)]

// 2. Re-register same address with new kind/version
register(ADDR_A, GrainlifyCore, v3)
list_contracts() → [(ADDR_A, GrainlifyCore, 3)]  // Updated, not moved

// 3. Query consistency
contract_count() → 1
get_contract(ADDR_A) → Some((ADDR_A, GrainlifyCore, 3))
```

## Deregister Behavior

- Deregistering a non-existent address is still a **no-op** (idempotent)
- After deregister, the address can be re-registered, appearing at the **end** of the list
- This preserves "deregister, then re-register = new entry" semantics

## Backwards Compatibility

**Breaking Change**: Existing deployments relying on duplicate-entry behavior will see different results:
- Old: `register(ADDR, Kind1, 1)` + `register(ADDR, Kind2, 2)` → 2 entries
- New: same calls → 1 entry (last update wins)

**Migration Path**:
- Audit existing registries for duplicates
- Decide canonicial metadata for each address
- Deregister all but the desired entry, then re-register if needed
- Recommend timestamped migration script in admin tooling

## Testing Verification

```bash
$ cargo test -p view-facade --lib
Compiling view-facade v0.1.0
Finished `test` profile [unoptimized + debuginfo] target(s) in 0.81s
Running unittests src/lib.rs

running 22 tests
test test::test_deregister_before_init_rejected ... ok
test test::test_contract_count_initially_zero ... ok
test test::test_double_init_rejected ... ok
test test::test_get_admin_before_init_returns_none ... ok
test test::test_init_emits_initialized_event ... ok
test test::test_get_contract_not_found ... ok
test test::test_deregister_nonexistent_is_noop ... ok
test test::test_init_stores_admin ... ok
test test::test_duplicate_register_updates_kind ... ok
test test::test_admin_can_register_with_explicit_auth ... ok
test test::test_deregister_contract ... ok
test test::test_admin_can_deregister_with_explicit_auth ... ok
test test::test_duplicate_register_updates_existing_entry ... ok
test test::test_duplicate_register_updates_version ... ok
test test::test_deregister_then_register_appends_to_end ... ok
test test::test_list_and_count_contracts ... ok
test test::test_register_and_lookup_contract ... ok
test test::test_duplicate_register_maintains_insertion_order ... ok
test test::test_register_all_contract_kinds ... ok
test test::test_register_before_init_rejected ... ok
test test::test_non_admin_cannot_register - should panic ... ok
test test::test_non_admin_cannot_deregister - should panic ... ok

test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured

elapsed time: 0.68s
```

## Code Changes Summary

### Files Modified

| File | Changes |
|------|---------|
| `src/lib.rs` | 1. Update module-level docs (Duplicate Registration Policy section)<br/>2. Modify `register()` function to implement update policy<br/>3. Add detailed docstring with policy explanation<br/>4. Remove unused import |
| `src/test.rs` | 1. Replace `test_get_contract_returns_first_match_for_duplicate_addresses`<br/>2. Add 4 new duplicate-handling tests<br/>3. Add 1 edge-case test (deregister-reregister) |

### Lines of Code

- **Implementation**: ~30 lines (register function with update logic)
- **Documentation**: ~50 lines (module + function docs)
- **Tests**: ~130 lines (5 new test cases)
- **Total**: ~210 lines changed/added

## Compliance Checklist

- ✅ Behavior clearly defined (update existing entries)
- ✅ Comprehensive test coverage (22 tests, all passing)
- ✅ Security analysis documented (admin-only, state invariants)
- ✅ Documentation updated (module + function level)
- ✅ Edge cases tested (deregister-reregister, insertion order)
- ✅ Backward compatibility analyzed
- ✅ Test output included

## Related Issues

- Issue #574: Grainlify View Interface v1 (spec alignment)
- Issue #953: Smart contract: View facade — duplicate registration policy (this issue)

## Recommendations

1. **For Dashboards**: Update UI to handle single-entry-per-address assumption
2. **For Indexers**: Re-scan registry after admin version updates
3. **For Admin Tools**: Add check-duplicates utility before deployment
4. **For Future Work**: Consider HashMap-based registry if > 100 entries needed
