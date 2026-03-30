# View Facade Registry Limits and Operational Guidance

## Overview

The View Facade contract implements bounded registry growth mitigations to prevent unbounded storage consumption and ensure predictable gas costs. This document outlines the operational limits, pagination strategy, and guidance for indexers and administrators.

## Registry Configuration

### Maximum Capacity

- **Hard Limit**: `MAX_REGISTRY_SIZE = 1000` contracts
- **Enforcement**: Strict rejection of registrations beyond capacity
- **Error**: `FacadeError::RegistryFull` when limit is reached
- **Recovery**: Deregister existing entries to free slots

### Rationale for 1000 Entry Limit

1. **Gas Efficiency**: Each registry entry requires storage reads/writes
2. **Indexer Friendliness**: Bounded size enables predictable pagination
3. **Operational Safety**: Prevents storage exhaustion attacks
4. **Future Upgradeability**: Can be increased via contract upgrade if needed

## Pagination Strategy

### New Paginated API

```rust
list_contracts(offset: Option<u32>, limit: Option<u32>) -> Result<Vec<RegisteredContract>, FacadeError>
```

### Pagination Parameters

- **`offset`**: Number of entries to skip (default: 0)
- **`limit`**: Maximum entries to return (default: all remaining)
- **Validation**: `offset > total` or `limit = 0` returns `InvalidPagination` error

### Pagination Workflow

1. Call `contract_count()` to get total entries
2. Calculate pages: `total_entries / page_size`
3. Fetch each page: `list_contracts(offset, limit)`
4. Stop when returned vec length < limit

### Example Pagination Code

```javascript
// JavaScript/TypeScript example for indexers
async function paginateRegistry(facadeContract, pageSize = 100) {
    const total = await facadeContract.contract_count();
    const allEntries = [];
    
    for (let offset = 0; offset < total; offset += pageSize) {
        const page = await facadeContract.list_contracts(offset, pageSize);
        allEntries.push(...page);
        
        // If we got fewer than pageSize, we're done
        if (page.length < pageSize) break;
    }
    
    return allEntries;
}
```

## Operational Guidance for Indexers

### Recommended Page Size

- **Default**: 100 entries per page
- **Maximum**: 200 entries per page (to stay within gas limits)
- **Minimum**: 10 entries per page (to avoid excessive calls)

### Indexing Strategy

1. **Initial Sync**: Use pagination with larger page sizes (100-200)
2. **Incremental Updates**: Use `contract_count()` to detect changes
3. **Change Detection**: Compare registry size with previous sync
4. **Full Sync Frequency**: Perform full pagination sync daily or weekly

### Error Handling

- **RegistryFull**: Log warning, notify admin of capacity issue
- **InvalidPagination**: Validate offset/limit parameters before retry
- **Network Errors**: Implement exponential backoff for retries

### Performance Considerations

- **Gas Costs**: Pagination reduces gas cost per call
- **Network Latency**: Fewer large calls vs many small calls
- **Memory Usage**: Process pages sequentially to limit memory footprint

## Administrator Guidance

### Capacity Management

1. **Monitor Usage**: Regularly check `contract_count()`
2. **Cleanup**: Deregister inactive or obsolete contracts
3. **Planning**: Consider future growth when approaching 80% capacity

### Registration Best Practices

1. **Check for Duplicates**: Use `get_contract()` before registering
2. **Batch Operations**: Register multiple contracts in sequence
3. **Error Handling**: Handle `RegistryFull` gracefully

### Deregistration Strategy

1. **Audit Registry**: Review for inactive contracts
2. **Prioritize**: Remove oldest or least important entries first
3. **Documentation**: Keep external records of deregistered contracts

## Migration from Legacy API

### Legacy Function

```rust
// Deprecated - returns entire registry
list_contracts() -> Vec<RegisteredContract>
```

### Migration Path

1. **Immediate**: Use `list_contracts_all()` for existing functionality
2. **Recommended**: Implement pagination for new integrations
3. **Timeline**: Plan migration before registry grows beyond 200 entries

### Compatibility Wrapper

```rust
// Legacy compatibility - use for existing code
list_contracts_all() -> Vec<RegisteredContract>
```

## Security Considerations

### Attack Vectors Mitigated

1. **Storage Exhaustion**: Hard cap prevents unbounded growth
2. **Gas Griefing**: Predictable costs for all operations
3. **Denial of Service**: Pagination prevents large response attacks

### Monitoring Recommendations

1. **Registry Size**: Alert when > 80% capacity
2. **Registration Rate**: Monitor for unusual spikes
3. **Failed Operations**: Track `RegistryFull` errors

## Testing and Validation

### Test Coverage Requirements

- **Capacity Tests**: Verify behavior at max capacity
- **Pagination Tests**: Validate offset/limit combinations
- **Error Tests**: Confirm proper error responses
- **Integration Tests**: End-to-end pagination workflows

### Performance Benchmarks

- **Max Registry**: 1000 entries with pagination
- **Page Size**: 100 entries optimal balance
- **Gas Costs**: Predictable within limits

## Future Enhancements

### Potential Improvements

1. **Dynamic Limits**: Configurable max size via admin
2. **Contract Types**: Pagination by contract kind
3. **Time-based Queries**: Filter by registration timestamp
4. **Sorting Options**: Different orderings beyond insertion order

### Upgrade Path

- **Contract Upgrade**: Can increase `MAX_REGISTRY_SIZE`
- **Backward Compatibility**: Maintain existing API during upgrade
- **Migration Planning**: Coordinate with indexer operators

## Support and Troubleshooting

### Common Issues

1. **RegistryFull Error**: Deregister entries or request capacity increase
2. **InvalidPagination**: Check offset/limit parameters
3. **High Gas Costs**: Use smaller page sizes

### Contact Information

- **Technical Support**: Create GitHub issue with error details
- **Capacity Requests**: Submit enhancement request for limit increase
- **Indexer Support**: Contact integration team for pagination guidance
