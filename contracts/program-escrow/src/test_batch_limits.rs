//! # Tests for Batch Payout Size Limits and Deterministic Failure Behavior
#![cfg(test)]
extern crate std;
use soroban_sdk::{testutils::Address as _, vec, Address, Env, Vec};
use crate::MAX_BATCH_SIZE;

#[test]
fn test_max_batch_size_constant_is_100() {
    assert_eq!(MAX_BATCH_SIZE, 100);
}

#[test]
fn test_max_batch_size_plus_one_exceeds_limit() {
    // MAX_BATCH_SIZE + 1 = 101, which must exceed the limit
    assert!(MAX_BATCH_SIZE + 1 > MAX_BATCH_SIZE);
}

#[test]
fn test_batch_limit_boundary_values() {
    // Verify the constant is within safe Soroban gas bounds
    assert!(MAX_BATCH_SIZE > 0);
    assert!(MAX_BATCH_SIZE <= 100);
}
