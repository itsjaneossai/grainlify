//! # Grainlify Contracts Library
//!
//! This crate provides shared utilities and storage key management for Grainlify smart contracts.
//! It includes namespace protection, collision detection, and common constants.

pub mod storage_key_audit;

#[cfg(test)]
mod storage_collision_tests;
