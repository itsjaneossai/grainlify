//! Tests for `get_version`, `get_version_semver_string`,
//! `get_version_numeric_encoded`, and `require_min_version`.
//!
//! # Coverage goals
//! - Zero / uninitialized state
//! - Legacy single-digit storage values (1, 2, …)
//! - Fully-encoded values (major*10_000 + minor*100 + patch)
//! - Boundary and large values
//! - `require_min_version` happy path and both panic branches

extern crate std;

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

use crate::{ContractError, GrainlifyContract, GrainlifyContractClient};

// ── helpers ──────────────────────────────────────────────────────────────────

fn setup() -> (Env, GrainlifyContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, GrainlifyContract);
    // SAFETY: the client borrows the env; we keep env alive for the test.
    let client = GrainlifyContractClient::new(&env, &id);
    (env, client)
}

fn init(client: &GrainlifyContractClient, env: &Env) -> Address {
    let admin = Address::generate(env);
    client.init_admin(&admin);
    admin
}

fn semver_str(client: &GrainlifyContractClient, env: &Env) -> std::string::String {
    let sdk_str = client.get_version_semver_string();
    let len = sdk_str.len() as usize;
    let mut buf = std::vec![0u8; len];
    sdk_str.copy_into_slice(&mut buf);
    std::string::String::from_utf8(buf).unwrap()
}

// ── get_version ───────────────────────────────────────────────────────────────

/// Before init the stored version key is absent; must return 0.
#[test]
fn get_version_returns_zero_before_init() {
    let (_, client) = setup();
    assert_eq!(client.get_version(), 0);
}

/// After `init_admin` the version is set to the compile-time `VERSION` constant (2).
#[test]
fn get_version_returns_initial_version_after_init() {
    let (env, client) = setup();
    init(&client, &env);
    assert_eq!(client.get_version(), 2);
}

/// `set_version` round-trips correctly.
#[test]
fn get_version_reflects_set_version() {
    let (env, client) = setup();
    init(&client, &env);
    client.set_version(&10_100u32);
    assert_eq!(client.get_version(), 10_100);
}

// ── get_version_numeric_encoded ───────────────────────────────────────────────

/// Legacy value `1` → `10_000`.
#[test]
fn numeric_encoded_promotes_legacy_1() {
    let (env, client) = setup();
    init(&client, &env);
    client.set_version(&1u32);
    assert_eq!(client.get_version_numeric_encoded(), 10_000);
}

/// Legacy value `2` → `20_000`.
#[test]
fn numeric_encoded_promotes_legacy_2() {
    let (env, client) = setup();
    init(&client, &env);
    // init sets VERSION=2; numeric_encoded should return 20_000
    assert_eq!(client.get_version_numeric_encoded(), 20_000);
}

/// Already-encoded value is returned unchanged.
#[test]
fn numeric_encoded_passthrough_for_encoded_value() {
    let (env, client) = setup();
    init(&client, &env);
    client.set_version(&10_305u32); // 1.3.5
    assert_eq!(client.get_version_numeric_encoded(), 10_305);
}

/// Zero stays zero.
#[test]
fn numeric_encoded_zero_stays_zero() {
    let (_, client) = setup();
    assert_eq!(client.get_version_numeric_encoded(), 0);
}

/// Boundary: value 9_999 (< 10_000) is treated as legacy major → 9_999 * 10_000.
#[test]
fn numeric_encoded_boundary_9999_is_legacy() {
    let (env, client) = setup();
    init(&client, &env);
    client.set_version(&9_999u32);
    assert_eq!(client.get_version_numeric_encoded(), 9_999u32.saturating_mul(10_000));
}

/// Boundary: value 10_000 is already encoded → returned as-is.
#[test]
fn numeric_encoded_boundary_10000_passthrough() {
    let (env, client) = setup();
    init(&client, &env);
    client.set_version(&10_000u32);
    assert_eq!(client.get_version_numeric_encoded(), 10_000);
}

// ── get_version_semver_string ─────────────────────────────────────────────────

/// Uninitialized → "0.0.0".
#[test]
fn semver_string_zero_is_0_0_0() {
    let (env, client) = setup();
    assert_eq!(semver_str(&client, &env), "0.0.0");
}

/// Legacy `1` → "1.0.0".
#[test]
fn semver_string_legacy_1_is_1_0_0() {
    let (env, client) = setup();
    init(&client, &env);
    client.set_version(&1u32);
    assert_eq!(semver_str(&client, &env), "1.0.0");
}

/// Encoded `10_000` → "1.0.0".
#[test]
fn semver_string_encoded_10000_is_1_0_0() {
    let (env, client) = setup();
    init(&client, &env);
    client.set_version(&10_000u32);
    assert_eq!(semver_str(&client, &env), "1.0.0");
}

/// Encoded `10_100` → "1.1.0".
#[test]
fn semver_string_encoded_10100_is_1_1_0() {
    let (env, client) = setup();
    init(&client, &env);
    client.set_version(&10_100u32);
    assert_eq!(semver_str(&client, &env), "1.1.0");
}

/// Encoded `10_001` → "1.0.1".
#[test]
fn semver_string_encoded_10001_is_1_0_1() {
    let (env, client) = setup();
    init(&client, &env);
    client.set_version(&10_001u32);
    assert_eq!(semver_str(&client, &env), "1.0.1");
}

/// Encoded `20_000` → "2.0.0" (default after init).
#[test]
fn semver_string_default_init_is_2_0_0() {
    let (env, client) = setup();
    init(&client, &env);
    assert_eq!(semver_str(&client, &env), "2.0.0");
}

/// Arbitrary encoded value `20_305` → "2.3.5".
#[test]
fn semver_string_arbitrary_encoded_2_3_5() {
    let (env, client) = setup();
    init(&client, &env);
    client.set_version(&20_305u32);
    assert_eq!(semver_str(&client, &env), "2.3.5");
}

/// Multi-digit minor/patch: `101_099` → "10.10.99".
#[test]
fn semver_string_large_components() {
    let (env, client) = setup();
    init(&client, &env);
    // 10*10_000 + 10*100 + 99 = 101_099
    client.set_version(&101_099u32);
    assert_eq!(semver_str(&client, &env), "10.10.99");
}

// ── require_min_version ───────────────────────────────────────────────────────

/// Exact match passes.
#[test]
fn require_min_version_exact_match_passes() {
    let (env, client) = setup();
    init(&client, &env);
    // VERSION=2 → encoded 20_000
    client.require_min_version(&20_000u32);
}

/// Lower minimum passes.
#[test]
fn require_min_version_lower_min_passes() {
    let (env, client) = setup();
    init(&client, &env);
    client.require_min_version(&10_000u32); // 1.0.0 ≤ 2.0.0
}

/// Zero minimum always passes (any initialised contract satisfies it).
#[test]
fn require_min_version_zero_min_passes() {
    let (env, client) = setup();
    init(&client, &env);
    client.require_min_version(&0u32);
}

/// Version strictly below minimum panics with "version_too_low".
#[test]
#[should_panic(expected = "version_too_low")]
fn require_min_version_too_low_panics() {
    let (env, client) = setup();
    init(&client, &env);
    // Contract is at 2.0.0 (20_000); require 3.0.0 (30_000) → panic
    client.require_min_version(&30_000u32);
}

/// Uninitialised contract (version == 0) panics with NotInitialized error code.
#[test]
#[should_panic]
fn require_min_version_uninitialized_panics() {
    let (_, client) = setup();
    // version is 0 → should panic with ContractError::NotInitialized code
    client.require_min_version(&10_000u32);
}

/// After `set_version` to a higher value, a previously-failing min check passes.
#[test]
fn require_min_version_passes_after_upgrade() {
    let (env, client) = setup();
    init(&client, &env);
    client.set_version(&30_000u32); // 3.0.0
    client.require_min_version(&30_000u32);
    client.require_min_version(&20_000u32);
    client.require_min_version(&10_000u32);
}

/// Patch-level minimum: 2.0.1 (20_001) fails against a 2.0.0 contract.
#[test]
#[should_panic(expected = "version_too_low")]
fn require_min_version_patch_level_too_low() {
    let (env, client) = setup();
    init(&client, &env);
    // Contract at 2.0.0 (20_000); require 2.0.1 (20_001)
    client.require_min_version(&20_001u32);
}

/// Minor-level minimum: 2.1.0 (20_100) fails against a 2.0.0 contract.
#[test]
#[should_panic(expected = "version_too_low")]
fn require_min_version_minor_level_too_low() {
    let (env, client) = setup();
    init(&client, &env);
    client.require_min_version(&20_100u32);
}

// ── consistency: numeric_encoded ↔ semver_string ─────────────────────────────

/// Round-trip: encode then decode must be consistent for a set of versions.
#[test]
fn semver_string_consistent_with_numeric_encoded() {
    let cases: &[(u32, &str)] = &[
        (0, "0.0.0"),
        (10_000, "1.0.0"),
        (10_001, "1.0.1"),
        (10_100, "1.1.0"),
        (20_000, "2.0.0"),
        (20_305, "2.3.5"),
        (30_099, "3.0.99"),
    ];

    for &(encoded, expected_str) in cases {
        let (env, client) = setup();
        init(&client, &env);
        client.set_version(&encoded);

        // numeric_encoded passthrough for already-encoded values
        assert_eq!(
            client.get_version_numeric_encoded(),
            encoded,
            "numeric_encoded mismatch for {encoded}"
        );

        // semver string matches expected
        assert_eq!(
            semver_str(&client, &env),
            expected_str,
            "semver_string mismatch for encoded={encoded}"
        );
    }
}
