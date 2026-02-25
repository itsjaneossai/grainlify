extern crate std;

use soroban_sdk::{
    xdr::{FromXdr, Hash, ScAddress, ToXdr},
    Address, BytesN, Env, IntoVal, String as SdkString, Symbol, TryFromVal, Val,
};

use crate::governance::*;
use crate::monitoring::*;
use crate::*;

mod serialization_goldens {
    include!("serialization_goldens.rs");
}
use serialization_goldens::EXPECTED;

fn contract_address(env: &Env, tag: u8) -> Address {
    Address::try_from_val(env, &ScAddress::Contract(Hash([tag; 32]))).unwrap()
}

fn hex_encode(bytes: &[u8]) -> std::string::String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = std::string::String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn xdr_hex<T>(env: &Env, value: &T) -> std::string::String
where
    T: IntoVal<Env, Val> + Clone,
{
    let xdr = value.clone().to_xdr(env);
    let len = xdr.len() as usize;
    let mut buf = std::vec![0u8; len];
    xdr.copy_into_slice(&mut buf);
    hex_encode(&buf)
}

fn assert_roundtrip<T>(env: &Env, value: &T)
where
    T: IntoVal<Env, Val> + TryFromVal<Env, Val> + Clone + Eq + core::fmt::Debug,
{
    let bytes = value.clone().to_xdr(env);
    let roundtrip = T::from_xdr(env, &bytes).expect("from_xdr should succeed");
    assert_eq!(roundtrip, *value);
}

// How to update goldens:
// 1) Run:
//    `GRAINLIFY_PRINT_SERIALIZATION_GOLDENS=1 cargo test --lib serialization_compatibility_public_types_and_events -- --nocapture > /tmp/grainlify_core_goldens.txt`
// 2) Regenerate `serialization_goldens.rs` from the printed EXPECTED block.
#[test]
fn serialization_compatibility_public_types_and_events() {
    let env = Env::default();

    let admin = contract_address(&env, 0x01);
    let proposer = contract_address(&env, 0x02);
    let voter = contract_address(&env, 0x03);
    let caller = contract_address(&env, 0x04);

    let wasm_hash = BytesN::<32>::from_array(&env, &[0x11; 32]);
    let migration_hash = BytesN::<32>::from_array(&env, &[0x22; 32]);

    let proposal = Proposal {
        id: 7,
        proposer: proposer.clone(),
        new_wasm_hash: wasm_hash.clone(),
        description: Symbol::new(&env, "upgrade_v2"),
        created_at: 1,
        voting_start: 2,
        voting_end: 3,
        execution_delay: 4,
        status: ProposalStatus::Active,
        votes_for: 10,
        votes_against: 5,
        votes_abstain: 1,
        total_votes: 3,
    };

    let governance_config = GovernanceConfig {
        voting_period: 100,
        execution_delay: 50,
        quorum_percentage: 6000,
        approval_threshold: 7000,
        min_proposal_stake: 123,
        voting_scheme: VotingScheme::OnePersonOneVote,
    };

    let vote = Vote {
        voter: voter.clone(),
        proposal_id: 7,
        vote_type: VoteType::For,
        voting_power: 99,
        timestamp: 9,
    };

    let op_metric = OperationMetric {
        operation: Symbol::new(&env, "upgrade"),
        caller: caller.clone(),
        timestamp: 10,
        success: true,
    };

    let perf_metric = PerformanceMetric {
        function: Symbol::new(&env, "upgrade"),
        duration: 123,
        timestamp: 11,
    };

    let health = HealthStatus {
        is_healthy: true,
        last_operation: 12,
        total_operations: 34,
        contract_version: SdkString::from_str(&env, "2.0.0"),
    };

    let analytics = Analytics {
        operation_count: 100,
        unique_users: 20,
        error_count: 3,
        error_rate: 150,
    };

    let snapshot = StateSnapshot {
        timestamp: 13,
        total_operations: 100,
        total_users: 20,
        total_errors: 3,
    };

    let perf_stats = PerformanceStats {
        function_name: Symbol::new(&env, "upgrade"),
        call_count: 7,
        total_time: 999,
        avg_time: 142,
        last_called: 14,
    };

    let migration_state = MigrationState {
        from_version: 1,
        to_version: 2,
        migrated_at: 15,
        migration_hash: migration_hash.clone(),
    };

    let migration_event = MigrationEvent {
        from_version: 1,
        to_version: 2,
        timestamp: 16,
        migration_hash: migration_hash.clone(),
        success: false,
        error_message: Some(SdkString::from_str(&env, "failed")),
    };

    let samples: &[(&str, Val)] = &[
        (
            "ProposalStatus::Active",
            ProposalStatus::Active.into_val(&env),
        ),
        ("VoteType::For", VoteType::For.into_val(&env)),
        (
            "VotingScheme::OnePersonOneVote",
            VotingScheme::OnePersonOneVote.into_val(&env),
        ),
        ("Proposal", proposal.clone().into_val(&env)),
        ("GovernanceConfig", governance_config.clone().into_val(&env)),
        ("Vote", vote.clone().into_val(&env)),
        ("OperationMetric", op_metric.clone().into_val(&env)),
        ("PerformanceMetric", perf_metric.clone().into_val(&env)),
        ("HealthStatus", health.clone().into_val(&env)),
        ("Analytics", analytics.clone().into_val(&env)),
        ("StateSnapshot", snapshot.clone().into_val(&env)),
        ("PerformanceStats", perf_stats.clone().into_val(&env)),
        ("MigrationState", migration_state.clone().into_val(&env)),
        ("MigrationEvent", migration_event.clone().into_val(&env)),
    ];

    assert_roundtrip(&env, &ProposalStatus::Active);
    assert_roundtrip(&env, &VoteType::For);
    assert_roundtrip(&env, &migration_state);

    let mut computed: std::vec::Vec<(&str, std::string::String)> = std::vec::Vec::new();
    for (name, val) in samples {
        computed.push((name, xdr_hex(&env, val)));
    }

    if std::env::var("GRAINLIFY_PRINT_SERIALIZATION_GOLDENS").is_ok() {
        std::eprintln!("const EXPECTED: &[(&str, &str)] = &[");
        for (name, hex) in &computed {
            std::eprintln!("  (\"{name}\", \"{hex}\"),");
        }
        std::eprintln!("];");
        return;
    }

    for (name, hex) in computed {
        let expected = EXPECTED
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| *v)
            .unwrap_or_else(|| panic!("Missing golden for {name}. Re-run with GRAINLIFY_PRINT_SERIALIZATION_GOLDENS=1"));
        assert_eq!(hex, expected, "XDR encoding changed for {name}");
    }
}
