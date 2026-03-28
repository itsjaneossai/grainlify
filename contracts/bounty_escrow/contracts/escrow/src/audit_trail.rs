use soroban_sdk::{contracttype, xdr::ToXdr, Address, BytesN, Env, Symbol, Vec};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditConfig {
    pub enabled: bool,
    pub sequence: u64,
    pub head_hash: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    pub sequence: u64,
    pub previous_hash: BytesN<32>,
    pub action: Symbol,
    pub actor: Address,
    pub target_id: u64,
    pub timestamp: u64,
}

#[contracttype]
pub enum AuditDataKey {
    Config,
    Record(u64), // sequence number
}

pub fn set_enabled(env: &Env, enabled: bool) {
    let mut config = env.storage().instance().get(&AuditDataKey::Config).unwrap_or(AuditConfig {
        enabled: false,
        sequence: 0,
        head_hash: BytesN::from_array(env, &[0; 32]),
    });
    config.enabled = enabled;
    env.storage().instance().set(&AuditDataKey::Config, &config);
}

pub fn log_action(env: &Env, action: Symbol, actor: Address, target_id: u64) {
    let mut config: AuditConfig = env.storage().instance().get(&AuditDataKey::Config).unwrap_or(AuditConfig {
        enabled: false,
        sequence: 0,
        head_hash: BytesN::from_array(env, &[0; 32]),
    });

    if !config.enabled {
        return;
    }

    let timestamp = env.ledger().timestamp();
    let record = AuditRecord {
        sequence: config.sequence,
        previous_hash: config.head_hash.clone(),
        action: action.clone(),
        actor: actor.clone(),
        target_id,
        timestamp,
    };

    // Create a deterministic hash of this action + the previous hash (The Hash Chain)
    let payload = (
        config.head_hash.clone(),
        action,
        actor,
        target_id,
        timestamp,
    );
    let new_hash = env.crypto().sha256(&payload.to_xdr(env));

    config.head_hash = new_hash;
    
    env.storage().persistent().set(&AuditDataKey::Record(config.sequence), &record);
    config.sequence += 1;
    env.storage().instance().set(&AuditDataKey::Config, &config);
}

pub fn get_audit_tail(env: &Env, n: u32) -> Vec<AuditRecord> {
    let config: AuditConfig = env.storage().instance().get(&AuditDataKey::Config).unwrap_or(AuditConfig {
        enabled: false,
        sequence: 0,
        head_hash: BytesN::from_array(env, &[0; 32]),
    });

    let mut tail = Vec::new(env);
    let start = config.sequence.saturating_sub(n as u64);
    
    for i in start..config.sequence {
        if let Some(record) = env.storage().persistent().get(&AuditDataKey::Record(i)) {
            tail.push_back(record);
        }
    }
    tail
}