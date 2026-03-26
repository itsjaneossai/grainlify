#![no_std]
//! Minimal Soroban escrow demo: lock, release, and refund.
//! Parity with main contracts/bounty_escrow where applicable; see soroban/PARITY.md.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, token, Address, BytesN, Env, String, Vec,
};

const ESCROW_DELEGATE_SET: soroban_sdk::Symbol = symbol_short!("EscDlgS");
const ESCROW_DELEGATE_REVOKED: soroban_sdk::Symbol = symbol_short!("EscDlgR");
const ESCROW_METADATA_UPDATED: soroban_sdk::Symbol = symbol_short!("EscMeta");
const LABEL_CONFIG_UPDATED: soroban_sdk::Symbol = symbol_short!("LblCfg");
const ESCROW_LABELS_UPDATED: soroban_sdk::Symbol = symbol_short!("EscLbls");

const MAX_LABEL_LENGTH: u32 = 32;
const MAX_LABELS: u32 = 10;
const MAX_PAGE_SIZE: u32 = 50;

pub const DELEGATE_PERMISSION_RELEASE: u32 = 1 << 0;
pub const DELEGATE_PERMISSION_REFUND: u32 = 1 << 1;
pub const DELEGATE_PERMISSION_UPDATE_META: u32 = 1 << 2;
pub const DELEGATE_PERMISSION_MASK: u32 = DELEGATE_PERMISSION_RELEASE
    | DELEGATE_PERMISSION_REFUND
    | DELEGATE_PERMISSION_UPDATE_META;

mod identity;
pub use identity::*;

mod reentrancy_guard;

use grainlify_core::errors;
#[contracterror]
#[derive(Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 2,
    AlreadyInitialized = 1,
    BountyExists = 201,
    BountyNotFound = 202,
    FundsNotLocked = 203,
    DeadlineNotPassed = 6,
    Unauthorized = 3,
    InsufficientFunds = 5,
    InvalidLabel = 226,
    TooManyLabels = 227,
    LabelNotAllowed = 228,
    // Identity-related errors
    InvalidSignature = 301,
    ClaimExpired = 302,
    UnauthorizedIssuer = 303,
    InvalidClaimFormat = 304,
    TransactionExceedsLimit = 305,
    InvalidRiskScore = 306,
    InvalidTier = 307,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EscrowStatus {
    Locked,
    Released,
    Refunded,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Escrow {
    pub depositor: Address,
    pub amount: i128,
    pub remaining_amount: i128,
    pub status: EscrowStatus,
    pub deadline: u64,
    pub jurisdiction: OptionalJurisdiction,
    pub labels: Vec<String>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowJurisdictionConfig {
    pub tag: Option<String>,
    pub requires_kyc: bool,
    pub enforce_identity_limits: bool,
    pub lock_paused: bool,
    pub release_paused: bool,
    pub refund_paused: bool,
    pub max_lock_amount: Option<i128>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowDelegateSetEvent {
    pub bounty_id: u64,
    pub delegate: Address,
    pub permissions: u32,
    pub updated_by: Address,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OptionalJurisdiction {
    None,
    Some(EscrowJurisdictionConfig),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowDelegateRevokedEvent {
    pub bounty_id: u64,
    pub revoked_by: Address,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowMetadataUpdatedEvent {
    pub bounty_id: u64,
    pub updated_by: Address,
    pub timestamp: u64,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Token,
    Escrow(u64),
    EscrowIndex,
    LabelConfig,
    // Identity-related storage keys
    AddressIdentity(Address),
    AuthorizedIssuer(Address),
    TierLimits,
    RiskThresholds,
    ReentrancyGuard,
    EscrowJurisdiction(u64),
}

#[contract]
pub struct EscrowContract;

#[contractimpl]
impl EscrowContract {
    fn default_label_config(env: &Env) -> LabelConfig {
        LabelConfig {
            restricted: false,
            allowed_labels: Vec::new(env),
        }
    }

    fn get_label_config_internal(env: &Env) -> LabelConfig {
        env.storage()
            .persistent()
            .get(&DataKey::LabelConfig)
            .unwrap_or_else(|| Self::default_label_config(env))
    }

    fn validate_single_label(label: &String) -> Result<(), Error> {
        if label.len() == 0 || label.len() > MAX_LABEL_LENGTH {
            return Err(Error::InvalidLabel);
        }
        Ok(())
    }

    fn normalize_labels(env: &Env, labels: Vec<String>) -> Result<Vec<String>, Error> {
        if labels.len() > MAX_LABELS {
            return Err(Error::TooManyLabels);
        }

        let config = Self::get_label_config_internal(env);
        let mut normalized = Vec::new(env);

        for label in labels.iter() {
            Self::validate_single_label(&label)?;

            let mut exists = false;
            for existing in normalized.iter() {
                if existing == label {
                    exists = true;
                    break;
                }
            }
            if exists {
                continue;
            }

            if config.restricted {
                let mut allowed = false;
                for candidate in config.allowed_labels.iter() {
                    if candidate == label {
                        allowed = true;
                        break;
                    }
                }
                if !allowed {
                    return Err(Error::LabelNotAllowed);
                }
            }

            normalized.push_back(label);
        }

        Ok(normalized)
    }

    fn sanitize_label_config(env: &Env, labels: Vec<String>) -> Result<Vec<String>, Error> {
        if labels.len() > MAX_LABELS {
            return Err(Error::TooManyLabels);
        }

        let mut normalized = Vec::new(env);
        for label in labels.iter() {
            Self::validate_single_label(&label)?;

            let mut exists = false;
            for existing in normalized.iter() {
                if existing == label {
                    exists = true;
                    break;
                }
            }
            if !exists {
                normalized.push_back(label);
            }
        }

        Ok(normalized)
    }

    fn append_escrow_id(env: &Env, bounty_id: u64) {
        let mut index: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::EscrowIndex)
            .unwrap_or_else(|| Vec::new(env));
        index.push_back(bounty_id);
        env.storage().persistent().set(&DataKey::EscrowIndex, &index);
    }

    /// Initialize with admin and token. Call once.
    pub fn init(env: Env, admin: Address, token: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);

        // Initialize default tier limits and risk thresholds
        let default_limits = TierLimits::default();
        let default_thresholds = RiskThresholds::default();
        env.storage()
            .persistent()
            .set(&DataKey::TierLimits, &default_limits);
        env.storage()
            .persistent()
            .set(&DataKey::RiskThresholds, &default_thresholds);

        Ok(())
    }

    /// Set or update an authorized claim issuer (admin only)
    pub fn set_authorized_issuer(env: Env, issuer: Address, authorized: bool) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        env.storage()
            .persistent()
            .set(&DataKey::AuthorizedIssuer(issuer.clone()), &authorized);

        // Emit event for issuer management
        env.events().publish(
            (soroban_sdk::symbol_short!("issuer"), issuer.clone()),
            if authorized {
                soroban_sdk::symbol_short!("add")
            } else {
                soroban_sdk::symbol_short!("remove")
            },
        );

        Ok(())
    }

    /// Configure tier-based transaction limits (admin only)
    pub fn set_tier_limits(
        env: Env,
        unverified: i128,
        basic: i128,
        verified: i128,
        premium: i128,
    ) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let limits = TierLimits {
            unverified_limit: unverified,
            basic_limit: basic,
            verified_limit: verified,
            premium_limit: premium,
        };

        env.storage()
            .persistent()
            .set(&DataKey::TierLimits, &limits);
        Ok(())
    }

    /// Configure risk-based adjustments (admin only)
    pub fn set_risk_thresholds(
        env: Env,
        high_risk_threshold: u32,
        high_risk_multiplier: u32,
    ) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let thresholds = RiskThresholds {
            high_risk_threshold,
            high_risk_multiplier,
        };

        env.storage()
            .persistent()
            .set(&DataKey::RiskThresholds, &thresholds);
        Ok(())
    }

    /// Submit an identity claim for verification and storage
    pub fn submit_identity_claim(
        env: Env,
        claim: IdentityClaim,
        signature: BytesN<64>,
        issuer_pubkey: BytesN<32>,
    ) -> Result<(), Error> {
        // Require authentication from the address in the claim
        claim.address.require_auth();

        // Check if contract is initialized
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }

        // Validate claim format
        identity::validate_claim(&claim)?;

        // Check if claim has expired
        if identity::is_claim_expired(&env, claim.expiry) {
            env.events().publish(
                (soroban_sdk::symbol_short!("claim"), claim.address.clone()),
                soroban_sdk::symbol_short!("expired"),
            );
            return Err(Error::ClaimExpired);
        }

        // Check if issuer is authorized
        let is_authorized: bool = env
            .storage()
            .persistent()
            .get(&DataKey::AuthorizedIssuer(claim.issuer.clone()))
            .unwrap_or(false);

        if !is_authorized {
            env.events().publish(
                (soroban_sdk::symbol_short!("claim"), claim.address.clone()),
                soroban_sdk::symbol_short!("unauth"),
            );
            return Err(Error::UnauthorizedIssuer);
        }

        // Verify claim signature
        identity::verify_claim_signature(&env, &claim, &signature, &issuer_pubkey)?;

        // Store identity data for the address
        let now = env.ledger().timestamp();
        let identity_data = AddressIdentity {
            tier: claim.tier.clone(),
            risk_score: claim.risk_score,
            expiry: claim.expiry,
            last_updated: now,
        };

        env.storage().persistent().set(
            &DataKey::AddressIdentity(claim.address.clone()),
            &identity_data,
        );

        // Emit event for successful claim submission
        env.events().publish(
            (soroban_sdk::symbol_short!("claim"), claim.address.clone()),
            (claim.tier, claim.risk_score, claim.expiry),
        );

        Ok(())
    }

    /// Query identity data for an address
    pub fn get_address_identity(env: Env, address: Address) -> AddressIdentity {
        let identity: Option<AddressIdentity> = env
            .storage()
            .persistent()
            .get(&DataKey::AddressIdentity(address));

        match identity {
            Some(id) => {
                // Check if claim has expired
                if identity::is_claim_expired(&env, id.expiry) {
                    // Return default unverified tier
                    AddressIdentity::default()
                } else {
                    id
                }
            }
            None => AddressIdentity::default(),
        }
    }

    /// Query effective transaction limit for an address
    pub fn get_effective_limit(env: Env, address: Address) -> i128 {
        let identity = Self::get_address_identity(env.clone(), address);

        let tier_limits: TierLimits = env
            .storage()
            .persistent()
            .get(&DataKey::TierLimits)
            .unwrap_or_default();

        let risk_thresholds: RiskThresholds = env
            .storage()
            .persistent()
            .get(&DataKey::RiskThresholds)
            .unwrap_or_default();

        identity::calculate_effective_limit(&env, &identity, &tier_limits, &risk_thresholds)
    }

    /// Check if an address has a valid (non-expired) claim
    pub fn is_claim_valid(env: Env, address: Address) -> bool {
        let identity: Option<AddressIdentity> = env
            .storage()
            .persistent()
            .get(&DataKey::AddressIdentity(address));

        match identity {
            Some(id) => !identity::is_claim_expired(&env, id.expiry),
            None => false,
        }
    }

    /// Internal: Enforce transaction limit for an address
    fn enforce_transaction_limit(env: &Env, address: &Address, amount: i128) -> Result<(), Error> {
        let effective_limit = Self::get_effective_limit(env.clone(), address.clone());

        if amount > effective_limit {
            // Emit event for limit enforcement failure
            env.events().publish(
                (soroban_sdk::symbol_short!("limit"), address.clone()),
                (
                    soroban_sdk::symbol_short!("exceed"),
                    amount,
                    effective_limit,
                ),
            );
            return Err(Error::TransactionExceedsLimit);
        }

        // Emit event for successful limit check
        env.events().publish(
            (soroban_sdk::symbol_short!("limit"), address.clone()),
            (soroban_sdk::symbol_short!("pass"), amount, effective_limit),
        );

        Ok(())
    }

    fn validate_delegate_permissions(permissions: u32) -> Result<(), Error> {
        if permissions == 0 || permissions & !DELEGATE_PERMISSION_MASK != 0 {
            return Err(Error::InvalidDelegatePermissions);
        }
        Ok(())
    }

    fn is_admin(env: &Env, caller: &Address) -> Result<bool, Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        Ok(admin == *caller)
    }

    fn require_escrow_owner_or_admin(
        env: &Env,
        escrow: &Escrow,
        caller: &Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        if *caller == escrow.depositor || Self::is_admin(env, caller)? {
            return Ok(());
        }
        Err(Error::Unauthorized)
    }

    fn require_escrow_actor(
        env: &Env,
        escrow: &Escrow,
        caller: &Address,
        required_permission: u32,
    ) -> Result<(), Error> {
        caller.require_auth();
        if *caller == escrow.depositor || Self::is_admin(env, caller)? {
            return Ok(());
        }

        let delegate_matches = escrow
            .delegate
            .as_ref()
            .map(|delegate| delegate == caller)
            .unwrap_or(false);
        if delegate_matches && (escrow.delegate_permissions & required_permission) == required_permission {
            return Ok(());
        }

        Err(Error::Unauthorized)
    }

    /// Lock funds: depositor must be authorized; tokens transferred from depositor to contract.
    ///
    /// # Reentrancy
    /// Protected by reentrancy guard. Escrow state is written before the
    /// inbound token transfer (CEI pattern).
    pub fn lock_funds(
        env: Env,
        depositor: Address,
        bounty_id: u64,
        amount: i128,
        deadline: u64,
    ) -> Result<(), Error> {
        Self::lock_funds_with_jurisdiction(
            env,
            depositor,
            bounty_id,
            amount,
            deadline,
            OptionalJurisdiction::None,
        )
    }

    /// Lock funds with optional jurisdiction controls.
    pub fn lock_funds_with_jurisdiction(
        env: Env,
        depositor: Address,
        bounty_id: u64,
        amount: i128,
        deadline: u64,
        jurisdiction: OptionalJurisdiction,
    ) -> Result<(), Error> {
        // GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);

        depositor.require_auth();
        if !env.storage().instance().has(&DataKey::Admin) {
            reentrancy_guard::release(&env);
            return Err(Error::NotInitialized);
        }
        if amount <= 0 {
            return Err(Error::InsufficientFunds);
        }
        if env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            reentrancy_guard::release(&env);
            return Err(Error::BountyExists);
        }

        // Enforcement rules from JURISDICTION_SEGMENTATION.md
        if let OptionalJurisdiction::Some(config) = &jurisdiction {
            if config.lock_paused {
                reentrancy_guard::release(&env);
                return Err(Error::Unauthorized);
            }
            if let Some(max_amount) = config.max_lock_amount {
                if amount > max_amount {
                    reentrancy_guard::release(&env);
                    return Err(Error::TransactionExceedsLimit);
                }
            }
            if config.requires_kyc && !Self::is_claim_valid(env.clone(), depositor.clone()) {
                reentrancy_guard::release(&env);
                return Err(Error::Unauthorized);
            }
            if config.enforce_identity_limits {
                if let Err(e) = Self::enforce_transaction_limit(&env, &depositor, amount) {
                    reentrancy_guard::release(&env);
                    return Err(e);
                }
            }
        } else {
            // Generic behavior: always enforce identity limits
            if let Err(e) = Self::enforce_transaction_limit(&env, &depositor, amount) {
                reentrancy_guard::release(&env);
                return Err(e);
            }
        }

        // EFFECTS: write escrow state before external call
        let labels = Vec::new(&env);
        let escrow = Escrow {
            depositor: depositor.clone(),
            amount,
            remaining_amount: amount,
            status: EscrowStatus::Locked,
            deadline,
            jurisdiction: jurisdiction.clone(),
            labels: Vec::new(&env),
        };
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);
        Self::append_escrow_id(&env, bounty_id);

        // Store jurisdiction config separately if present
        if let OptionalJurisdiction::Some(config) = &jurisdiction {
            env.storage()
                .persistent()
                .set(&DataKey::EscrowJurisdiction(bounty_id), config);

            // Emit juris event for lock
            env.events().publish(
                (
                    soroban_sdk::symbol_short!("juris"),
                    soroban_sdk::symbol_short!("lock"),
                    bounty_id,
                ),
                (
                    config.tag.clone(),
                    config.requires_kyc,
                    config.enforce_identity_limits,
                ),
            );
        }

        // INTERACTION: external token transfer is last
        let token = env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::Token)
            .unwrap();
        let contract = env.current_contract_address();
        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&depositor, &contract, &amount);

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Read escrow jurisdiction config.
    pub fn get_escrow_jurisdiction(env: Env, bounty_id: u64) -> OptionalJurisdiction {
        let escrow: Option<Escrow> = env.storage().persistent().get(&DataKey::Escrow(bounty_id));
        match escrow {
            Some(e) => e.jurisdiction,
            None => OptionalJurisdiction::None,
        }
    }

    /// Release funds to contributor. Admin must be authorized. Fails if already released or refunded.
    ///
    /// # Reentrancy
    /// Protected by reentrancy guard. Escrow state is updated to
    /// `Released` *before* the outbound token transfer (CEI pattern).
    pub fn release_funds(env: Env, bounty_id: u64, contributor: Address) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        Self::release_funds_by(env, admin, bounty_id, contributor)
    }

    pub fn release_funds_by(
        env: Env,
        caller: Address,
        bounty_id: u64,
        contributor: Address,
    ) -> Result<(), Error> {
        // GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);

        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }

        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .unwrap();
        Self::require_escrow_actor(&env, &escrow, &caller, DELEGATE_PERMISSION_RELEASE)?;
        if escrow.status != EscrowStatus::Locked {
            return Err(Error::FundsNotLocked);
        }
        if escrow.remaining_amount <= 0 {
            return Err(Error::InsufficientFunds);
        }

        // Enforce transaction limit for contributor
        Self::enforce_transaction_limit(&env, &contributor, escrow.remaining_amount)?;

        // EFFECTS: update state before external call (CEI)
        let release_amount = escrow.remaining_amount;
        escrow.remaining_amount = 0;
        escrow.status = EscrowStatus::Released;
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        // INTERACTION: external token transfer is last
        let token = env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::Token)
            .unwrap();
        let contract = env.current_contract_address();
        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&contract, &contributor, &release_amount);

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Refund remaining funds to depositor. Allowed after deadline.
    ///
    /// # Reentrancy
    /// Protected by reentrancy guard. Escrow state is updated to
    /// `Refunded` *before* the outbound token transfer (CEI pattern).
    pub fn refund(env: Env, bounty_id: u64) -> Result<(), Error> {
        let escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .ok_or(Error::BountyNotFound)?;
        Self::refund_by(env, escrow.depositor, bounty_id)
    }

    pub fn refund_by(env: Env, caller: Address, bounty_id: u64) -> Result<(), Error> {
        // GUARD: acquire reentrancy lock
        reentrancy_guard::acquire(&env);

        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }

        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .unwrap();
        Self::require_escrow_actor(&env, &escrow, &caller, DELEGATE_PERMISSION_REFUND)?;
        if escrow.status != EscrowStatus::Locked {
            return Err(Error::FundsNotLocked);
        }
        let now = env.ledger().timestamp();
        if now < escrow.deadline {
            return Err(Error::DeadlineNotPassed);
        }
        if escrow.remaining_amount <= 0 {
            return Err(Error::InsufficientFunds);
        }

        // EFFECTS: update state before external call (CEI)
        let amount = escrow.remaining_amount;
        let depositor = escrow.depositor.clone();
        escrow.remaining_amount = 0;
        escrow.status = EscrowStatus::Refunded;
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        // INTERACTION: external token transfer is last
        let token = env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::Token)
            .unwrap();
        let contract = env.current_contract_address();
        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&contract, &depositor, &amount);

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    pub fn set_delegate(
        env: Env,
        caller: Address,
        bounty_id: u64,
        delegate: Address,
        permissions: u32,
    ) -> Result<(), Error> {
        Self::validate_delegate_permissions(permissions)?;
        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .ok_or(Error::BountyNotFound)?;
        Self::require_escrow_owner_or_admin(&env, &escrow, &caller)?;

        if delegate == escrow.depositor {
            return Err(Error::InvalidDelegateTarget);
        }

        escrow.delegate = Some(delegate.clone());
        escrow.delegate_permissions = permissions;
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        env.events().publish(
            (ESCROW_DELEGATE_SET, bounty_id),
            EscrowDelegateSetEvent {
                bounty_id,
                delegate,
                permissions,
                updated_by: caller,
                timestamp: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    pub fn revoke_delegate(env: Env, caller: Address, bounty_id: u64) -> Result<(), Error> {
        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .ok_or(Error::BountyNotFound)?;
        Self::require_escrow_owner_or_admin(&env, &escrow, &caller)?;

        escrow.delegate = None;
        escrow.delegate_permissions = 0;
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        env.events().publish(
            (ESCROW_DELEGATE_REVOKED, bounty_id),
            EscrowDelegateRevokedEvent {
                bounty_id,
                revoked_by: caller,
                timestamp: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    pub fn update_metadata(
        env: Env,
        caller: Address,
        bounty_id: u64,
        metadata: String,
    ) -> Result<(), Error> {
        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .ok_or(Error::BountyNotFound)?;
        Self::require_escrow_actor(&env, &escrow, &caller, DELEGATE_PERMISSION_UPDATE_META)?;

        escrow.metadata = Some(metadata);
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        env.events().publish(
            (ESCROW_METADATA_UPDATED, bounty_id),
            EscrowMetadataUpdatedEvent {
                bounty_id,
                updated_by: caller,
                timestamp: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    /// Read escrow state (for tests).
    pub fn get_escrow(env: Env, bounty_id: u64) -> Result<Escrow, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .ok_or(Error::BountyNotFound)
    }

    pub fn get_label_config(env: Env) -> LabelConfig {
        Self::get_label_config_internal(&env)
    }

    pub fn set_label_config(
        env: Env,
        restricted: bool,
        allowed_labels: Vec<String>,
    ) -> Result<LabelConfig, Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let allowed_labels = Self::sanitize_label_config(&env, allowed_labels)?;
        let config = LabelConfig {
            restricted,
            allowed_labels: allowed_labels.clone(),
        };
        env.storage().persistent().set(&DataKey::LabelConfig, &config);
        env.events().publish(
            (LABEL_CONFIG_UPDATED,),
            LabelConfigUpdatedEvent {
                version: 1,
                admin,
                restricted,
                allowed_labels,
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(config)
    }

    pub fn update_labels(
        env: Env,
        actor: Address,
        bounty_id: u64,
        labels: Vec<String>,
    ) -> Result<Escrow, Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(bounty_id))
            .ok_or(Error::BountyNotFound)?;

        if actor != admin && actor != escrow.depositor {
            return Err(Error::Unauthorized);
        }
        actor.require_auth();

        let labels = Self::normalize_labels(&env, labels)?;
        escrow.labels = labels.clone();
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);
        env.events().publish(
            (ESCROW_LABELS_UPDATED, bounty_id),
            EscrowLabelsUpdatedEvent {
                version: 1,
                bounty_id,
                actor,
                labels,
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(escrow)
    }

    pub fn get_escrows_by_label(
        env: Env,
        label: String,
        cursor: Option<u64>,
        limit: u32,
    ) -> EscrowLabelPage {
        let effective_limit = if limit == 0 || limit > MAX_PAGE_SIZE {
            MAX_PAGE_SIZE
        } else {
            limit
        };
        let index: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::EscrowIndex)
            .unwrap_or_else(|| Vec::new(&env));

        let mut records: Vec<EscrowLabelRecord> = Vec::new(&env);
        let mut collecting = cursor.is_none();
        let mut next_cursor = None;
        let mut has_more = false;

        for i in 0..index.len() {
            let id = index.get(i).unwrap();
            if !collecting {
                if Some(id) == cursor {
                    collecting = true;
                }
                continue;
            }

            let Some(escrow) = env
                .storage()
                .persistent()
                .get::<_, Escrow>(&DataKey::Escrow(id))
            else {
                continue;
            };

            let mut matches = false;
            for escrow_label in escrow.labels.iter() {
                if escrow_label == label {
                    matches = true;
                    break;
                }
            }
            if !matches {
                continue;
            }

            if records.len() >= effective_limit {
                has_more = true;
                break;
            }

            next_cursor = Some(id);
            records.push_back(EscrowLabelRecord {
                bounty_id: id,
                depositor: escrow.depositor,
                amount: escrow.amount,
                remaining_amount: escrow.remaining_amount,
                status: escrow.status,
                deadline: escrow.deadline,
                labels: escrow.labels,
            });
        }

        if !has_more {
            next_cursor = None;
        }

        EscrowLabelPage {
            records,
            next_cursor,
            has_more,
        }
    }
}

// ── NEW public methods ──────────────────────────────────────────────────────

impl EscrowContract {
    /// Return the contract's current token balance.
    /// Added to satisfy the standard EscrowInterface (Issue #574).
    pub fn get_balance(env: Env) -> Result<i128, Error> {
        if !env.storage().instance().has(&DataKey::Token) {
            return Err(Error::NotInitialized);
        }
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token);
        Ok(client.balance(&env.current_contract_address()))
    }

    /// Alias of `get_escrow` using the standard name from EscrowInterface.
    pub fn get_escrow_info(env: Env, bounty_id: u64) -> Result<Escrow, Error> {
        Self::get_escrow(env, bounty_id)
    }
}

// ── Standard interface traits (local definitions, Issue #574) ───────────────
//
// Mirrors the canonical trait definitions from
// contracts/bounty_escrow/contracts/escrow/src/traits.rs.
// Kept local to avoid a cross-crate dependency on bounty_escrow types.

pub mod traits {
    use super::{Error, Escrow, EscrowContract};
    use soroban_sdk::{Address, Env};

    /// Core lifecycle interface — see bounty_escrow traits.rs for full spec.
    pub trait EscrowInterface {
        fn lock_funds(
            env: &Env,
            depositor: Address,
            bounty_id: u64,
            amount: i128,
            deadline: u64,
        ) -> Result<(), Error>;
        fn release_funds(env: &Env, bounty_id: u64, contributor: Address) -> Result<(), Error>;
        fn refund(env: &Env, bounty_id: u64) -> Result<(), Error>;
        fn get_escrow_info(env: &Env, bounty_id: u64) -> Result<Escrow, Error>;
        fn get_balance(env: &Env) -> Result<i128, Error>;
    }

    /// Version interface — see bounty_escrow traits.rs for full spec.
    pub trait UpgradeInterface {
        fn get_version(env: &Env) -> u32;
    }

    impl EscrowInterface for EscrowContract {
        fn lock_funds(
            env: &Env,
            depositor: Address,
            bounty_id: u64,
            amount: i128,
            deadline: u64,
        ) -> Result<(), Error> {
            EscrowContract::lock_funds(env.clone(), depositor, bounty_id, amount, deadline)
        }
        fn release_funds(env: &Env, bounty_id: u64, contributor: Address) -> Result<(), Error> {
            EscrowContract::release_funds(env.clone(), bounty_id, contributor)
        }
        fn refund(env: &Env, bounty_id: u64) -> Result<(), Error> {
            EscrowContract::refund(env.clone(), bounty_id)
        }
        fn get_escrow_info(env: &Env, bounty_id: u64) -> Result<Escrow, Error> {
            EscrowContract::get_escrow(env.clone(), bounty_id)
        }
        fn get_balance(env: &Env) -> Result<i128, Error> {
            EscrowContract::get_balance(env.clone())
        }
    }

    impl UpgradeInterface for EscrowContract {
        /// Soroban escrow is pinned at v1 (no WASM upgrade path yet).
        fn get_version(_env: &Env) -> u32 {
            1
        }
    }
}

mod identity_test;
mod test;
mod test_dispute_resolution;
