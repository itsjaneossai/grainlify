# apply_patch.ps1
# Run this from: C:\Users\BUY-PC COMPUTERS\drips\grainlify\contracts\bounty_escrow\contracts\escrow\src
# Usage: .\apply_patch.ps1

$libPath = "lib.rs"
$content = Get-Content $libPath -Raw

Write-Host "Applying patch to lib.rs..." -ForegroundColor Cyan

# ── PATCH 1: Add OracleConfig struct after RefundMode enum ───────────────────
$oldText1 = @'
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefundMode {
    Full,
    Partial,
}
'@

$newText1 = @'
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefundMode {
    Full,
    Partial,
}

/// Configuration for the oracle-attested refund path.
///
/// When `enabled` is true, the address at `oracle_address` may call
/// `oracle_refund` to unilaterally trigger a refund for any locked bounty
/// without requiring admin or depositor authorization.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleConfig {
    pub oracle_address: Address,
    pub enabled: bool,
}
'@

if ($content.Contains($oldText1)) {
    $content = $content.Replace($oldText1, $newText1)
    Write-Host "PATCH 1 applied: OracleConfig struct added" -ForegroundColor Green
} else {
    Write-Host "PATCH 1 FAILED: RefundMode enum not found" -ForegroundColor Red
}

# ── PATCH 2: Add OracleConfig and OracleRefundUsed to DataKey enum ────────────
$oldText2 = '    /// Per-operation gas budget caps configured by the admin.
    /// See [`gas_budget::GasBudgetConfig`].
    GasBudgetConfig,'

$newText2 = '    /// Per-operation gas budget caps configured by the admin.
    /// See [`gas_budget::GasBudgetConfig`].
    GasBudgetConfig,

    /// OracleConfig for oracle-attested refunds.
    OracleConfig,
    /// bounty_id -> bool, prevents double oracle refund.
    OracleRefundUsed(u64),'

if ($content.Contains($oldText2)) {
    $content = $content.Replace($oldText2, $newText2)
    Write-Host "PATCH 2 applied: OracleConfig and OracleRefundUsed added to DataKey" -ForegroundColor Green
} else {
    Write-Host "PATCH 2 FAILED: GasBudgetConfig DataKey not found" -ForegroundColor Red
}

# ── PATCH 3: Add new error codes ──────────────────────────────────────────────
$oldText3 = '    /// Returned when an operation''s measured CPU or memory consumption exceeds
    /// the configured cap and [`gas_budget::GasBudgetConfig::enforce`] is `true`.
    /// The Soroban host reverts all storage writes and token transfers in the
    /// transaction atomically. Only reachable in test / testutils builds.
    GasBudgetExceeded = 44,'

$newText3 = '    /// Returned when an operation''s measured CPU or memory consumption exceeds
    /// the configured cap and [`gas_budget::GasBudgetConfig::enforce`] is `true`.
    /// The Soroban host reverts all storage writes and token transfers in the
    /// transaction atomically. Only reachable in test / testutils builds.
    GasBudgetExceeded = 44,
    /// Oracle not configured or disabled.
    OracleNotConfigured = 45,
    /// Oracle refund already processed for this bounty (double-refund prevention).
    OracleRefundAlreadyProcessed = 46,
    /// Caller is not the configured oracle address.
    CallerNotOracle = 47,'

if ($content.Contains($oldText3)) {
    $content = $content.Replace($oldText3, $newText3)
    Write-Host "PATCH 3 applied: New error codes added" -ForegroundColor Green
} else {
    Write-Host "PATCH 3 FAILED: GasBudgetExceeded error not found" -ForegroundColor Red
}

# ── PATCH 4: Add trigger_type field to RefundRecord ──────────────────────────
$oldText4 = @'
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundRecord {
    pub amount: i128,
    pub recipient: Address,
    pub timestamp: u64,
    pub mode: RefundMode,
}
'@

$newText4 = @'
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundRecord {
    pub amount: i128,
    pub recipient: Address,
    pub timestamp: u64,
    pub mode: RefundMode,
    /// Which code path triggered this refund entry.
    pub trigger_type: events::RefundTriggerType,
}
'@

if ($content.Contains($oldText4)) {
    $content = $content.Replace($oldText4, $newText4)
    Write-Host "PATCH 4 applied: trigger_type added to RefundRecord" -ForegroundColor Green
} else {
    Write-Host "PATCH 4 FAILED: RefundRecord struct not found" -ForegroundColor Red
}

# ── PATCH 5: Update refund() function - RefundRecord push ────────────────────
$oldText5 = @'
        // Add to refund history
        escrow.refund_history.push_back(RefundRecord {
            amount: refund_amount,
            recipient: refund_to.clone(),
            timestamp: now,
            mode: if is_full {
                RefundMode::Full
            } else {
                RefundMode::Partial
            },
        });

        // Save updated escrow
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        // Remove approval after successful execution
        if approval.is_some() {
            env.storage().persistent().remove(&approval_key);
        }

        // INTERACTION: external token transfer is last
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);
        client.transfer(&env.current_contract_address(), &refund_to, &refund_amount);

        emit_funds_refunded(
            &env,
            FundsRefunded {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount: refund_amount,
                refund_to: refund_to.clone(),
                timestamp: now,
            },
        );
'@

$newText5 = @'
        // Determine trigger type based on which path was taken
        let trigger_type = if approval.is_some() {
            events::RefundTriggerType::AdminApproval
        } else {
            events::RefundTriggerType::DeadlineExpired
        };

        // Add to refund history
        escrow.refund_history.push_back(RefundRecord {
            amount: refund_amount,
            recipient: refund_to.clone(),
            timestamp: now,
            mode: if is_full {
                RefundMode::Full
            } else {
                RefundMode::Partial
            },
            trigger_type: trigger_type.clone(),
        });

        // Save updated escrow
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(bounty_id), &escrow);

        // Remove approval after successful execution
        if approval.is_some() {
            env.storage().persistent().remove(&approval_key);
        }

        // INTERACTION: external token transfer is last
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);
        client.transfer(&env.current_contract_address(), &refund_to, &refund_amount);

        emit_funds_refunded(
            &env,
            FundsRefunded {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount: refund_amount,
                refund_to: refund_to.clone(),
                timestamp: now,
                trigger_type,
            },
        );
'@

if ($content.Contains($oldText5)) {
    $content = $content.Replace($oldText5, $newText5)
    Write-Host "PATCH 5 applied: refund() updated with trigger_type" -ForegroundColor Green
} else {
    Write-Host "PATCH 5 FAILED: refund() RefundRecord block not found" -ForegroundColor Red
}

# ── PATCH 6: Fix refund_with_capability RefundRecord ─────────────────────────
$oldText6 = @'
        escrow.refund_history.push_back(RefundRecord {
            amount,
            recipient: refund_to.clone(),
            timestamp: now,
            mode: if escrow.status == EscrowStatus::Refunded {
                RefundMode::Full
            } else {
                RefundMode::Partial
            },
        });
'@

$newText6 = @'
        escrow.refund_history.push_back(RefundRecord {
            amount,
            recipient: refund_to.clone(),
            timestamp: now,
            mode: if escrow.status == EscrowStatus::Refunded {
                RefundMode::Full
            } else {
                RefundMode::Partial
            },
            trigger_type: events::RefundTriggerType::AdminApproval,
        });
'@

if ($content.Contains($oldText6)) {
    $content = $content.Replace($oldText6, $newText6)
    Write-Host "PATCH 6 applied: refund_with_capability RefundRecord updated" -ForegroundColor Green
} else {
    Write-Host "PATCH 6 FAILED: refund_with_capability RefundRecord not found" -ForegroundColor Red
}

# ── PATCH 7: Fix refund_with_capability emit_funds_refunded ──────────────────
$oldText7 = @'
        emit_funds_refunded(
            &env,
            FundsRefunded {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount,
                refund_to,
                timestamp: now,
            },
        );

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// view function to get escrow info
'@

$newText7 = @'
        emit_funds_refunded(
            &env,
            FundsRefunded {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount,
                refund_to,
                timestamp: now,
                trigger_type: events::RefundTriggerType::AdminApproval,
            },
        );

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// view function to get escrow info
'@

if ($content.Contains($oldText7)) {
    $content = $content.Replace($oldText7, $newText7)
    Write-Host "PATCH 7 applied: refund_with_capability emit updated" -ForegroundColor Green
} else {
    Write-Host "PATCH 7 FAILED: refund_with_capability emit not found" -ForegroundColor Red
}

# ── PATCH 8: Fix refund_resolved RefundRecord (anon escrow) ──────────────────
$oldText8 = @'
        // Add to refund history
        anon.refund_history.push_back(RefundRecord {
            amount: refund_amount,
            recipient: refund_to.clone(),
            timestamp: now,
            mode: if is_full {
                RefundMode::Full
            } else {
                RefundMode::Partial
            },
        });
'@

$newText8 = @'
        // Add to refund history
        anon.refund_history.push_back(RefundRecord {
            amount: refund_amount,
            recipient: refund_to.clone(),
            timestamp: now,
            mode: if is_full {
                RefundMode::Full
            } else {
                RefundMode::Partial
            },
            trigger_type: events::RefundTriggerType::AdminApproval,
        });
'@

if ($content.Contains($oldText8)) {
    $content = $content.Replace($oldText8, $newText8)
    Write-Host "PATCH 8 applied: refund_resolved RefundRecord updated" -ForegroundColor Green
} else {
    Write-Host "PATCH 8 FAILED: refund_resolved RefundRecord not found" -ForegroundColor Red
}

# ── PATCH 9: Fix refund_resolved emit_funds_refunded ─────────────────────────
$oldText9 = @'
        emit_funds_refunded(
            &env,
            FundsRefunded {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount: refund_amount,
                refund_to: refund_to.clone(),
                timestamp: now,
            },
        );

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Delegated refund path using a capability.
'@

$newText9 = @'
        emit_funds_refunded(
            &env,
            FundsRefunded {
                version: EVENT_VERSION_V2,
                bounty_id,
                amount: refund_amount,
                refund_to: refund_to.clone(),
                timestamp: now,
                trigger_type: events::RefundTriggerType::AdminApproval,
            },
        );

        // GUARD: release reentrancy lock
        reentrancy_guard::release(&env);
        Ok(())
    }

    /// Delegated refund path using a capability.
'@

if ($content.Contains($oldText9)) {
    $content = $content.Replace($oldText9, $newText9)
    Write-Host "PATCH 9 applied: refund_resolved emit updated" -ForegroundColor Green
} else {
    Write-Host "PATCH 9 FAILED: refund_resolved emit not found" -ForegroundColor Red
}

# ── PATCH 10: Add new functions + test module before trait impls ──────────────
$oldText10 = @'
}

impl traits::EscrowInterface for BountyEscrowContract {
'@

$newFunctions = Get-Content "new_functions.rs" -Raw

$newText10 = @"

$newFunctions
}

impl traits::EscrowInterface for BountyEscrowContract {
"@

if ($content.Contains($oldText10)) {
    $content = $content.Replace($oldText10, $newText10)
    Write-Host "PATCH 10 applied: set_oracle, oracle_refund, auto_refund added" -ForegroundColor Green
} else {
    Write-Host "PATCH 10 FAILED: impl block closing not found" -ForegroundColor Red
}

# ── PATCH 11: Register test module ───────────────────────────────────────────
$oldText11 = '#[cfg(test)]
mod test_status_transitions;'

$newText11 = '#[cfg(test)]
mod test_status_transitions;
#[cfg(test)]
mod test_conditional_refund;'

if ($content.Contains($oldText11)) {
    $content = $content.Replace($oldText11, $newText11)
    Write-Host "PATCH 11 applied: test_conditional_refund module registered" -ForegroundColor Green
} else {
    Write-Host "PATCH 11 FAILED: test_status_transitions not found" -ForegroundColor Red
}

# ── Write output ──────────────────────────────────────────────────────────────
Set-Content $libPath $content -NoNewline
Write-Host ""
Write-Host "Done! lib.rs has been patched." -ForegroundColor Cyan
Write-Host "Now run: cargo test test_conditional_refund 2>&1 | Select-Object -Last 60" -ForegroundColor Yellow
