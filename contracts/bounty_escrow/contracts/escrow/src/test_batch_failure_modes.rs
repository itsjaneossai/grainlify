
/// Lock a single bounty via the single-item path (for pre-seeding state).
fn lock_one(ctx: &Ctx, depositor: &Address, bounty_id: u64) {
    ctx.client.lock_funds(
        depositor,
        &bounty_id,
        &AMOUNT,
        &(ctx.env.ledger().timestamp() + DEADLINE_OFFSET),
    );
}

/// Advance the ledger timestamp by `seconds`.
fn advance_time(ctx: &Ctx, seconds: u64) {
    ctx.env.ledger().set(LedgerInfo {
        timestamp: ctx.env.ledger().timestamp() + seconds,
        ..ctx.env.ledger().get()
    });
}

