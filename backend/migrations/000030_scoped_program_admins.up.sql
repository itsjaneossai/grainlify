-- Scoped admin roles: allows granting admin-like permissions to a user
-- for a specific program or escrow, rather than globally.
--
-- scope_type: 'program' | 'escrow'
-- scope_id:   the program_id or escrow contract address the role applies to

CREATE TABLE IF NOT EXISTS program_admins (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('program', 'escrow')),
    scope_id   TEXT NOT NULL,
    granted_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_program_admins_user_id  ON program_admins(user_id);
CREATE INDEX IF NOT EXISTS idx_program_admins_scope    ON program_admins(scope_type, scope_id);
