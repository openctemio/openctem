-- Migration 000228: TOTP two-factor authentication for organization users.
--
-- Second-factor state lives in its own tables rather than new users columns,
-- so the secret material is kept apart from the identity row and the many
-- existing users read paths never load it (same split as admin_credentials).

-- One row per user that has started or finished enrolling.
CREATE TABLE IF NOT EXISTS user_mfa (
    user_id                  UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- Active TOTP secret, encrypted with the application encryption key.
    secret_encrypted         TEXT,
    -- Secret issued by a setup call and not yet confirmed with a code.
    pending_secret_encrypted TEXT,
    pending_created_at       TIMESTAMPTZ,
    enabled                  BOOLEAN NOT NULL DEFAULT FALSE,
    enabled_at               TIMESTAMPTZ,
    -- Newest accepted RFC 6238 time step; a code whose step is not newer is a
    -- replay and is rejected.
    last_used_step           BIGINT NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Single-use recovery codes, bcrypt-hashed. Shown to the user exactly once.
CREATE TABLE IF NOT EXISTS user_mfa_recovery_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_mfa_recovery_codes_user
    ON user_mfa_recovery_codes(user_id) WHERE used_at IS NULL;

-- Short-lived handles returned by a password login that still needs a second
-- step. Not sessions: they mint nothing until the code is verified. Only the
-- SHA-256 of the token is stored.
CREATE TABLE IF NOT EXISTS user_mfa_challenges (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    purpose     VARCHAR(16) NOT NULL CHECK (purpose IN ('verify', 'enroll')),
    attempts    INTEGER NOT NULL DEFAULT 0,
    ip_address  VARCHAR(45),
    user_agent  TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_mfa_challenges_expires_at
    ON user_mfa_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_mfa_challenges_user
    ON user_mfa_challenges(user_id);
