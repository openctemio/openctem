-- Migration 000225: platform admin console authentication (RFC-022 Phase 1)
--
-- Human login for the platform admin console: password + mandatory TOTP and
-- server-side sessions. API-key auth on admin_users is unchanged (CLI and
-- automation keep using it).
--
-- Credentials live in their own table instead of new admin_users columns so
-- secrets are kept apart from the identity row and the existing admin_users
-- read paths never load them.

CREATE TABLE IF NOT EXISTS admin_credentials (
    admin_id             UUID PRIMARY KEY REFERENCES admin_users(id) ON DELETE CASCADE,
    password_hash        TEXT,
    -- TOTP secret, encrypted with the application encryption key.
    mfa_secret_encrypted TEXT,
    mfa_enabled          BOOLEAN NOT NULL DEFAULT FALSE,
    -- Last accepted TOTP time step; a code whose step is not newer is a replay.
    mfa_last_step        BIGINT NOT NULL DEFAULT 0,
    password_changed_at  TIMESTAMPTZ,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id     UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    -- SHA-256 of the session token; the token itself is never stored.
    token_hash   TEXT NOT NULL UNIQUE,
    -- FALSE while the login is waiting for its TOTP step.
    mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip           VARCHAR(45),
    user_agent   TEXT
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin_id ON admin_sessions(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions(expires_at);
