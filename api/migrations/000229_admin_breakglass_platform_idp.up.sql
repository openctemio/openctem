-- Migration 000229: break-glass administrators and the platform identity
-- provider for administrators (RFC-022 revision 4).
--
-- Additive only (expand step): new nullable/defaulted columns and new tables,
-- so pods on the previous release keep working during a rolling deploy.

-- ---------------------------------------------------------------------------
-- admin_users: break-glass marker, forced password change, IdP binding
-- ---------------------------------------------------------------------------
ALTER TABLE admin_users
    ADD COLUMN IF NOT EXISTS is_break_glass BOOLEAN NOT NULL DEFAULT FALSE,
    -- When another super admin last confirmed a break-glass sign-in as a test.
    ADD COLUMN IF NOT EXISTS break_glass_tested_at TIMESTAMPTZ,
    -- Set when the account was given a temporary password (bootstrap-admin,
    -- POST /admin/administrators); cleared by the console password change.
    ADD COLUMN IF NOT EXISTS password_change_required BOOLEAN NOT NULL DEFAULT FALSE,
    -- Platform IdP binding: set on the first IdP sign-in, matched on
    -- (issuer, subject) afterwards, never on email.
    ADD COLUMN IF NOT EXISTS idp_issuer TEXT,
    ADD COLUMN IF NOT EXISTS idp_subject TEXT,
    ADD COLUMN IF NOT EXISTS idp_bound_at TIMESTAMPTZ;

-- A break-glass administrator is local by definition: it must keep working
-- when the IdP is down or compromised, so it can never be bound to it.
ALTER TABLE admin_users DROP CONSTRAINT IF EXISTS chk_admin_users_break_glass_local;
ALTER TABLE admin_users ADD CONSTRAINT chk_admin_users_break_glass_local
    CHECK (NOT is_break_glass OR idp_subject IS NULL);

ALTER TABLE admin_users DROP CONSTRAINT IF EXISTS chk_admin_users_idp_binding_pair;
ALTER TABLE admin_users ADD CONSTRAINT chk_admin_users_idp_binding_pair
    CHECK ((idp_issuer IS NULL) = (idp_subject IS NULL));

CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_idp_binding
    ON admin_users(idp_issuer, idp_subject) WHERE idp_subject IS NOT NULL;

-- ---------------------------------------------------------------------------
-- admin_sessions: how the session was authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE admin_sessions
    ADD COLUMN IF NOT EXISTS auth_method TEXT NOT NULL DEFAULT 'password';

-- ---------------------------------------------------------------------------
-- admin_audit_logs: severity (break-glass sign-ins and IdP changes are high)
-- ---------------------------------------------------------------------------
ALTER TABLE admin_audit_logs
    ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT 'info';

-- ---------------------------------------------------------------------------
-- platform_identity_provider: the administrators' IdP (one row, platform-level,
-- unrelated to any organization's identity providers)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS platform_identity_provider (
    id                      SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    protocol                TEXT NOT NULL DEFAULT 'oidc' CHECK (protocol = 'oidc'),
    enabled                 BOOLEAN NOT NULL DEFAULT FALSE,
    display_name            TEXT NOT NULL,
    issuer                  TEXT NOT NULL,
    client_id               TEXT NOT NULL,
    -- AES-GCM with the application encryption key; never returned by the API.
    client_secret_encrypted TEXT NOT NULL,
    redirect_uri            TEXT NOT NULL,
    scopes                  TEXT[] NOT NULL DEFAULT ARRAY['openid', 'email', 'profile'],
    -- From the issuer's discovery document, fetched when the config is saved.
    authorization_endpoint  TEXT NOT NULL,
    token_endpoint          TEXT NOT NULL,
    jwks_uri                TEXT NOT NULL,
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic'
        CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post')),
    -- Refuse local password sign-in to the console for non-break-glass admins.
    require_idp             BOOLEAN NOT NULL DEFAULT FALSE,
    -- Opt-in: accept the IdP's MFA instead of the console TOTP when the
    -- id_token's acr is one of these, or its amr contains one of these.
    trusted_acr_values      TEXT[] NOT NULL DEFAULT '{}',
    trusted_amr_values      TEXT[] NOT NULL DEFAULT '{}',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by              UUID REFERENCES admin_users(id) ON DELETE SET NULL
);

-- ---------------------------------------------------------------------------
-- admin_idp_login_states: in-flight IdP sign-ins (single use, 10 minutes)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_idp_login_states (
    -- SHA-256 of the state; the state itself lives only in the browser cookie
    -- and the authorization request.
    state_hash              TEXT PRIMARY KEY,
    nonce                   TEXT NOT NULL,
    code_verifier_encrypted TEXT NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at              TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_idp_login_states_expires_at
    ON admin_idp_login_states(expires_at);
