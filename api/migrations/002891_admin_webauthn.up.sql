-- Platform console WebAuthn authenticators, one-time recovery codes and the
-- single-use ceremony state of a console session (RFC-078, console part).
-- Platform-level tables: administrators belong to no organization, so there is
-- no tenant_id. New, empty tables: no lock on populated data.

CREATE TABLE admin_webauthn_credentials (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id         uuid NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    credential_id    bytea NOT NULL,
    public_key       bytea NOT NULL,
    sign_count       bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    aaguid           uuid,
    transports       text[] NOT NULL DEFAULT '{}',
    attachment       text NOT NULL DEFAULT '',
    attestation_fmt  text NOT NULL DEFAULT '',
    user_verified    boolean NOT NULL DEFAULT false,
    backup_eligible  boolean NOT NULL DEFAULT false,
    backup_state     boolean NOT NULL DEFAULT false,
    name             varchar(64) NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_used_at     timestamptz,
    CONSTRAINT admin_webauthn_credentials_credential_id_key UNIQUE (credential_id),
    CONSTRAINT admin_webauthn_credentials_name_check CHECK (length(btrim(name)) > 0)
);
CREATE INDEX idx_admin_webauthn_credentials_admin ON admin_webauthn_credentials (admin_id);

COMMENT ON TABLE admin_webauthn_credentials IS
    'Platform console WebAuthn authenticators (public keys only). The relying party is the console origin.';

CREATE TABLE admin_recovery_codes (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id   uuid NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    code_hash  text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at    timestamptz,
    CONSTRAINT admin_recovery_codes_hash_key UNIQUE (admin_id, code_hash)
);
CREATE INDEX idx_admin_recovery_codes_unused ON admin_recovery_codes (admin_id) WHERE used_at IS NULL;

COMMENT ON TABLE admin_recovery_codes IS
    'One-time console recovery codes (SHA-256 of high-entropy codes). A used code keeps used_at.';

-- One open ceremony per console session and purpose. Taken (deleted) by the
-- finishing request, so a challenge is never accepted twice.
CREATE TABLE admin_webauthn_ceremonies (
    session_id   uuid NOT NULL REFERENCES admin_sessions (id) ON DELETE CASCADE,
    purpose      text NOT NULL CHECK (purpose IN ('register', 'login', 'step_up')),
    session_data bytea NOT NULL,
    expires_at   timestamptz NOT NULL,
    PRIMARY KEY (session_id, purpose)
);
