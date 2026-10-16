-- Support access (RFC-063): an organization owner grants a named platform
-- administrator time-boxed, read-only access for one case; the administrator
-- opens support sessions inside the grant from the console. New, empty
-- tables: no lock on populated data.

CREATE TABLE support_grants (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    admin_id    uuid NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    -- Snapshot of who was named, for the organization's history.
    admin_email varchar(255) NOT NULL,
    admin_name  varchar(255) NOT NULL DEFAULT '',
    access_level text NOT NULL DEFAULT 'read' CHECK (access_level IN ('read')),
    scopes      text[] NOT NULL CHECK (cardinality(scopes) > 0 AND scopes <@ ARRAY['findings', 'assets']::text[]),
    reason      text NOT NULL CHECK (length(btrim(reason)) BETWEEN 10 AND 500),
    case_ref    varchar(64),
    granted_by  uuid NOT NULL REFERENCES users (id),
    starts_at   timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    revoked_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT support_grants_window_check
        CHECK (expires_at > starts_at AND expires_at <= starts_at + interval '72 hours'),
    CONSTRAINT support_grants_tenant_id_key UNIQUE (tenant_id, id)
);
CREATE INDEX idx_support_grants_tenant ON support_grants (tenant_id, expires_at DESC);
CREATE INDEX idx_support_grants_admin ON support_grants (admin_id, expires_at DESC);

COMMENT ON TABLE support_grants IS
    'Organization-granted, time-boxed, read-only access of one named platform administrator (RFC-063).';

CREATE TABLE support_sessions (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          uuid NOT NULL,
    grant_id           uuid NOT NULL,
    admin_id           uuid NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    -- The console session that opened it: another console session (a stolen
    -- cookie elsewhere, a new sign-in) cannot use it.
    console_session_id uuid NOT NULL,
    reason             text NOT NULL DEFAULT '',
    started_at         timestamptz NOT NULL DEFAULT now(),
    last_access_at     timestamptz,
    ended_at           timestamptz,
    end_reason         text,
    CONSTRAINT support_sessions_grant_fkey FOREIGN KEY (tenant_id, grant_id)
        REFERENCES support_grants (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_support_sessions_grant ON support_sessions (tenant_id, grant_id);
CREATE INDEX idx_support_sessions_open ON support_sessions (admin_id) WHERE ended_at IS NULL;
