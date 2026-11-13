-- Sign-up events for the platform console (docs/architecture/signup-activity.md).
-- One row per account created, organization created and access request
-- submitted. Aggregate data only: the registrable email domain and the
-- client network prefix (/24 for IPv4, /48 for IPv6), never the address
-- itself, the email local part, a name or a user agent. Rows are kept 90
-- days (signup-event-retention controller). tenant_id and user_id are
-- cleared when the organization or the account goes, and account erasure
-- clears user_id.
CREATE TABLE IF NOT EXISTS signup_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind varchar(32) NOT NULL,
    source varchar(32) NOT NULL,
    email_domain varchar(253),
    ip_prefix cidr,
    tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL,
    user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_signup_events_kind CHECK (kind IN ('account_created', 'organization_created', 'access_requested')),
    CONSTRAINT chk_signup_events_source CHECK (source ~ '^[a-z_]{1,32}$'),
    CONSTRAINT chk_signup_events_prefix CHECK (ip_prefix IS NULL
        OR (family(ip_prefix) = 4 AND masklen(ip_prefix) = 24)
        OR (family(ip_prefix) = 6 AND masklen(ip_prefix) = 48))
);
CREATE INDEX IF NOT EXISTS idx_signup_events_occurred ON signup_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_signup_events_kind_occurred ON signup_events (kind, occurred_at DESC);
-- The foreign keys' ON DELETE SET NULL looks rows up by these columns.
CREATE INDEX IF NOT EXISTS idx_signup_events_tenant ON signup_events (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_signup_events_user ON signup_events (user_id) WHERE user_id IS NOT NULL;
