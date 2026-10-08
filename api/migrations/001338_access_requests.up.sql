-- Requests for an organization from people who cannot sign up (sign-up
-- policy admin_only with request access on). A platform administrator
-- approves (the organization is created, the requester owns it) or rejects
-- (docs/architecture/user-onboarding.md, "Request access").
--
-- Platform data, no tenant_id. Data minimisation: the requester's IP is kept
-- only as a hash (rate limits); unconfirmed requests are deleted after 24 h
-- and decided ones after 90 days by the access-request-retention controller.
-- A new, empty table.

CREATE TABLE access_requests (
    id            uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    company       text NOT NULL,
    email         text NOT NULL,
    domain        text NOT NULL,
    note          text NOT NULL DEFAULT '',
    status        text NOT NULL DEFAULT 'unconfirmed',
    ip_hash       text NOT NULL DEFAULT '',
    confirm_hash  text,
    confirmed_at  timestamp with time zone,
    created_at    timestamp with time zone NOT NULL DEFAULT now(),
    decided_at    timestamp with time zone,
    decided_by    uuid,
    created_tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL,
    CONSTRAINT chk_access_requests_status CHECK (status IN ('unconfirmed', 'pending', 'approved', 'rejected')),
    CONSTRAINT chk_access_requests_sizes CHECK (
        char_length(company) <= 200 AND char_length(note) <= 1000 AND char_length(email) <= 320
    )
);

CREATE INDEX idx_access_requests_status_created ON access_requests (status, created_at DESC);
CREATE INDEX idx_access_requests_ip_created ON access_requests (ip_hash, created_at);
CREATE INDEX idx_access_requests_domain_created ON access_requests (domain, created_at);
CREATE UNIQUE INDEX uq_access_requests_confirm_hash ON access_requests (confirm_hash) WHERE confirm_hash IS NOT NULL;
