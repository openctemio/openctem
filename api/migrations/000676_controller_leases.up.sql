-- RFC-046 §11 (B1, P1.8): named leases for work that must run on one API
-- replica at a time (retention sweeps, threat-intel refresh, per-tenant CT
-- and DNS sweeps). A holder takes a lease row by compare-and-set on its
-- expiry, renews it while it works, and every take bumps the epoch, so a
-- holder that lost its lease can tell. Replaces session advisory locks,
-- which a pooled connection could leak or release on the wrong connection.
--
-- Platform-internal: never exposed through the API. A name may contain a
-- tenant id (per-tenant sweeps), nothing else.
CREATE TABLE IF NOT EXISTS controller_leases (
    name        TEXT PRIMARY KEY,
    holder      TEXT NOT NULL,
    epoch       BIGINT NOT NULL DEFAULT 1,
    expires_at  TIMESTAMPTZ NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_controller_leases_name CHECK (length(name) BETWEEN 1 AND 200),
    CONSTRAINT chk_controller_leases_holder CHECK (length(holder) BETWEEN 1 AND 200)
);
