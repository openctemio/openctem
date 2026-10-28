-- Resolution state of an asset's host name: whether the name resolves in DNS
-- right now, when it last did, and how many checks in a row it failed.
-- Resolve stages and sensor refusals ("cannot resolve") feed it; an active
-- stage leaves out a name that is not_resolving, passive stages keep taking
-- it, so it comes back by itself when it resolves again. This is not an
-- ownership or scope decision.
--
-- Also clears the wildcard-only marks (asset_wildcard_dns): until now a name
-- the filtered resolver did not report was marked, which also caught names
-- that simply do not resolve. The marks held no proof of a wildcard record,
-- so all go; the next filtered resolution marks only names that resolve
-- through a probed wildcard record of their parent zone.
--
-- Live impact: a new, empty table (state starts unknown = no row); the
-- DELETE touches only asset_wildcard_dns, a small table.

CREATE TABLE IF NOT EXISTS asset_resolution (
    tenant_id     uuid        NOT NULL,
    asset_id      uuid        NOT NULL,
    state         varchar(16) NOT NULL DEFAULT 'resolving',
    resolved_at   timestamptz,
    checked_at    timestamptz NOT NULL,
    failures      integer     NOT NULL DEFAULT 0,
    source        varchar(32) NOT NULL DEFAULT '',
    CONSTRAINT pk_asset_resolution PRIMARY KEY (tenant_id, asset_id),
    CONSTRAINT fk_asset_resolution_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_resolution_state CHECK (state IN ('resolving', 'not_resolving')),
    CONSTRAINT chk_asset_resolution_failures CHECK (failures >= 0)
);

CREATE INDEX IF NOT EXISTS idx_asset_resolution_not_resolving
    ON asset_resolution (tenant_id, asset_id) WHERE state = 'not_resolving';

COMMENT ON TABLE asset_resolution IS
    'Whether an asset''s host name resolves: last resolved time, consecutive failed checks, state. Active stages skip not_resolving names; passive stages keep them.';

DELETE FROM asset_wildcard_dns;
