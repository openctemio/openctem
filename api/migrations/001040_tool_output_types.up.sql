-- research/27 F3, RFC-046 stage catalogue (docs/rfcs/RFC-046-scans-redesign.md):
-- the tool registry recorded what a tool takes (supported_targets) but not what
-- it produces, so nothing could type-check a chain of scan stages.
--
-- Additive and safe on a populated table: a new column with a constant default
-- (no table rewrite on PostgreSQL 11+), then a small UPDATE of the platform
-- rows the catalogue knows (pkg/domain/stage), as stored type labels ("type"
-- or "type/sub_type": service/http is an HTTP service). Tenant custom tools
-- keep the empty list; the catalogue in code stays the authority and a DB test
-- keeps these values equal to it.
ALTER TABLE tools ADD COLUMN IF NOT EXISTS output_types TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN tools.output_types IS
    'Asset types a report of this tool may create (scan stage catalogue outputs); empty = findings only or unknown';

UPDATE tools AS t
SET output_types = v.outputs
FROM (VALUES
    ('subfinder', ARRAY['domain', 'subdomain']),
    ('dnsx',      ARRAY['domain', 'ip_address', 'subdomain']),
    ('naabu',     ARRAY['host', 'ip_address', 'service/open_port']),
    ('httpx',     ARRAY['certificate', 'ip_address', 'service/http']),
    ('katana',    ARRAY['service/discovered_url'])
) AS v(name, outputs)
WHERE t.tenant_id IS NULL AND t.name = v.name;
