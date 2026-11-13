-- Representative rows for the upgrade test (.github/scripts/upgrade-test.sh).
--
-- Applied to a database migrated to the PREVIOUS release's schema, as a
-- superuser, before the new migrations run. It must therefore use only columns
-- that exist in every released schema: the identifiers, the NOT NULL columns
-- without a default, and a few stable optional ones. Do not add a column here
-- because the current tree has it; the previous tag does not.
--
-- The point is volume and shape, not realism: several tenants with members, a
-- role grant, assets, findings in several statuses, sources and severities, a sensor
-- per tenant, and audit rows, so a migration that rewrites, renames or
-- backfills a populated table runs against rows. Fixed ids keep the foreign
-- keys readable. Everything is example data (example.com).

\set ON_ERROR_STOP on

BEGIN;

-- 3 tenants, 6 users (2 per tenant), each member of one tenant as `member`
-- (role 00000000-0000-0000-0000-000000000003, seeded by the migrations).
INSERT INTO tenants (id, name, slug)
SELECT ('10000000-0000-0000-0000-' || lpad(g::text, 12, '0'))::uuid, 'Upgrade test ' || g, 'upgrade-test-' || g
FROM generate_series(1, 3) AS g;

INSERT INTO users (id, email)
SELECT ('20000000-0000-0000-0000-' || lpad(g::text, 12, '0'))::uuid, 'upgrade-user-' || g || '@example.com'
FROM generate_series(1, 6) AS g;

INSERT INTO tenant_members (user_id, tenant_id)
SELECT ('20000000-0000-0000-0000-' || lpad(g::text, 12, '0'))::uuid,
       ('10000000-0000-0000-0000-' || lpad(((g + 1) / 2)::text, 12, '0'))::uuid
FROM generate_series(1, 6) AS g;

INSERT INTO user_roles (user_id, tenant_id, role_id)
SELECT ('20000000-0000-0000-0000-' || lpad(g::text, 12, '0'))::uuid,
       ('10000000-0000-0000-0000-' || lpad(((g + 1) / 2)::text, 12, '0'))::uuid,
       '00000000-0000-0000-0000-000000000003'::uuid
FROM generate_series(1, 6) AS g
ON CONFLICT DO NOTHING; -- a trigger may already have granted the default role

-- 25 assets per tenant, three types.
INSERT INTO assets (id, tenant_id, name, asset_type)
SELECT ('30000000-0000-0000-' || lpad(t::text, 4, '0') || '-' || lpad(a::text, 12, '0'))::uuid,
       ('10000000-0000-0000-0000-' || lpad(t::text, 12, '0'))::uuid,
       'host-' || a || '.example.com',
       (ARRAY['domain', 'host', 'repository'])[1 + a % 3]
FROM generate_series(1, 3) AS t, generate_series(1, 25) AS a;

-- 80 findings per tenant: five severities, four sources, three statuses, a third of them
-- on an asset. The fingerprint is unique per tenant.
INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
SELECT ('40000000-0000-0000-' || lpad(t::text, 4, '0') || '-' || lpad(f::text, 12, '0'))::uuid,
       ('10000000-0000-0000-0000-' || lpad(t::text, 12, '0'))::uuid,
       CASE WHEN f % 3 = 0 THEN ('30000000-0000-0000-' || lpad(t::text, 4, '0') || '-' || lpad((1 + f % 25)::text, 12, '0'))::uuid END,
       (ARRAY['sast', 'sca', 'dast', 'secret'])[1 + f % 4],
       (ARRAY['semgrep', 'trivy', 'nuclei', 'betterleaks'])[1 + f % 4],
       'Example finding ' || f,
       (ARRAY['critical', 'high', 'medium', 'low', 'info'])[1 + f % 5],
       'upgrade-test-' || t || '-' || f,
       (ARRAY['new', 'new', 'confirmed', 'in_progress'])[1 + f % 4]
FROM generate_series(1, 3) AS t, generate_series(1, 80) AS f;

-- One sensor per tenant.
INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
SELECT ('50000000-0000-0000-0000-' || lpad(t::text, 12, '0'))::uuid,
       ('10000000-0000-0000-0000-' || lpad(t::text, 12, '0'))::uuid,
       'upgrade-sensor-' || t, 'upgrade-test-hash-' || t, 'upg' || t, 'active'
FROM generate_series(1, 3) AS t;

-- 50 audit rows per tenant.
INSERT INTO audit_logs (tenant_id, action, resource_type)
SELECT ('10000000-0000-0000-0000-' || lpad(t::text, 12, '0'))::uuid, 'upgrade_test.event', 'finding'
FROM generate_series(1, 3) AS t, generate_series(1, 50) AS e;

COMMIT;
