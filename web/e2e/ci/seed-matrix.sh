#!/usr/bin/env bash
# Extra rows for the layout matrix (layout-matrix.sh, .github/workflows/
# layout-matrix.yml), added after seed.sh so the settings lists are seen with
# data:
#   - 4 API keys (varied scopes, expiry, one revoked); key_hash is a digest of a
#     fixed label and key_prefix a made-up prefix: no usable key exists
#   - 3 SLA policies (default, a strict one, an inactive one)
#   - 3 notification channels (Slack, Teams, a webhook in an error state)
# Fixture data only: example.com names and RFC 5737 addresses.
#
# Requires: docker (runs psql from PSQL_IMAGE, default postgres:17-alpine).
# Env: E2E_DATABASE_URL (make-env.sh), E2E_TENANT_SLUG and E2E_USER_EMAIL
# (seed.sh output), COMPOSE_NETWORK (default octe2e-ci_default).
set -euo pipefail
DATABASE_URL="${E2E_DATABASE_URL:?set E2E_DATABASE_URL}"
SLUG="${E2E_TENANT_SLUG:?set E2E_TENANT_SLUG (seed.sh output)}"
EMAIL="${E2E_USER_EMAIL:?set E2E_USER_EMAIL (seed.sh output)}"
NETWORK="${COMPOSE_NETWORK:-octe2e-ci_default}"

docker run --rm -i --network "$NETWORK" -e PGCONNECT_TIMEOUT=10 "${PSQL_IMAGE:-postgres:17-alpine}" \
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtA -v slug="$SLUG" -v email="$EMAIL" >/dev/null <<'SQL'
SELECT id AS tid FROM tenants WHERE slug = :'slug' \gset
SELECT id AS uid FROM users WHERE email = :'email' \gset

INSERT INTO api_keys (tenant_id, user_id, created_by, name, description, key_hash, key_prefix, scopes,
                      status, expires_at, last_used_at, last_used_ip, use_count, revoked_at, revoked_by)
VALUES
 (:'tid', :'uid', :'uid', 'CI pipeline (read findings)', 'Used by the build pipeline to read open findings',
  encode(sha256('seed-ci'::bytea), 'hex'), 'oc_ci7f', '{findings:read,assets:read}', 'active',
  now() + interval '80 days', now() - interval '2 hours', '192.0.2.10', 1834, NULL, NULL),
 (:'tid', :'uid', :'uid', 'Findings feed for the SIEM', 'Pulls findings into the SIEM every 15 minutes',
  encode(sha256('seed-siem'::bytea), 'hex'), 'oc_s13m', '{findings:read}', 'active',
  now() + interval '6 days', now() - interval '9 minutes', '198.51.100.24', 52011, NULL, NULL),
 (:'tid', :'uid', :'uid', 'Asset import from CMDB (cmdb.example.com)', NULL,
  encode(sha256('seed-cmdb'::bytea), 'hex'), 'oc_cmdb', '{assets:read,assets:write,scans:read,findings:read}', 'active',
  NULL, NULL, NULL, 0, NULL, NULL),
 (:'tid', :'uid', :'uid', 'Old ticket sync', 'Replaced by the Jira integration',
  encode(sha256('seed-old'::bytea), 'hex'), 'oc_o1d0', '{findings:read,findings:write}', 'revoked',
  now() - interval '20 days', now() - interval '40 days', '203.0.113.7', 310, now() - interval '30 days', :'uid');

INSERT INTO sla_policies (tenant_id, name, description, is_default, critical_days, high_days, medium_days,
                          low_days, info_days, warning_threshold_percent, is_active)
SELECT :'tid', 'Standard remediation', 'Default windows for every asset', true, 7, 30, 60, 90, 180, 75, true
WHERE NOT EXISTS (SELECT 1 FROM sla_policies WHERE tenant_id = :'tid' AND is_default AND asset_id IS NULL AND practice IS NULL);
INSERT INTO sla_policies (tenant_id, name, description, is_default, critical_days, high_days, medium_days,
                          low_days, info_days, warning_threshold_percent, is_active)
VALUES
 (:'tid', 'Internet-facing production (strict)', 'Shorter windows for public services on example.com', false, 2, 7, 21, 45, 90, 60, true),
 (:'tid', 'Lab and test hosts', NULL, false, 30, 60, 120, 180, 365, 80, false);

WITH ch AS (
  INSERT INTO integrations (tenant_id, name, description, category, provider, status, status_message,
                            auth_type, base_url, last_sync_at, config, created_by)
  VALUES
   (:'tid', 'Security alerts (#sec-alerts)', 'Critical and high findings', 'notification', 'slack', 'connected', NULL,
    'token', NULL, now() - interval '1 hour', '{}', :'uid'),
   (:'tid', 'SOC on-call (Teams)', NULL, 'notification', 'teams', 'connected', NULL,
    'token', NULL, now() - interval '3 hours', '{}', :'uid'),
   (:'tid', 'Ticket intake webhook', 'Posts new exposures to hooks.example.com', 'notification', 'webhook', 'error',
    'POST https://hooks.example.com/intake answered 502 Bad Gateway', 'token', 'https://hooks.example.com/intake',
    now() - interval '2 days', '{}', :'uid')
  RETURNING id, provider)
INSERT INTO integration_notification_extensions (integration_id, enabled_severities, enabled_event_types)
SELECT id,
       CASE provider WHEN 'teams' THEN '["critical","high","medium","low","info"]'::jsonb ELSE '["critical","high"]'::jsonb END,
       '["security_alert","new_finding","new_exposure"]'::jsonb
FROM ch;
SQL
echo "seed-matrix: api keys, sla policies, channels added" >&2
