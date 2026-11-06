-- Asset liveness (docs/architecture/asset-liveness.md): per asset, the
-- evidence the coverage loop collects about whether the asset is still there
-- (answers, no answers, names without an address) and the state decided from
-- it: unknown, alive, unreachable, unresolvable or gone.
CREATE TABLE IF NOT EXISTS asset_liveness (
    tenant_id         uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    asset_id          uuid        NOT NULL,
    state             varchar(16) NOT NULL DEFAULT 'unknown',
    reason            varchar(32) NOT NULL DEFAULT '',
    state_since       timestamptz,
    last_checked_at   timestamptz,
    last_checked_by   varchar(80) NOT NULL DEFAULT '',
    last_kind         varchar(16) NOT NULL DEFAULT '',
    last_capability   varchar(64) NOT NULL DEFAULT '',
    last_outcome      varchar(64) NOT NULL DEFAULT '',
    last_alive_at     timestamptz,
    last_resolved_at  timestamptz,
    reach_fails       smallint    NOT NULL DEFAULT 0,
    reach_fail_since  timestamptz,
    reach_fail_last   timestamptz,
    reach_observers   text[]      NOT NULL DEFAULT '{}',
    dns_fails         smallint    NOT NULL DEFAULT 0,
    dns_fail_since    timestamptz,
    dns_fail_last     timestamptz,
    nx_count          smallint    NOT NULL DEFAULT 0,
    nx_since          timestamptz,
    nx_last           timestamptz,
    nx_observers      text[]      NOT NULL DEFAULT '{}',
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_liveness PRIMARY KEY (tenant_id, asset_id),
    CONSTRAINT fk_asset_liveness_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_liveness_state
        CHECK (state IN ('unknown', 'alive', 'unreachable', 'unresolvable', 'gone')),
    CONSTRAINT chk_asset_liveness_counts CHECK (reach_fails >= 0 AND dns_fails >= 0 AND nx_count >= 0),
    CONSTRAINT chk_asset_liveness_observers
        CHECK (cardinality(reach_observers) <= 8 AND cardinality(nx_observers) <= 8)
);

COMMENT ON TABLE asset_liveness IS
    'Per-asset liveness evidence from the coverage loop and the state decided from it (unknown, alive, unreachable, unresolvable, gone).';

CREATE INDEX IF NOT EXISTS idx_asset_liveness_state
    ON asset_liveness (tenant_id, state) WHERE state <> 'alive';

ALTER TABLE asset_liveness ENABLE ROW LEVEL SECURITY;
CREATE POLICY asset_liveness_tenant_isolation ON asset_liveness
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

-- Seed the evidence from the coverage ledger so the first pass does not
-- start from nothing. The ledger keeps a streak count and the last attempt,
-- not when the streak began, so the start is estimated from the recheck
-- schedule (1, 3, 7 days, then weekly) without its jitter: the estimate is
-- never earlier than the truth, which can only delay a state. Observers of
-- an NXDOMAIN streak are not in the ledger: seeded streaks count as one
-- observer (the longer window). The state is left unknown; the next liveness
-- pass decides it.
WITH pairs AS (
    SELECT c.tenant_id, c.asset_id, c.capability, c.state, c.reason, c.last_outcome,
           c.fail_streak, c.last_attempt_at, c.last_success_at, c.unreached_from,
           c.capability IN ('probe.http', 'scan.ports', 'vuln.templates', 'crawl.web', 'dast.web') AS reach,
           c.last_attempt_at - CASE
               WHEN c.fail_streak <= 1 THEN interval '0'
               WHEN c.fail_streak = 2 THEN interval '1 day'
               WHEN c.fail_streak = 3 THEN interval '4 days'
               ELSE interval '4 days' + interval '7 days' * (least(c.fail_streak, 100) - 3)
           END AS streak_since
    FROM asset_coverage c
    WHERE c.vantage = '' AND c.last_attempt_at IS NOT NULL
), per_asset AS (
    SELECT tenant_id, asset_id,
           max(last_success_at) FILTER (WHERE reach) AS alive_at,
           max(last_success_at) FILTER (WHERE capability = 'resolve.dns' AND last_outcome = 'ok') AS resolved_at,
           max(fail_streak) FILTER (WHERE reach AND state = 'paused' AND reason IN ('unreachable', 'timeout')) AS reach_n,
           min(streak_since) FILTER (WHERE reach AND state = 'paused' AND reason IN ('unreachable', 'timeout')) AS reach_since,
           max(last_attempt_at) FILTER (WHERE reach AND state = 'paused' AND reason IN ('unreachable', 'timeout')) AS reach_last,
           COALESCE(array_agg(DISTINCT unreached_from) FILTER (WHERE reach AND state = 'paused'
               AND reason IN ('unreachable', 'timeout') AND unreached_from <> ''), '{}') AS reach_obs,
           max(fail_streak) FILTER (WHERE (capability = 'resolve.dns' AND last_outcome = 'no_answer')
               OR (state = 'blocked' AND reason = 'unresolvable')) AS nx_n,
           min(streak_since) FILTER (WHERE (capability = 'resolve.dns' AND last_outcome = 'no_answer')
               OR (state = 'blocked' AND reason = 'unresolvable')) AS nx_since,
           max(last_attempt_at) FILTER (WHERE (capability = 'resolve.dns' AND last_outcome = 'no_answer')
               OR (state = 'blocked' AND reason = 'unresolvable')) AS nx_last,
           max(fail_streak) FILTER (WHERE (capability = 'resolve.dns' AND last_outcome = 'no_answer')
               OR (state = 'blocked' AND reason IN ('unresolvable', 'resolver_failed'))) AS dns_n,
           min(streak_since) FILTER (WHERE (capability = 'resolve.dns' AND last_outcome = 'no_answer')
               OR (state = 'blocked' AND reason IN ('unresolvable', 'resolver_failed'))) AS dns_since,
           max(last_attempt_at) FILTER (WHERE (capability = 'resolve.dns' AND last_outcome = 'no_answer')
               OR (state = 'blocked' AND reason IN ('unresolvable', 'resolver_failed'))) AS dns_last
    FROM pairs
    GROUP BY tenant_id, asset_id
)
INSERT INTO asset_liveness (tenant_id, asset_id, last_alive_at, last_resolved_at,
                            reach_fails, reach_fail_since, reach_fail_last, reach_observers,
                            dns_fails, dns_fail_since, dns_fail_last,
                            nx_count, nx_since, nx_last)
SELECT p.tenant_id, p.asset_id, p.alive_at, COALESCE(p.resolved_at, p.alive_at),
       CASE WHEN p.reach_n > 0 AND (p.alive_at IS NULL OR p.alive_at < p.reach_since) THEN least(p.reach_n, 32767) ELSE 0 END,
       CASE WHEN p.reach_n > 0 AND (p.alive_at IS NULL OR p.alive_at < p.reach_since) THEN p.reach_since END,
       CASE WHEN p.reach_n > 0 AND (p.alive_at IS NULL OR p.alive_at < p.reach_since) THEN p.reach_last END,
       CASE WHEN p.reach_n > 0 AND (p.alive_at IS NULL OR p.alive_at < p.reach_since) THEN p.reach_obs[1:8] ELSE '{}' END,
       CASE WHEN p.dns_ok THEN least(p.dns_n, 32767) ELSE 0 END,
       CASE WHEN p.dns_ok THEN p.dns_since END, CASE WHEN p.dns_ok THEN p.dns_last END,
       CASE WHEN p.dns_ok AND p.nx_n > 0 THEN least(p.nx_n, 32767) ELSE 0 END,
       CASE WHEN p.dns_ok AND p.nx_n > 0 THEN p.nx_since END, CASE WHEN p.dns_ok AND p.nx_n > 0 THEN p.nx_last END
FROM (SELECT pa.*,
             -- A DNS streak counts only when nothing answered or resolved after it began.
             pa.dns_n > 0 AND (greatest(pa.alive_at, pa.resolved_at) IS NULL
                               OR greatest(pa.alive_at, pa.resolved_at) < pa.dns_since) AS dns_ok
      FROM per_asset pa) p
JOIN assets a ON a.tenant_id = p.tenant_id AND a.id = p.asset_id AND a.deleted_at IS NULL
WHERE p.alive_at IS NOT NULL OR p.resolved_at IS NOT NULL OR p.reach_n > 0 OR p.dns_n > 0
ON CONFLICT DO NOTHING;
