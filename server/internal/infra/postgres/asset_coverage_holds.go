package postgres

// Coverage holds (RFC-093, not_claimed): the unclaimed-run streak of each
// capability per tenant, the pause it sets and the fleet fingerprint that
// lifts it. Every statement is scoped to one tenant.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RecordRunClaim adds one to the capability's streak for an unclaimed run
// and resets it for any other; it returns the new streak.
func (r *AssetCoverageRepository) RecordRunClaim(ctx context.Context, tenantID shared.ID, capability string, unclaimed bool) (int, error) {
	var streak int
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO asset_coverage_holds (tenant_id, capability, unclaimed_streak)
		VALUES ($1, $2, CASE WHEN $3 THEN 1 ELSE 0 END)
		ON CONFLICT (tenant_id, capability) DO UPDATE
		SET unclaimed_streak = CASE WHEN $3 THEN LEAST(asset_coverage_holds.unclaimed_streak + 1, 1000) ELSE 0 END,
		    probe_at = CASE WHEN $3 THEN asset_coverage_holds.probe_at END,
		    updated_at = now()
		RETURNING unclaimed_streak`,
		tenantID.String(), coverage.Clip(capability, coverage.MaxCodeLen), unclaimed).Scan(&streak)
	if err != nil {
		return 0, fmt.Errorf("record coverage run claim: %w", err)
	}
	return streak, nil
}

// Holds returns the tenant's holds with a streak.
func (r *AssetCoverageRepository) Holds(ctx context.Context, tenantID shared.ID) (map[string]coverage.Hold, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT capability, unclaimed_streak, fingerprint, probe_at
		FROM asset_coverage_holds WHERE tenant_id = $1 AND unclaimed_streak > 0`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list coverage holds: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]coverage.Hold{}
	for rows.Next() {
		var (
			h     coverage.Hold
			probe sql.NullTime
		)
		if err := rows.Scan(&h.Capability, &h.Streak, &h.Fingerprint, &probe); err != nil {
			return nil, err
		}
		if probe.Valid {
			t := probe.Time
			h.ProbeAt = &t
		}
		out[h.Capability] = h
	}
	return out, rows.Err()
}

// HoldCapability records the fingerprint and probe time and pauses the
// capability with not_claimed until probeAt: pairs whose time has come,
// failed pairs (their back-off would only start another unclaimed run) and
// pairs paused for another readiness reason. One transaction.
func (r *AssetCoverageRepository) HoldCapability(ctx context.Context, tenantID shared.ID, capability, fingerprint string, probeAt time.Time) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("hold coverage: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO asset_coverage_holds (tenant_id, capability, fingerprint, probe_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, capability) DO UPDATE
		SET fingerprint = EXCLUDED.fingerprint, probe_at = EXCLUDED.probe_at, updated_at = now()`,
		tenantID.String(), capability, coverage.Clip(fingerprint, coverage.MaxCodeLen), probeAt); err != nil {
		return 0, fmt.Errorf("hold coverage: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE asset_coverage c SET state = 'paused', reason = $3, next_due_at = $4, updated_at = now()
		WHERE c.tenant_id = $1 AND c.capability = $2 AND c.vantage = ''
		  AND ((c.state IN `+plannableStatesSQL+` AND (c.next_due_at IS NULL OR c.next_due_at <= now()))
		       OR c.state = 'failed'
		       OR (c.state = 'paused' AND c.reason = ANY($5::text[])))`,
		tenantID.String(), capability, coverage.ReadyNotClaimed, probeAt, pq.Array(coverage.ReadinessReasons()))
	if err != nil {
		return 0, fmt.Errorf("hold coverage: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("hold coverage: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ResumeNow makes the capability's pairs paused for a readiness reason due
// now, whatever their retry time.
func (r *AssetCoverageRepository) ResumeNow(ctx context.Context, tenantID shared.ID, capability string) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE asset_coverage c SET state = 'due', reason = '', next_due_at = now(), updated_at = now()
		WHERE c.tenant_id = $1 AND c.capability = $2 AND c.vantage = ''
		  AND c.state = 'paused' AND c.reason = ANY($3::text[])`,
		tenantID.String(), capability, pq.Array(coverage.ReadinessReasons()))
	if err != nil {
		return 0, fmt.Errorf("resume coverage: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// FleetFingerprint hashes what decides whether the tenant's work can be
// claimed. Only slow-changing columns: never heartbeats, health or load,
// so it changes when an administrator or a sensor's report changes the
// fleet, not every minute. The platform sensors' part is the same for
// every tenant and holds no tenant data. The hash never leaves the server.
func (r *AssetCoverageRepository) FleetFingerprint(ctx context.Context, tenantID shared.ID) (string, error) {
	var fp string
	err := r.db.QueryRowContext(ctx, `
		SELECT md5(concat_ws('|',
		  (SELECT string_agg(concat_ws(',', s.id, s.status, s.effective_tools::text, s.effective_capabilities::text,
		                               s.reported_local_policy->>'state', s.reported_local_policy->>'digest',
		                               s.reported_local_policy->>'kill_switch', s.accepts_unzoned_jobs, g.version),
		                     ';' ORDER BY s.id)
		     FROM sensors s
		     LEFT JOIN sensor_grants g ON g.tenant_id = s.tenant_id AND g.sensor_id = s.id
		    WHERE s.tenant_id = $1 AND s.scope = 'organization'),
		  (SELECT string_agg(z.zone_id::text || ':' || z.sensor_id::text, ';' ORDER BY z.zone_id, z.sensor_id)
		     FROM scan_zone_sensors z WHERE z.tenant_id = $1),
		  (SELECT COALESCE(t.shared_sensors_access, '') FROM tenants t WHERE t.id = $1),
		  (SELECT string_agg(concat_ws(',', s.id, s.status, s.effective_tools::text), ';' ORDER BY s.id)
		     FROM sensors s WHERE s.scope = 'instance')))`, tenantID.String()).Scan(&fp)
	if err != nil {
		return "", fmt.Errorf("fleet fingerprint: %w", err)
	}
	return fp, nil
}
