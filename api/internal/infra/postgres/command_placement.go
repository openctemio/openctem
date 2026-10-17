package postgres

// The claim predicates read back for one command (docs/architecture/placement.md):
// the same SQL the poll and the claim use (pendingForSensorWhere), evaluated
// for every sensor of the command's tenant instead of filtering by one.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ command.PlacementReader = (*CommandRepository)(nil)

// PlacementPredicates evaluates the claim predicates of one command of the
// tenant: the job-level ones (not expired, due, hosts free) and, for at
// most maxSensors sensors of the same tenant (by name), the per-sensor ones
// (pinning, zone, tool, refusal, capability, features), with the scans each holds.
// Platform sensors are never the tenant's and never read. A command of
// another tenant is shared.ErrNotFound.
func (r *CommandRepository) PlacementPredicates(ctx context.Context, tenantID, commandID shared.ID, maxSensors int) (command.PlacementJob, []command.SensorClaim, error) {
	var job command.PlacementJob
	var status string
	err := r.db.QueryRowContext(ctx, `
		SELECT commands.status, COALESCE(commands.is_platform_job, FALSE),
		       COALESCE(commands.expires_at IS NULL OR commands.expires_at > NOW(), FALSE),
		       COALESCE(`+scheduledDuePredicate+`, FALSE),
		       COALESCE(`+hostFreePredicate+`, FALSE),
		       COALESCE(commands.error_message = $3, FALSE)
		FROM commands
		WHERE commands.tenant_id = $1 AND commands.id = $2`,
		tenantID.String(), commandID.String(), command.ReleasedBySensorPrefix+command.ReleaseReasonHostsBusy).
		Scan(&status, &job.IsPlatformJob, &job.NotExpired, &job.Due, &job.HostFree, &job.SensorHostsBusy)
	if errors.Is(err, sql.ErrNoRows) {
		return job, nil, fmt.Errorf("%w: command not found", shared.ErrNotFound)
	}
	if err != nil {
		return job, nil, fmt.Errorf("read command placement: %w", err)
	}
	job.Status = command.CommandStatus(status)
	if maxSensors <= 0 || job.IsPlatformJob {
		return job, nil, nil
	}

	// The per-sensor predicates are the poll's, with the sensor bound to the
	// row (ps.id) instead of a parameter, and the capability gate fed the
	// sensor's effective capabilities, the list the poll is given. NULL
	// reads as false, as it does in the poll's WHERE.
	rows, err := r.db.QueryContext(ctx, `
		SELECT ps.id,
		       COALESCE(commands.sensor_id = ps.id OR commands.sensor_id IS NULL, FALSE),
		       COALESCE(`+zoneClaimPredicate("ps.id")+`, FALSE),
		       COALESCE(`+toolClaimPredicate("ps.id")+`, FALSE),
		       COALESCE(`+refusedByPredicate("ps.id")+`, FALSE),
		       COALESCE(`+capabilityClaimPredicate("ps.effective_capabilities")+`, FALSE),
		       COALESCE(`+featureClaimPredicate("ps.id")+`, FALSE),
		       (SELECT count(*) FROM commands held
		         WHERE held.tenant_id = ps.tenant_id AND held.sensor_id = ps.id AND held.type = 'scan'
		           AND held.status IN ('acknowledged', 'running'))
		FROM commands
		JOIN sensors ps ON ps.tenant_id = commands.tenant_id
		WHERE commands.tenant_id = $1 AND commands.id = $2
		  AND COALESCE(ps.scope, 'organization') = 'organization'
		ORDER BY ps.name, ps.id
		LIMIT $3`,
		tenantID.String(), commandID.String(), maxSensors)
	if err != nil {
		return job, nil, fmt.Errorf("read sensor placement: %w", err)
	}
	defer rows.Close()
	var out []command.SensorClaim
	for rows.Next() {
		var c command.SensorClaim
		var id string
		if err := rows.Scan(&id, &c.PinOK, &c.ZoneOK, &c.ToolOK, &c.NotRefused, &c.CapabilityOK, &c.FeaturesOK, &c.HeldScans); err != nil {
			return job, nil, fmt.Errorf("scan sensor placement: %w", err)
		}
		if c.SensorID, err = shared.IDFromString(id); err != nil {
			return job, nil, fmt.Errorf("scan sensor placement: %w", err)
		}
		out = append(out, c)
	}
	return job, out, rows.Err()
}

var _ command.HostHoldersReader = (*CommandRepository)(nil)

// HostHolders reads the pending command's host keys and the tenant's
// acknowledged or running commands that hold a key it conflicts with and
// have not released it (the holder half of hostFreePredicate), most shared
// keys first, at most limit. Keys holds only the command's conflicting keys
// each holder still holds. Tenant-scoped on both sides.
func (r *CommandRepository) HostHolders(ctx context.Context, tenantID, commandID shared.ID, limit int) ([]string, []command.HostHolder, error) {
	var keys []string
	err := r.db.QueryRowContext(ctx, `SELECT host_keys FROM commands WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), commandID.String()).Scan(pq.Array(&keys))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, fmt.Errorf("%w: command not found", shared.ErrNotFound)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read command hosts: %w", err)
	}
	if len(keys) == 0 || limit <= 0 {
		return keys, nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT h.id, h.run_id, h.step_key, h.tool, h.held FROM (
			SELECT hk.id,
			       COALESCE(hk.payload->>'scan_run_id', '') AS run_id,
			       COALESCE(sr.step_key, hk.payload->>'step_key', '') AS step_key,
			       COALESCE(NULLIF(hk.payload->>'scanner', ''), NULLIF(hk.payload->>'preferred_tool', ''), '') AS tool,
			       ARRAY(SELECT DISTINCT ck FROM unnest(`+hostKeyConflictsSQL+`) AS ck
			             WHERE ck = ANY(hk.host_keys)
			               AND ck <> ALL(COALESCE(hk.settled_host_keys, '{}'::text[]))) AS held
			FROM commands
			JOIN commands hk ON hk.tenant_id = commands.tenant_id
			LEFT JOIN scan_run_steps sr ON sr.id = hk.scan_run_step_id
			WHERE commands.tenant_id = $1 AND commands.id = $2
			  AND hk.id <> commands.id
			  AND hk.host_keys IS NOT NULL
			  AND hk.status IN ('acknowledged', 'running')
			  AND hk.host_keys && `+hostKeyConflictsSQL+`
		) h
		WHERE cardinality(h.held) > 0
		ORDER BY cardinality(h.held) DESC, h.id
		LIMIT $3`,
		tenantID.String(), commandID.String(), limit)
	if err != nil {
		return nil, nil, fmt.Errorf("read host holders: %w", err)
	}
	defer rows.Close()
	var out []command.HostHolder
	for rows.Next() {
		var h command.HostHolder
		var id string
		if err := rows.Scan(&id, &h.RunID, &h.StepKey, &h.Tool, pq.Array(&h.Keys)); err != nil {
			return nil, nil, fmt.Errorf("scan host holder: %w", err)
		}
		h.CommandID, _ = shared.IDFromString(id)
		out = append(out, h)
	}
	return keys, out, rows.Err()
}
