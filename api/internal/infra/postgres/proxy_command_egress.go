package postgres

// The proxy path the platform handed each pooled job, and the job's proxy
// verdict (docs/architecture/sensor-proxies.md, "Task-reported proxy
// faults"). Every statement is tenant-scoped; a record names only a command
// of the tenant held by the named sensor and only endpoints of the named
// pool, and the pool reference is a composite (tenant_id, pool_id) key.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// maxTaskSamples bounds the verdicts read for one window.
const maxTaskSamples = 5000

// RecordCommandEgress stores the egress a claimed command was handed. The
// command must be the tenant's and held by the sensor; endpoint ids that are
// not the pool's are dropped. A repeat of the claim under the same epoch
// replaces the endpoints of a record that has no verdict yet.
func (r *ProxyPoolRepository) RecordCommandEgress(ctx context.Context, rec proxypool.CommandEgress) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO proxy_command_egress (command_id, lease_epoch, tenant_id, sensor_id, pool_id, pool_revision, applies_to, endpoint_ids)
		SELECT c.id, $2, c.tenant_id, $4, p.id, $6, $7,
		       ARRAY(SELECT e.id FROM proxy_endpoints e
		             WHERE e.tenant_id = p.tenant_id AND e.pool_id = p.id AND e.id::text = ANY($8::text[]))
		FROM commands c
		JOIN proxy_pools p ON p.tenant_id = c.tenant_id AND p.id = $5
		WHERE c.id = $1 AND c.tenant_id = $3 AND c.sensor_id = $4
		ON CONFLICT (command_id, lease_epoch) DO UPDATE
		   SET pool_id = EXCLUDED.pool_id, pool_revision = EXCLUDED.pool_revision,
		       applies_to = EXCLUDED.applies_to, endpoint_ids = EXCLUDED.endpoint_ids, assigned_at = now()
		 WHERE proxy_command_egress.tenant_id = EXCLUDED.tenant_id
		   AND proxy_command_egress.sensor_id = EXCLUDED.sensor_id
		   AND proxy_command_egress.verdict IS NULL`,
		rec.CommandID.String(), rec.LeaseEpoch, rec.TenantID.String(), rec.SensorID.String(), rec.PoolID.String(),
		rec.Revision, rec.AppliesTo, pq.Array(rec.EndpointIDs))
	if err != nil {
		return fmt.Errorf("record command egress: %w", err)
	}
	return nil
}

// CloseCommandEgress sets the verdict of the open record of a command for
// the sensor and epoch it was handed under and returns that record.
func (r *ProxyPoolRepository) CloseCommandEgress(ctx context.Context, tenantID, commandID, sensorID shared.ID, leaseEpoch int,
	v proxypool.TaskVerdict, at time.Time,
) (*proxypool.CommandEgress, error) {
	var (
		pool, applies string
		revision      int
		eps           []string
	)
	err := r.db.QueryRowContext(ctx, `
		UPDATE proxy_command_egress SET verdict = $5, proxy_faults = $6, verdict_at = $7
		 WHERE tenant_id = $1 AND command_id = $2 AND sensor_id = $3 AND lease_epoch = $4 AND verdict IS NULL
		RETURNING pool_id, pool_revision, applies_to, endpoint_ids::text[]`,
		tenantID.String(), commandID.String(), sensorID.String(), leaseEpoch, v.Verdict, max(v.Faults, 0), at).
		Scan(&pool, &revision, &applies, pq.Array(&eps))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("close command egress: %w", err)
	}
	return &proxypool.CommandEgress{TenantID: tenantID, CommandID: commandID, SensorID: sensorID, LeaseEpoch: leaseEpoch,
		PoolID: shared.MustIDFromString(pool), Revision: revision, AppliesTo: applies, EndpointIDs: eps}, nil
}

// TaskSamples returns the verdicts on a pool's jobs since a time, newest
// first, at most maxTaskSamples.
func (r *ProxyPoolRepository) TaskSamples(ctx context.Context, tenantID, poolID shared.ID, since time.Time) ([]proxypool.TaskSample, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT endpoint_ids::text[], verdict = $4, verdict_at FROM proxy_command_egress
		 WHERE tenant_id = $1 AND pool_id = $2 AND verdict IS NOT NULL AND verdict_at >= $3
		 ORDER BY verdict_at DESC LIMIT `+fmt.Sprint(maxTaskSamples),
		tenantID.String(), poolID.String(), since, proxypool.VerdictProxyFault)
	if err != nil {
		return nil, fmt.Errorf("list proxy task samples: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []proxypool.TaskSample{}
	for rows.Next() {
		var s proxypool.TaskSample
		if err := rows.Scan(pq.Array(&s.EndpointIDs), &s.Fault, &s.At); err != nil {
			return nil, fmt.Errorf("scan proxy task sample: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
