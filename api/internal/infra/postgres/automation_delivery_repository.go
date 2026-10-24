package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AutomationDeliveryRepository stores what automation steps sent or would
// have sent (RFC-125 §5). Every query carries the tenant.
type AutomationDeliveryRepository struct {
	db *DB
}

// NewAutomationDeliveryRepository creates an AutomationDeliveryRepository.
func NewAutomationDeliveryRepository(db *DB) *AutomationDeliveryRepository {
	return &AutomationDeliveryRepository{db: db}
}

var _ automation.DeliveryRepository = (*AutomationDeliveryRepository)(nil)

// Record stores d (its payload cut to the allow-list); a repeat of the same
// idempotency key is ignored. The run must belong to d's tenant.
func (r *AutomationDeliveryRepository) Record(ctx context.Context, d *automation.Delivery) error {
	payload, err := json.Marshal(automation.DeliveryPayload(d.Payload))
	if err != nil {
		return fmt.Errorf("marshal delivery payload: %w", err)
	}
	if d.ID.IsZero() {
		d.ID = shared.NewID()
	}
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now()
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO automation_deliveries (id, tenant_id, run_id, node_key, channel, target, mode, status, attempts,
		                                   idempotency_key, payload, external_ref, error, created_at)
		SELECT $1, $2, ru.id, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		  FROM automation_runs ru WHERE ru.tenant_id = $2 AND ru.id = $3
		ON CONFLICT (tenant_id, idempotency_key) DO NOTHING`,
		d.ID.String(), d.TenantID.String(), d.RunID.String(), d.NodeKey, d.Channel, truncate(d.Target, 255),
		string(d.Mode), string(d.Status), d.Attempts, d.IdempotencyKey, payload, truncate(d.ExternalRef, 255),
		truncate(d.Error, 1000), d.CreatedAt)
	if err != nil {
		return fmt.Errorf("record automation delivery: %w", err)
	}
	return nil
}

// ListByRun lists the deliveries of one run of the tenant, oldest first.
func (r *AutomationDeliveryRepository) ListByRun(ctx context.Context, tenantID, runID shared.ID) ([]*automation.Delivery, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, run_id, node_key, channel, target, mode, status, attempts, idempotency_key, payload, external_ref, error, created_at
		  FROM automation_deliveries WHERE tenant_id = $1 AND run_id = $2 ORDER BY created_at, id LIMIT 500`,
		tenantID.String(), runID.String())
	if err != nil {
		return nil, fmt.Errorf("list automation deliveries: %w", err)
	}
	defer rows.Close()
	var out []*automation.Delivery
	for rows.Next() {
		d := &automation.Delivery{TenantID: tenantID}
		var id, run, mode, status string
		var payload []byte
		if err := rows.Scan(&id, &run, &d.NodeKey, &d.Channel, &d.Target, &mode, &status, &d.Attempts,
			&d.IdempotencyKey, &payload, &d.ExternalRef, &d.Error, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.ID, _ = shared.IDFromString(id)
		d.RunID, _ = shared.IDFromString(run)
		d.Mode, d.Status = automation.Mode(mode), automation.DeliveryStatus(status)
		_ = json.Unmarshal(payload, &d.Payload)
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteExpiredRuns deletes simulate runs older than simulateBefore and live
// runs older than liveBefore (steps and deliveries go with them), at most
// limit per call. It returns how many runs it deleted.
func (r *AutomationDeliveryRepository) DeleteExpiredRuns(ctx context.Context, simulateBefore, liveBefore time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM automation_runs WHERE id IN (
		    SELECT id FROM automation_runs
		     WHERE status NOT IN ('pending', 'running')
		       AND ((mode = 'simulate' AND created_at < $1) OR (mode = 'live' AND created_at < $2))
		     LIMIT $3)`, simulateBefore, liveBefore, limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired automation runs: %w", err)
	}
	return res.RowsAffected()
}
