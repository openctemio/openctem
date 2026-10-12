package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// FindingSLARestartRepository writes the fresh SLA deadline a regression gets
// (RFC-039 D2).
type FindingSLARestartRepository struct {
	db *DB
}

// NewFindingSLARestartRepository creates the repository.
func NewFindingSLARestartRepository(db *DB) *FindingSLARestartRepository {
	return &FindingSLARestartRepository{db: db}
}

// openStatusesForSLA are the statuses whose SLA clock runs.
var openStatusesForSLA = []string{"new", "confirmed", "in_progress", "fix_applied", "validated_fixed"} //nolint:gochecknoglobals // static list

// LoadRegressionCandidates returns the tenant's open findings among ids.
func (r *FindingSLARestartRepository) LoadRegressionCandidates(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]sladom.RegressionCandidate, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	strs := make([]string, 0, len(ids))
	for _, id := range ids {
		strs = append(strs, id.String())
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, asset_id, COALESCE(priority_class, ''), severity, sla_deadline, COALESCE(sla_status, '')
		FROM findings
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND status = ANY($3)`,
		tenantID.String(), pq.Array(strs), pq.Array(openStatusesForSLA))
	if err != nil {
		return nil, fmt.Errorf("load regression candidates: %w", err)
	}
	defer rows.Close()
	out := make([]sladom.RegressionCandidate, 0, len(ids))
	for rows.Next() {
		var (
			idStr    string
			assetID  sql.NullString
			c        sladom.RegressionCandidate
			deadline sql.NullTime
		)
		if err := rows.Scan(&idStr, &assetID, &c.PriorityClass, &c.Severity, &deadline, &c.SLAStatus); err != nil {
			return nil, fmt.Errorf("scan regression candidate: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		c.FindingID = id
		if assetID.Valid {
			c.AssetID, _ = shared.IDFromString(assetID.String)
		}
		if deadline.Valid {
			d := deadline.Time
			c.SLADeadline = &d
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RestartSLA writes the new deadline and the sla_restarted activity together,
// only while the finding is still open.
func (r *FindingSLARestartRepository) RestartSLA(ctx context.Context, tenantID shared.ID, rs sladom.RegressionRestart) (bool, error) {
	changes := map[string]any{
		"reason":              sladom.RegressionRestartReason,
		"trigger":             rs.Trigger,
		"sla_deadline":        rs.Deadline.UTC().Format(time.RFC3339),
		"restarted_at":        rs.RestartedAt.UTC().Format(time.RFC3339),
		"previous_sla_status": rs.PreviousStatus,
	}
	if rs.PreviousDeadline != nil {
		changes["previous_sla_deadline"] = rs.PreviousDeadline.UTC().Format(time.RFC3339)
	}
	raw, err := json.Marshal(changes)
	if err != nil {
		return false, fmt.Errorf("marshal sla restart: %w", err)
	}
	wrote := false
	err = r.db.Transaction(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE findings SET sla_deadline = $3, sla_status = 'on_track', updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2 AND status = ANY($4)`,
			tenantID.String(), rs.FindingID.String(), rs.Deadline, pq.Array(openStatusesForSLA))
		if err != nil {
			return fmt.Errorf("restart sla: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO finding_activities (id, tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, created_at)
			VALUES ($1, $2, $3, $4, 'system', $5, $6, 'auto', NOW())`,
			shared.NewID().String(), tenantID.String(), rs.FindingID.String(),
			string(vulnerability.ActivitySLARestarted), "system: "+rs.Trigger, raw); err != nil {
			return fmt.Errorf("record sla restart: %w", err)
		}
		wrote = true
		return nil
	})
	return wrote, err
}
