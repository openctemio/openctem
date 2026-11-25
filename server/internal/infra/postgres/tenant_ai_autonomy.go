package postgres

// The organization's switch and limits on changes AI agents make without a
// person (tenant_ai_settings.autonomy) and the per-hour count of such changes
// (ai_auto_change_counts); docs/architecture/ai-autonomy.md. Every query is
// scoped by tenant_id.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	aidom "github.com/openctemio/openctem/server/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

var _ aidom.AutonomyRepository = (*TenantAISettingsRepository)(nil)

// autonomyJSON is the stored setting. A null limit is unlimited.
type autonomyJSON struct {
	Version   int        `json:"version"`
	Paused    bool       `json:"paused"`
	PausedAt  *time.Time `json:"paused_at,omitempty"`
	PausedBy  string     `json:"paused_by,omitempty"`
	PerHour   *int       `json:"per_hour"`
	PerDay    *int       `json:"per_day"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

// GetAutonomy returns the stored setting; ok is false when none was saved.
func (r *TenantAISettingsRepository) GetAutonomy(ctx context.Context, tenantID shared.ID) (aidom.Autonomy, bool, error) {
	var raw []byte
	err := r.db.QueryRowContext(ctx, `SELECT autonomy FROM tenant_ai_settings WHERE tenant_id = $1`, tenantID.String()).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && len(raw) == 0) {
		return aidom.Autonomy{}, false, nil
	}
	if err != nil {
		return aidom.Autonomy{}, false, fmt.Errorf("read AI autonomy: %w", err)
	}
	var j autonomyJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return aidom.Autonomy{}, false, fmt.Errorf("decode AI autonomy: %w", err)
	}
	return aidom.Autonomy{Paused: j.Paused, PausedAt: j.PausedAt, PausedBy: j.PausedBy, PerHour: j.PerHour, PerDay: j.PerDay,
		UpdatedAt: j.UpdatedAt, UpdatedBy: j.UpdatedBy}, true, nil
}

// SaveAutonomy writes the setting. A missing settings row is created with
// the column defaults (AI stays off until an administrator consents).
func (r *TenantAISettingsRepository) SaveAutonomy(ctx context.Context, tenantID shared.ID, a aidom.Autonomy) error {
	raw, err := json.Marshal(autonomyJSON{Version: 1, Paused: a.Paused, PausedAt: a.PausedAt, PausedBy: a.PausedBy,
		PerHour: a.PerHour, PerDay: a.PerDay, UpdatedAt: a.UpdatedAt, UpdatedBy: a.UpdatedBy})
	if err != nil {
		return fmt.Errorf("encode AI autonomy: %w", err)
	}
	if _, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_ai_settings (tenant_id, autonomy) VALUES ($1, $2::jsonb)
		ON CONFLICT (tenant_id) DO UPDATE SET autonomy = EXCLUDED.autonomy`, tenantID.String(), raw); err != nil {
		return fmt.Errorf("save AI autonomy: %w", err)
	}
	return nil
}

// ReserveAutoChange counts one automatic change when the organization is
// within its limits. A transaction-scoped advisory lock on the organization
// serializes concurrent reservations, so two runs cannot both take the
// last slot. Counts older than two days are dropped on the way.
func (r *TenantAISettingsRepository) ReserveAutoChange(ctx context.Context, tenantID shared.ID, perHour, perDay *int, now time.Time) (bool, error) {
	hour := now.UTC().Truncate(time.Hour)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('ai_auto_change:' || $1::text, 0))`, tenantID.String()); err != nil {
		return false, fmt.Errorf("lock AI change count: %w", err)
	}
	var inHour, inDay int
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(sum(changes) FILTER (WHERE hour_start = $2::timestamptz), 0),
		       COALESCE(sum(changes), 0)
		FROM ai_auto_change_counts
		WHERE tenant_id = $1 AND hour_start > $2::timestamptz - interval '24 hours' AND hour_start <= $2::timestamptz`,
		tenantID, hour).Scan(&inHour, &inDay); err != nil {
		return false, fmt.Errorf("read AI change count: %w", err)
	}
	if (perHour != nil && inHour >= *perHour) || (perDay != nil && inDay >= *perDay) {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ai_auto_change_counts (tenant_id, hour_start, changes) VALUES ($1, $2, 1)
		ON CONFLICT (tenant_id, hour_start) DO UPDATE SET changes = ai_auto_change_counts.changes + 1`,
		tenantID, hour); err != nil {
		return false, fmt.Errorf("count AI change: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ai_auto_change_counts WHERE tenant_id = $1 AND hour_start < $2::timestamptz - interval '48 hours'`,
		tenantID, hour); err != nil {
		return false, fmt.Errorf("trim AI change count: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit AI change count: %w", err)
	}
	return true, nil
}
