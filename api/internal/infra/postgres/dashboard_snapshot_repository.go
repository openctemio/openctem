package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// DashboardSnapshotRepository implements dashboard.SnapshotStore
// (migration dashboard_snapshots).
type DashboardSnapshotRepository struct {
	db *DB
}

// NewDashboardSnapshotRepository creates the repository.
func NewDashboardSnapshotRepository(db *DB) *DashboardSnapshotRepository {
	return &DashboardSnapshotRepository{db: db}
}

var _ dashboard.SnapshotStore = (*DashboardSnapshotRepository)(nil)

// GetSnapshot implements dashboard.SnapshotStore.
func (r *DashboardSnapshotRepository) GetSnapshot(ctx context.Context, tenantID, dashboardID shared.ID) (*dashboard.Snapshot, error) {
	var (
		s              dashboard.Snapshot
		kind           string
		owner, lastErr sql.NullString
		next, failed   sql.NullTime
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT tenant_id, dashboard_id, kind, owner_user_id, scope_key, layout_hash, data, computed_at,
		       duration_ms, next_refresh_at, last_error, failed_at, viewed_at
		FROM dash_snapshots WHERE tenant_id = $1 AND dashboard_id = $2`,
		tenantID.String(), dashboardID.String()).Scan(&s.TenantID, &s.DashboardID, &kind, &owner, &s.ScopeKey,
		&s.LayoutHash, &s.Data, &s.ComputedAt, &s.DurationMS, &next, &lastErr, &failed, &s.ViewedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read dashboard snapshot: %w", err)
	}
	s.Kind = dashboard.Kind(kind)
	if owner.Valid {
		if id, perr := shared.IDFromString(owner.String); perr == nil {
			s.OwnerID = id
		}
	}
	if next.Valid {
		s.NextRefreshAt = &next.Time
	}
	if failed.Valid {
		s.FailedAt = &failed.Time
	}
	s.LastError = lastErr.String
	return &s, nil
}

// PutSnapshot implements dashboard.SnapshotStore. The snapshot and the
// dashboard's next_refresh_at change in one transaction, and only for a
// dashboard of this tenant (and, for a personal one, of this owner).
func (r *DashboardSnapshotRepository) PutSnapshot(ctx context.Context, s dashboard.Snapshot) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var owner any
	if s.Kind == dashboard.KindPersonal {
		owner = s.OwnerID.String()
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO dash_snapshots (tenant_id, dashboard_id, kind, owner_user_id, scope_key, layout_hash, data,
		                            computed_at, duration_ms, next_refresh_at, last_error, failed_at, viewed_at)
		SELECT d.tenant_id, d.id, $3::varchar, $4::uuid, $5, $6, $7, $8, $9, $10, NULL, NULL, $8
		FROM user_dashboards d
		WHERE d.tenant_id = $1 AND d.id = $2 AND d.kind = $3::text AND d.user_id IS NOT DISTINCT FROM $4::uuid
		ON CONFLICT ON CONSTRAINT pk_dash_snapshots DO UPDATE SET
		    scope_key = EXCLUDED.scope_key, layout_hash = EXCLUDED.layout_hash, data = EXCLUDED.data,
		    computed_at = EXCLUDED.computed_at, duration_ms = EXCLUDED.duration_ms,
		    next_refresh_at = EXCLUDED.next_refresh_at, last_error = NULL, failed_at = NULL`,
		s.TenantID.String(), s.DashboardID.String(), string(s.Kind), owner, s.ScopeKey, s.LayoutHash, s.Data,
		s.ComputedAt, s.DurationMS, s.NextRefreshAt)
	if err != nil {
		return fmt.Errorf("store dashboard snapshot: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: dashboard", shared.ErrNotFound)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_dashboards SET next_refresh_at = $3 WHERE tenant_id = $1 AND id = $2`,
		s.TenantID.String(), s.DashboardID.String(), s.NextRefreshAt); err != nil {
		return fmt.Errorf("store next refresh: %w", err)
	}
	return tx.Commit()
}

// MarkSnapshotFailed implements dashboard.SnapshotStore.
func (r *DashboardSnapshotRepository) MarkSnapshotFailed(ctx context.Context, tenantID, dashboardID shared.ID, code string, next *time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE dash_snapshots SET last_error = $3, failed_at = now(), next_refresh_at = $4
		WHERE tenant_id = $1 AND dashboard_id = $2`, tenantID.String(), dashboardID.String(), code, next)
	if err != nil {
		return fmt.Errorf("mark dashboard snapshot failed: %w", err)
	}
	return nil
}

// TouchSnapshot implements dashboard.SnapshotStore.
func (r *DashboardSnapshotRepository) TouchSnapshot(ctx context.Context, tenantID, dashboardID shared.ID, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE dash_snapshots SET viewed_at = $3
		WHERE tenant_id = $1 AND dashboard_id = $2 AND viewed_at < $3 - interval '1 hour'`,
		tenantID.String(), dashboardID.String(), at)
	if err != nil {
		return fmt.Errorf("touch dashboard snapshot: %w", err)
	}
	return nil
}

// DeleteSnapshot implements dashboard.SnapshotStore.
func (r *DashboardSnapshotRepository) DeleteSnapshot(ctx context.Context, tenantID, dashboardID shared.ID) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM dash_snapshots WHERE tenant_id = $1 AND dashboard_id = $2`,
		tenantID.String(), dashboardID.String()); err != nil {
		return fmt.Errorf("delete dashboard snapshot: %w", err)
	}
	return nil
}

// TakeRefreshBudget implements dashboard.SnapshotStore. A transaction-level
// advisory lock per tenant serializes the check and the insert, so two
// concurrent requests cannot both pass a full budget.
func (r *DashboardSnapshotRepository) TakeRefreshBudget(ctx context.Context, tenantID, dashboardID, userID shared.ID) (bool, time.Duration, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('dash_refresh:' || $1, 0))`, tenantID.String()); err != nil {
		return false, 0, fmt.Errorf("lock refresh budget: %w", err)
	}
	var lastMine, oldestHour sql.NullTime
	var hourCount int
	if err := tx.QueryRowContext(ctx, `
		SELECT max(requested_at) FILTER (WHERE dashboard_id = $2 AND user_id = $3 AND requested_at > now() - $4::interval),
		       count(*) FILTER (WHERE requested_at > now() - interval '1 hour'),
		       min(requested_at) FILTER (WHERE requested_at > now() - interval '1 hour')
		FROM dash_refresh_requests WHERE tenant_id = $1 AND requested_at > now() - interval '1 hour'`,
		tenantID.String(), dashboardID.String(), userID.String(), fmt.Sprintf("%d seconds", int(dashboard.RefreshPerUserEvery.Seconds()))).
		Scan(&lastMine, &hourCount, &oldestHour); err != nil {
		return false, 0, fmt.Errorf("read refresh budget: %w", err)
	}
	now := time.Now()
	if lastMine.Valid {
		return false, max(time.Until(lastMine.Time.Add(dashboard.RefreshPerUserEvery)), time.Second), nil
	}
	if hourCount >= dashboard.MaxTenantRefreshesPerHour {
		wait := time.Minute
		if oldestHour.Valid {
			wait = max(oldestHour.Time.Add(time.Hour).Sub(now), time.Second)
		}
		return false, wait, nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO dash_refresh_requests (tenant_id, dashboard_id, user_id) VALUES ($1, $2, $3)`,
		tenantID.String(), dashboardID.String(), userID.String()); err != nil {
		return false, 0, fmt.Errorf("record refresh: %w", err)
	}
	return true, 0, tx.Commit()
}

// ScopeFingerprint implements dashboard.SnapshotStore. The key holds hashes
// only (never ids), and every read is bound to the tenant. The id lists are
// digested in the database, so a scope of many assets costs one row of 32
// characters per open instead of the whole list.
func (r *DashboardSnapshotRepository) ScopeFingerprint(ctx context.Context, tenantID, userID shared.ID, scope *shared.DataScope, allCampaigns bool) (string, error) {
	mode, assets := "all", ""
	switch {
	case scope == nil:
	case scope.Unrestricted:
		mode = "unrestricted"
		//nolint:gosec // G202: HiddenAssetWhere is fixed SQL with numbered placeholders
		q := `SELECT md5(COALESCE(string_agg(ph.id::text, ',' ORDER BY ph.id), '')) FROM assets ph WHERE ` + filterspec.HiddenAssetWhere(1, 2)
		if err := r.db.QueryRowContext(ctx, q, userID.String(), tenantID.String()).Scan(&assets); err != nil {
			return "", fmt.Errorf("fingerprint hidden assets: %w", err)
		}
	default:
		mode = "restricted"
		if err := r.db.QueryRowContext(ctx, `
			SELECT md5(COALESCE(string_agg(asset_id::text, ',' ORDER BY asset_id), ''))
			FROM user_accessible_assets WHERE user_id = $1 AND tenant_id = $2`,
			userID.String(), tenantID.String()).Scan(&assets); err != nil {
			return "", fmt.Errorf("fingerprint scope rows: %w", err)
		}
	}
	campaigns := "*"
	if !allCampaigns {
		if err := r.db.QueryRowContext(ctx, `
			SELECT md5(COALESCE(string_agg(campaign_id::text, ',' ORDER BY campaign_id), ''))
			FROM pentest_campaign_members WHERE user_id = $1 AND tenant_id = $2`,
			userID.String(), tenantID.String()).Scan(&campaigns); err != nil {
			return "", fmt.Errorf("fingerprint campaigns: %w", err)
		}
	}
	sum := sha256.Sum256([]byte(mode + "|" + assets + "|" + campaigns))
	return mode + ":" + hex.EncodeToString(sum[:16]), nil
}

// ClaimDueSnapshotsForPlatform implements dashboard.SnapshotStore.
func (r *DashboardSnapshotRepository) ClaimDueSnapshotsForPlatform(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]dashboard.DueSnapshot, error) {
	rows, err := r.db.QueryContext(ctx, `
		WITH due AS (
			SELECT tenant_id, dashboard_id FROM dash_snapshots
			WHERE next_refresh_at IS NOT NULL AND next_refresh_at <= $1
			ORDER BY next_refresh_at LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		UPDATE dash_snapshots s SET next_refresh_at = $1 + $3::interval
		FROM due WHERE s.tenant_id = due.tenant_id AND s.dashboard_id = due.dashboard_id
		RETURNING s.tenant_id, s.dashboard_id, s.kind, s.owner_user_id`,
		now, max(limit, 1), fmt.Sprintf("%d seconds", int(lease.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("claim due dashboard snapshots: %w", err)
	}
	defer rows.Close()
	var out []dashboard.DueSnapshot
	for rows.Next() {
		var d dashboard.DueSnapshot
		var kind string
		var owner sql.NullString
		if err := rows.Scan(&d.TenantID, &d.DashboardID, &kind, &owner); err != nil {
			return nil, fmt.Errorf("scan due snapshot: %w", err)
		}
		d.Kind = dashboard.Kind(kind)
		if owner.Valid {
			if id, perr := shared.IDFromString(owner.String); perr == nil {
				d.OwnerID = id
			}
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// PruneForPlatform implements dashboard.SnapshotStore.
func (r *DashboardSnapshotRepository) PruneForPlatform(ctx context.Context, before, staleBefore time.Time) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM dash_refresh_requests WHERE requested_at < $1`, before); err != nil {
		return fmt.Errorf("prune refresh requests: %w", err)
	}
	if _, err := r.db.ExecContext(ctx, `DELETE FROM dash_snapshots WHERE kind = 'personal' AND viewed_at < $1`, staleBefore); err != nil {
		return fmt.Errorf("prune unviewed snapshots: %w", err)
	}
	return nil
}
