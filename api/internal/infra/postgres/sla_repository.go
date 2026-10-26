package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/sla"
)

// SLAPolicyRepository implements sla.Repository using PostgreSQL.
type SLAPolicyRepository struct {
	db *DB
}

// NewSLAPolicyRepository creates a new SLAPolicyRepository.
func NewSLAPolicyRepository(db *DB) *SLAPolicyRepository {
	return &SLAPolicyRepository{db: db}
}

// Create persists a new SLA policy.
func (r *SLAPolicyRepository) Create(ctx context.Context, policy *sla.Policy) error {
	escalationConfig, err := json.Marshal(policy.EscalationConfig())
	if err != nil {
		return fmt.Errorf("failed to marshal escalation config: %w", err)
	}

	query := `
		INSERT INTO sla_policies (
			id, tenant_id, asset_id, name, description, is_default,
			critical_days, high_days, medium_days, low_days, info_days,
			warning_threshold_percent, escalation_enabled, escalation_config,
			is_active, created_at, updated_at,
			p0_days, p1_days, p2_days, p3_days, kev_cap_days
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
	`

	_, err = r.db.ExecContext(ctx, query,
		policy.ID().String(),
		policy.TenantID().String(),
		nullID(policy.AssetID()),
		policy.Name(),
		nullString(policy.Description()),
		policy.IsDefault(),
		policy.CriticalDays(),
		policy.HighDays(),
		policy.MediumDays(),
		policy.LowDays(),
		policy.InfoDays(),
		policy.WarningThresholdPct(),
		policy.EscalationEnabled(),
		escalationConfig,
		policy.IsActive(),
		policy.CreatedAt(),
		policy.UpdatedAt(),
		policy.P0Days(),
		policy.P1Days(),
		policy.P2Days(),
		policy.P3Days(),
		policy.KEVCapDays(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return sla.AlreadyExistsError(policy.Name())
		}
		return fmt.Errorf("failed to create SLA policy: %w", err)
	}

	return nil
}

// GetByTenantAndID retrieves a policy by tenant and ID (tenant-scoped).
func (r *SLAPolicyRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*sla.Policy, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanPolicy(row)
}

// GetByAsset retrieves the policy for a specific asset.
// Returns the asset-specific policy if exists, otherwise the tenant default.
func (r *SLAPolicyRepository) GetByAsset(ctx context.Context, tenantID, assetID shared.ID) (*sla.Policy, error) {
	query := r.selectQuery() + `
		WHERE tenant_id = $1
		AND (asset_id = $2 OR (asset_id IS NULL AND is_default = true))
		AND is_active = true
		ORDER BY asset_id NULLS LAST
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), assetID.String())
	return r.scanPolicy(row)
}

// GetTenantDefault retrieves the default policy for a tenant.
//
// The single-default invariant is enforced by a partial unique index and
// UpdateMakingDefault. An inactive default never governs: it is skipped, like
// an inactive asset policy in GetByAsset.
func (r *SLAPolicyRepository) GetTenantDefault(ctx context.Context, tenantID shared.ID) (*sla.Policy, error) {
	query := r.selectQuery() + ` WHERE tenant_id = $1 AND is_default = true AND is_active = true AND asset_id IS NULL
		ORDER BY created_at ASC LIMIT 1`
	row := r.db.QueryRowContext(ctx, query, tenantID.String())
	return r.scanPolicy(row)
}

// Update updates an existing policy.
func (r *SLAPolicyRepository) Update(ctx context.Context, policy *sla.Policy) error {
	return r.updateExec(ctx, r.db, policy)
}

// UpdateMakingDefault writes the policy and makes it the tenant's only default
// in one transaction. An advisory lock keyed by tenant serializes concurrent
// make-default calls (a row lock alone cannot: once the first commits, the
// second's lock query no longer matches the old default and would skip it),
// and the old default row is locked FOR UPDATE as well.
func (r *SLAPolicyRepository) UpdateMakingDefault(ctx context.Context, policy *sla.Policy) (err error) {
	if policy.AssetID() != nil || !policy.IsDefault() || !policy.IsActive() {
		return fmt.Errorf("%w: only an active tenant-wide policy can be the default", shared.ErrValidation)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	tenant := policy.TenantID().String()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('sla_default:' || $1::text, 0))`, tenant); err != nil {
		return fmt.Errorf("failed to lock tenant default: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `SELECT id FROM sla_policies
		WHERE tenant_id = $1 AND asset_id IS NULL AND is_default = true FOR UPDATE`, tenant); err != nil {
		return fmt.Errorf("failed to lock current default SLA policy: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE sla_policies SET is_default = false, updated_at = now()
		WHERE tenant_id = $1 AND asset_id IS NULL AND is_default = true AND id <> $2`,
		tenant, policy.ID().String()); err != nil {
		return fmt.Errorf("failed to unset existing default SLA policies: %w", err)
	}
	if err := r.updateExec(ctx, tx, policy); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit default change: %w", err)
	}
	return nil
}

func (r *SLAPolicyRepository) updateExec(ctx context.Context, ex sqlExecer, policy *sla.Policy) error {
	escalationConfig, err := json.Marshal(policy.EscalationConfig())
	if err != nil {
		return fmt.Errorf("failed to marshal escalation config: %w", err)
	}

	query := `
		UPDATE sla_policies SET
			name = $2, description = $3, is_default = $4,
			critical_days = $5, high_days = $6, medium_days = $7, low_days = $8, info_days = $9,
			warning_threshold_percent = $10, escalation_enabled = $11, escalation_config = $12,
			is_active = $13, updated_at = $14,
			p0_days = $16, p1_days = $17, p2_days = $18, p3_days = $19, kev_cap_days = $20
		WHERE id = $1 AND tenant_id = $15
	`

	result, err := ex.ExecContext(ctx, query,
		policy.ID().String(),
		policy.Name(),
		nullString(policy.Description()),
		policy.IsDefault(),
		policy.CriticalDays(),
		policy.HighDays(),
		policy.MediumDays(),
		policy.LowDays(),
		policy.InfoDays(),
		policy.WarningThresholdPct(),
		policy.EscalationEnabled(),
		escalationConfig,
		policy.IsActive(),
		policy.UpdatedAt(),
		policy.TenantID().String(),
		policy.P0Days(),
		policy.P1Days(),
		policy.P2Days(),
		policy.P3Days(),
		policy.KEVCapDays(),
	)

	if err != nil {
		return fmt.Errorf("failed to update SLA policy: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return sla.NotFoundError(policy.ID().String())
	}

	return nil
}

// Delete removes a policy of the tenant.
func (r *SLAPolicyRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	query := `DELETE FROM sla_policies WHERE tenant_id = $1 AND id = $2`

	result, err := r.db.ExecContext(ctx, query, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to delete SLA policy: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return sla.NotFoundError(id.String())
	}

	return nil
}

// ListByTenant returns all policies for a tenant.
func (r *SLAPolicyRepository) ListByTenant(ctx context.Context, tenantID shared.ID) ([]*sla.Policy, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 ORDER BY is_default DESC, name ASC"

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query SLA policies: %w", err)
	}
	defer rows.Close()

	var policies []*sla.Policy
	for rows.Next() {
		policy, err := r.scanPolicyFromRows(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return policies, nil
}

// Helper methods

func (r *SLAPolicyRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, asset_id, name, description, is_default,
			critical_days, high_days, medium_days, low_days, info_days,
			warning_threshold_percent, escalation_enabled, escalation_config,
			is_active, created_at, updated_at,
			p0_days, p1_days, p2_days, p3_days, kev_cap_days
		FROM sla_policies
	`
}

func (r *SLAPolicyRepository) scanPolicy(row *sql.Row) (*sla.Policy, error) {
	policy, err := r.doScan(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sla.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan SLA policy: %w", err)
	}
	return policy, nil
}

func (r *SLAPolicyRepository) scanPolicyFromRows(rows *sql.Rows) (*sla.Policy, error) {
	return r.doScan(rows.Scan)
}

func (r *SLAPolicyRepository) doScan(scan func(dest ...any) error) (*sla.Policy, error) {
	var (
		idStr               string
		tenantIDStr         string
		assetIDStr          sql.NullString
		name                string
		description         sql.NullString
		isDefault           bool
		criticalDays        int
		highDays            int
		mediumDays          int
		lowDays             int
		infoDays            int
		warningThresholdPct int
		escalationEnabled   bool
		escalationConfig    []byte
		isActive            bool
		createdAt           time.Time
		updatedAt           time.Time
		p0, p1, p2, p3      sql.NullInt64
		kevCapDays          int
	)

	err := scan(
		&idStr, &tenantIDStr, &assetIDStr, &name, &description, &isDefault,
		&criticalDays, &highDays, &mediumDays, &lowDays, &infoDays,
		&warningThresholdPct, &escalationEnabled, &escalationConfig,
		&isActive, &createdAt, &updatedAt,
		&p0, &p1, &p2, &p3, &kevCapDays,
	)
	if err != nil {
		return nil, err
	}

	parsedID, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id: %w", err)
	}

	parsedTenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tenant_id: %w", err)
	}

	var parsedAssetID *shared.ID
	if assetIDStr.Valid {
		id, err := shared.IDFromString(assetIDStr.String)
		if err == nil {
			parsedAssetID = &id
		}
	}

	var config map[string]any
	if len(escalationConfig) > 0 {
		if err := json.Unmarshal(escalationConfig, &config); err != nil {
			config = make(map[string]any)
		}
	}

	return sla.Reconstitute(
		parsedID,
		parsedTenantID,
		parsedAssetID,
		name,
		nullStringValue(description),
		isDefault,
		criticalDays,
		highDays,
		mediumDays,
		lowDays,
		infoDays,
		warningThresholdPct,
		escalationEnabled,
		config,
		isActive,
		createdAt,
		updatedAt,
	).WithPriorityDays(nullDays(p0), nullDays(p1), nullDays(p2), nullDays(p3)).WithKEVCapDays(kevCapDays), nil
}

// nullDays maps a NULL priority-days column to 0, which WithPriorityDays
// treats as "keep the default for that class".
func nullDays(v sql.NullInt64) int {
	if !v.Valid || v.Int64 < 1 || v.Int64 > sla.MaxSLADays {
		return 0
	}
	return int(v.Int64)
}
