package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/sla"
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
			is_active, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
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
	)

	if err != nil {
		if isUniqueViolation(err) {
			return sla.AlreadyExistsError(policy.Name())
		}
		return fmt.Errorf("failed to create SLA policy: %w", err)
	}

	return nil
}

// GetByID retrieves a policy by ID.
func (r *SLAPolicyRepository) GetByID(ctx context.Context, id shared.ID) (*sla.Policy, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
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
func (r *SLAPolicyRepository) GetTenantDefault(ctx context.Context, tenantID shared.ID) (*sla.Policy, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND is_default = true AND asset_id IS NULL"
	row := r.db.QueryRowContext(ctx, query, tenantID.String())
	return r.scanPolicy(row)
}

// Update updates an existing policy.
func (r *SLAPolicyRepository) Update(ctx context.Context, policy *sla.Policy) error {
	escalationConfig, err := json.Marshal(policy.EscalationConfig())
	if err != nil {
		return fmt.Errorf("failed to marshal escalation config: %w", err)
	}

	query := `
		UPDATE sla_policies SET
			name = $2, description = $3, is_default = $4,
			critical_days = $5, high_days = $6, medium_days = $7, low_days = $8, info_days = $9,
			warning_threshold_percent = $10, escalation_enabled = $11, escalation_config = $12,
			is_active = $13, updated_at = $14
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
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

// Delete removes a policy.
func (r *SLAPolicyRepository) Delete(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM sla_policies WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
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

	return policies, nil
}

// ExistsByAsset checks if an asset-specific policy exists.
func (r *SLAPolicyRepository) ExistsByAsset(ctx context.Context, assetID shared.ID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM sla_policies WHERE asset_id = $1)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, assetID.String()).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check SLA policy existence: %w", err)
	}

	return exists, nil
}

// Helper methods

func (r *SLAPolicyRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, asset_id, name, description, is_default,
			critical_days, high_days, medium_days, low_days, info_days,
			warning_threshold_percent, escalation_enabled, escalation_config,
			is_active, created_at, updated_at
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
	)

	err := scan(
		&idStr, &tenantIDStr, &assetIDStr, &name, &description, &isDefault,
		&criticalDays, &highDays, &mediumDays, &lowDays, &infoDays,
		&warningThresholdPct, &escalationEnabled, &escalationConfig,
		&isActive, &createdAt, &updatedAt,
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
	), nil
}
