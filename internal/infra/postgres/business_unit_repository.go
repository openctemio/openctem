package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/businessunit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// BusinessUnitRepository implements businessunit.Repository.
type BusinessUnitRepository struct {
	db *DB
}

// NewBusinessUnitRepository creates a new repository.
func NewBusinessUnitRepository(db *DB) *BusinessUnitRepository {
	return &BusinessUnitRepository{db: db}
}

const buSelectCols = `id, tenant_id, name, description, owner_name, owner_email,
	asset_count, finding_count, avg_risk_score, critical_finding_count,
	tags, created_at, updated_at`

func (r *BusinessUnitRepository) scanBU(scan func(dest ...any) error) (*businessunit.BusinessUnit, error) {
	var (
		id, tenantID                        string
		name, desc                          string
		ownerName, ownerEmail               sql.NullString
		assetCount, findingCount, critCount int
		avgRisk                             float64
		tags                                pq.StringArray
		createdAt, updatedAt                time.Time
	)
	err := scan(&id, &tenantID, &name, &desc, &ownerName, &ownerEmail,
		&assetCount, &findingCount, &avgRisk, &critCount,
		&tags, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	pid, _ := shared.IDFromString(id)
	ptid, _ := shared.IDFromString(tenantID)
	return businessunit.ReconstituteBusinessUnit(
		pid, ptid, name, desc, ownerName.String, ownerEmail.String,
		assetCount, findingCount, avgRisk, critCount,
		[]string(tags), createdAt, updatedAt,
	), nil
}

func (r *BusinessUnitRepository) Create(ctx context.Context, bu *businessunit.BusinessUnit) error {
	query := `INSERT INTO business_units (id, tenant_id, name, description, owner_name, owner_email, tags, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	_, err := r.db.ExecContext(ctx, query,
		bu.ID().String(), bu.TenantID().String(), bu.Name(), bu.Description(),
		bu.OwnerName(), bu.OwnerEmail(), pq.StringArray(bu.Tags()),
		bu.CreatedAt(), bu.UpdatedAt())
	if err != nil {
		return fmt.Errorf("failed to create business unit: %w", err)
	}
	return nil
}

func (r *BusinessUnitRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*businessunit.BusinessUnit, error) {
	query := "SELECT " + buSelectCols + " FROM business_units WHERE tenant_id = $1 AND id = $2"
	bu, err := r.scanBU(r.db.QueryRowContext(ctx, query, tenantID.String(), id.String()).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, businessunit.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get business unit: %w", err)
	}
	return bu, nil
}

func (r *BusinessUnitRepository) Update(ctx context.Context, bu *businessunit.BusinessUnit) error {
	query := `UPDATE business_units SET name=$3, description=$4, owner_name=$5, owner_email=$6,
		asset_count=$7, finding_count=$8, avg_risk_score=$9, critical_finding_count=$10,
		tags=$11, updated_at=$12 WHERE tenant_id=$1 AND id=$2`
	_, err := r.db.ExecContext(ctx, query,
		bu.TenantID().String(), bu.ID().String(),
		bu.Name(), bu.Description(), bu.OwnerName(), bu.OwnerEmail(),
		bu.AssetCount(), bu.FindingCount(), bu.AvgRiskScore(), bu.CriticalFindingCount(),
		pq.StringArray(bu.Tags()), bu.UpdatedAt())
	if err != nil {
		return fmt.Errorf("failed to update business unit: %w", err)
	}
	return nil
}

func (r *BusinessUnitRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM business_units WHERE tenant_id = $1 AND id = $2",
		tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to delete business unit: %w", err)
	}
	return nil
}

func (r *BusinessUnitRepository) List(ctx context.Context, filter businessunit.Filter, page pagination.Pagination) (pagination.Result[*businessunit.BusinessUnit], error) {
	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1
	if filter.TenantID != nil {
		where += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, filter.TenantID.String())
		argIdx++
	}
	if filter.Search != nil && *filter.Search != "" {
		where += fmt.Sprintf(" AND (name ILIKE $%d OR description ILIKE $%d)", argIdx, argIdx)
		// Escape LIKE special characters to prevent wildcard injection
		escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(*filter.Search)
		args = append(args, "%"+escaped+"%")
		// argIdx not incremented — no further conditions
	}
	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM business_units "+where, args...).Scan(&total); err != nil {
		return pagination.Result[*businessunit.BusinessUnit]{}, fmt.Errorf("failed to count: %w", err)
	}
	query := "SELECT " + buSelectCols + " FROM business_units " + where +
		" ORDER BY name" + fmt.Sprintf(" LIMIT %d OFFSET %d", page.PerPage, (page.Page-1)*page.PerPage)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*businessunit.BusinessUnit]{}, fmt.Errorf("failed to list: %w", err)
	}
	defer rows.Close()
	items := make([]*businessunit.BusinessUnit, 0)
	for rows.Next() {
		bu, err := r.scanBU(rows.Scan)
		if err != nil {
			return pagination.Result[*businessunit.BusinessUnit]{}, err
		}
		items = append(items, bu)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*businessunit.BusinessUnit]{}, err
	}
	return pagination.NewResult(items, int64(total), page), nil
}

func (r *BusinessUnitRepository) AddAsset(ctx context.Context, tenantID, buID, assetID shared.ID) error {
	// Only link the asset if it belongs to this tenant — defence-in-depth on
	// top of the service-layer check, so the link table can never reference a
	// foreign asset even if a caller bypasses the service.
	query := `INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id, created_at)
		SELECT $1, $2, $3, $4, NOW()
		WHERE EXISTS (SELECT 1 FROM assets WHERE id = $4 AND tenant_id = $2)
		ON CONFLICT DO NOTHING`
	_, err := r.db.ExecContext(ctx, query, shared.NewID().String(), tenantID.String(), buID.String(), assetID.String())
	return err
}

// RecalculateCounts refreshes the cached rollup counters for a business unit
// from its current membership (asset_count, finding_count, critical_finding_count,
// avg_risk_score).
func (r *BusinessUnitRepository) RecalculateCounts(ctx context.Context, tenantID, buID shared.ID) error {
	query := `
		UPDATE business_units SET
			asset_count = (
				SELECT COUNT(*) FROM business_unit_assets
				WHERE business_unit_id = $2 AND tenant_id = $1
			),
			finding_count = COALESCE((
				SELECT COUNT(*) FROM findings f
				JOIN business_unit_assets bua ON bua.asset_id = f.asset_id
				WHERE bua.business_unit_id = $2 AND bua.tenant_id = $1
			), 0),
			critical_finding_count = COALESCE((
				SELECT COUNT(*) FROM findings f
				JOIN business_unit_assets bua ON bua.asset_id = f.asset_id
				WHERE bua.business_unit_id = $2 AND bua.tenant_id = $1 AND f.severity = 'critical'
			), 0),
			avg_risk_score = COALESCE((
				SELECT AVG(a.risk_score) FROM business_unit_assets bua
				JOIN assets a ON a.id = bua.asset_id
				WHERE bua.business_unit_id = $2 AND bua.tenant_id = $1
			), 0),
			updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2
	`
	if _, err := r.db.ExecContext(ctx, query, tenantID.String(), buID.String()); err != nil {
		return fmt.Errorf("recalculate business unit counts: %w", err)
	}
	return nil
}

func (r *BusinessUnitRepository) RemoveAsset(ctx context.Context, tenantID, buID, assetID shared.ID) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM business_unit_assets WHERE tenant_id = $1 AND business_unit_id = $2 AND asset_id = $3",
		tenantID.String(), buID.String(), assetID.String())
	return err
}

func (r *BusinessUnitRepository) ListAssetIDs(ctx context.Context, tenantID, buID shared.ID) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT asset_id FROM business_unit_assets WHERE tenant_id = $1 AND business_unit_id = $2",
		tenantID.String(), buID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, err
		}
		id, _ := shared.IDFromString(idStr)
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
