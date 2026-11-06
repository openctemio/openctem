package postgres

// An organization's own sensor products (docs/rfcs/RFC-037 §13; table
// tenant_sensor_products). Every query carries the tenant.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ sensor.CustomProductStore = (*SensorRepository)(nil)

// ListCustomProducts implements sensor.CustomProductStore.
func (r *SensorRepository) ListCustomProducts(ctx context.Context, tenantID shared.ID) ([]sensor.CustomProduct, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT product, latest_version, min_version, updated_by, updated_at
		FROM tenant_sensor_products
		WHERE tenant_id = $1
		ORDER BY product
		LIMIT $2`, tenantID.String(), sensor.MaxCustomProducts)
	if err != nil {
		return nil, fmt.Errorf("failed to list sensor products: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]sensor.CustomProduct, 0, 8)
	for rows.Next() {
		var (
			p               = sensor.CustomProduct{TenantID: tenantID}
			latest, minimum sql.NullString
			updatedBy       sql.NullString
		)
		if err := rows.Scan(&p.Product, &latest, &minimum, &updatedBy, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan sensor product: %w", err)
		}
		p.Latest, p.Min = latest.String, minimum.String
		if updatedBy.Valid {
			if id, err := shared.IDFromString(updatedBy.String); err == nil {
				p.UpdatedBy = &id
			}
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to list sensor products: %w", err)
	}
	return out, nil
}

// SaveCustomProduct implements sensor.CustomProductStore. A new product is
// inserted only while the organization has fewer than MaxCustomProducts
// others.
func (r *SensorRepository) SaveCustomProduct(ctx context.Context, p sensor.CustomProduct) error {
	at := p.UpdatedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_sensor_products (tenant_id, product, latest_version, min_version, updated_by, updated_at)
		SELECT $1::uuid, $2::varchar, NULLIF($3::varchar, ''), NULLIF($4::varchar, ''), $5::uuid, $6::timestamptz
		WHERE (SELECT count(*) FROM tenant_sensor_products WHERE tenant_id = $1::uuid AND product <> $2::varchar) < $7::int
		ON CONFLICT (tenant_id, product) DO UPDATE
		SET latest_version = EXCLUDED.latest_version, min_version = EXCLUDED.min_version,
		    updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
		p.TenantID.String(), p.Product, p.Latest, p.Min, nullID(p.UpdatedBy), at, sensor.MaxCustomProducts)
	if err != nil {
		return fmt.Errorf("failed to save sensor product: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to save sensor product: %w", err)
	}
	if n == 0 {
		return sensor.ErrCustomProductLimit
	}
	return nil
}

// DeleteCustomProduct implements sensor.CustomProductStore.
func (r *SensorRepository) DeleteCustomProduct(ctx context.Context, tenantID shared.ID, product string) error {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM tenant_sensor_products WHERE tenant_id = $1 AND product = $2`, tenantID.String(), product)
	if err != nil {
		return fmt.Errorf("failed to delete sensor product: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to delete sensor product: %w", err)
	}
	if n == 0 {
		return sensor.ErrCustomProductNotFound
	}
	return nil
}
