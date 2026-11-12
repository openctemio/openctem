package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASMDeclinedNetworkRepository stores the networks an organization
// answered "not ours" about on the Decisions card (research/425). Every
// query is pinned to the tenant.
type EASMDeclinedNetworkRepository struct {
	db *DB
}

// NewEASMDeclinedNetworkRepository creates it.
func NewEASMDeclinedNetworkRepository(db *DB) *EASMDeclinedNetworkRepository {
	return &EASMDeclinedNetworkRepository{db: db}
}

// maxDeclinedNetworks bounds the rows one card reads.
const maxDeclinedNetworks = 1000

// ListDeclined lists the tenant's declined networks, newest first.
func (r *EASMDeclinedNetworkRepository) ListDeclined(ctx context.Context, tenantID shared.ID) ([]easmseed.Declined, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, kind, value, label, created_at FROM easm_declined_networks
		WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2`, tenantID.String(), maxDeclinedNetworks)
	if err != nil {
		return nil, fmt.Errorf("declined networks: %w", err)
	}
	defer rows.Close()
	out := []easmseed.Declined{}
	for rows.Next() {
		var d easmseed.Declined
		var kind string
		if err := rows.Scan(&d.ID, &kind, &d.Value, &d.Label, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.Kind = easmseed.Kind(kind)
		out = append(out, d)
	}
	return out, rows.Err()
}

// Decline records a declined network (an existing one is returned as is).
func (r *EASMDeclinedNetworkRepository) Decline(ctx context.Context, tenantID shared.ID, kind easmseed.Kind, value, label string, by *shared.ID) (*easmseed.Declined, error) {
	var creator any
	if by != nil {
		creator = by.String()
	}
	var d easmseed.Declined
	var k string
	err := r.db.QueryRowContext(ctx, `INSERT INTO easm_declined_networks (tenant_id, kind, value, label, created_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, kind, value) DO UPDATE SET label = easm_declined_networks.label
		RETURNING id, kind, value, label, created_at`,
		tenantID.String(), string(kind), value, label, creator).Scan(&d.ID, &k, &d.Value, &d.Label, &d.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("decline network: %w", err)
	}
	d.Kind = easmseed.Kind(k)
	return &d, nil
}

// Undecline removes one of the tenant's declined networks.
func (r *EASMDeclinedNetworkRepository) Undecline(ctx context.Context, tenantID shared.ID, id string) (*easmseed.Declined, error) {
	if _, err := shared.IDFromString(id); err != nil {
		return nil, shared.ErrNotFound
	}
	var d easmseed.Declined
	var k string
	err := r.db.QueryRowContext(ctx, `DELETE FROM easm_declined_networks WHERE tenant_id = $1 AND id = $2
		RETURNING id, kind, value, label, created_at`, tenantID.String(), id).Scan(&d.ID, &k, &d.Value, &d.Label, &d.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("undecline network: %w", err)
	}
	d.Kind = easmseed.Kind(k)
	return &d, nil
}

// UndeclineValue removes the tenant's declined network of that value, if any.
func (r *EASMDeclinedNetworkRepository) UndeclineValue(ctx context.Context, tenantID shared.ID, kind easmseed.Kind, value string) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM easm_declined_networks WHERE tenant_id = $1 AND kind = $2 AND value = $3`,
		tenantID.String(), string(kind), value); err != nil {
		return fmt.Errorf("undecline network: %w", err)
	}
	return nil
}
