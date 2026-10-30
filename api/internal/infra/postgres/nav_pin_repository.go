package postgres

// Sidebar pins (research/236 C4). Every statement is scoped to the tenant
// and the user; nothing here reads or writes another member's pins.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/navpin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// NavPinRepository implements navpin.Repository.
type NavPinRepository struct {
	db *DB
}

// NewNavPinRepository creates a NavPinRepository.
func NewNavPinRepository(db *DB) *NavPinRepository { return &NavPinRepository{db: db} }

// List returns the member's pins in their order.
func (r *NavPinRepository) List(ctx context.Context, tenantID, userID shared.ID) ([]navpin.Pin, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT kind, ref FROM nav_pins WHERE tenant_id = $1 AND user_id = $2 ORDER BY position, created_at`,
		tenantID.String(), userID.String())
	if err != nil {
		return nil, fmt.Errorf("list nav pins: %w", err)
	}
	defer rows.Close()
	out := make([]navpin.Pin, 0, navpin.MaxPins)
	for rows.Next() {
		var p navpin.Pin
		var kind string
		if err := rows.Scan(&kind, &p.Ref); err != nil {
			return nil, fmt.Errorf("scan nav pin: %w", err)
		}
		p.Kind = navpin.Kind(kind)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Replace stores the list in order, replacing the member's pins, in one
// transaction.
func (r *NavPinRepository) Replace(ctx context.Context, tenantID, userID shared.ID, pins []navpin.Pin) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM nav_pins WHERE tenant_id = $1 AND user_id = $2`,
			tenantID.String(), userID.String()); err != nil {
			return fmt.Errorf("clear nav pins: %w", err)
		}
		for i, p := range pins {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO nav_pins (tenant_id, user_id, kind, ref, position) VALUES ($1, $2, $3, $4, $5)`,
				tenantID.String(), userID.String(), string(p.Kind), p.Ref, i); err != nil {
				return fmt.Errorf("insert nav pin: %w", err)
			}
		}
		return nil
	})
}
