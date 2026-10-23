package postgres

import (
	"context"
	"fmt"

	"github.com/lib/pq"
)

// KEVLookup answers whether CVE ids are in the KEV catalogue (a global
// reference table, no tenant data).
type KEVLookup struct {
	db *DB
}

// NewKEVLookup constructs a KEVLookup.
func NewKEVLookup(db *DB) *KEVLookup { return &KEVLookup{db: db} }

// AnyKEV reports whether any of the CVE ids is in kev_catalog.
func (k *KEVLookup) AnyKEV(ctx context.Context, cveIDs []string) (bool, error) {
	if len(cveIDs) == 0 {
		return false, nil
	}
	var hit bool
	if err := k.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM kev_catalog WHERE cve_id = ANY($1))`,
		pq.Array(cveIDs)).Scan(&hit); err != nil {
		return false, fmt.Errorf("kev lookup: %w", err)
	}
	return hit, nil
}
