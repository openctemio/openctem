package ctemid

import "context"

// Repository persists the CTEM-ID catalog. It is tenant-agnostic reference data.
type Repository interface {
	// UpsertBatch inserts or updates catalog entries keyed by ctem_id. It is
	// idempotent: re-ingesting the same feed updates mutable fields and leaves
	// the row count unchanged.
	UpsertBatch(ctx context.Context, entries []*CTEMID) error

	// List returns catalog entries, optionally filtered by category, with
	// limit/offset pagination. The second return is the total matching count.
	List(ctx context.Context, category *string, limit, offset int) ([]*CTEMID, int, error)

	// GetByCTEMID returns a single catalog entry by its external id.
	GetByCTEMID(ctx context.Context, ctemID string) (*CTEMID, error)

	// Count returns the total number of catalog entries.
	Count(ctx context.Context) (int, error)
}
