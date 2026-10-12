package postgres

// Network seeds of EASM discovery (docs/rfcs/RFC-082-network-seeds.md).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASMNetworkSeedRepository stores network seeds.
type EASMNetworkSeedRepository struct {
	db *DB
}

// NewEASMNetworkSeedRepository creates the repository.
func NewEASMNetworkSeedRepository(db *DB) *EASMNetworkSeedRepository {
	return &EASMNetworkSeedRepository{db: db}
}

const networkSeedColumns = `id, kind, value, label, holder, prefixes, suggestions, last_expanded_at, expand_error, created_at`

func scanNetworkSeed(s interface{ Scan(...any) error }) (easmseed.Seed, error) {
	var sd easmseed.Seed
	var kind string
	var prefixes pq.StringArray
	var sugg []byte
	var last sql.NullTime
	if err := s.Scan(&sd.ID, &kind, &sd.Value, &sd.Label, &sd.Holder, &prefixes, &sugg, &last, &sd.ExpandError, &sd.CreatedAt); err != nil {
		return sd, err
	}
	sd.Kind = easmseed.Kind(kind)
	sd.Prefixes = []string(prefixes)
	if sd.Prefixes == nil {
		sd.Prefixes = []string{}
	}
	sd.Suggestions = []easmseed.ASNSuggestion{}
	if len(sugg) > 0 {
		_ = json.Unmarshal(sugg, &sd.Suggestions)
	}
	sd.LastExpandedAt = nullTimeValue(last)
	return sd, nil
}

// List returns the tenant's seeds, oldest first.
func (r *EASMNetworkSeedRepository) List(ctx context.Context, tenantID shared.ID) ([]easmseed.Seed, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+networkSeedColumns+` FROM easm_network_seeds
		WHERE tenant_id = $1 ORDER BY created_at, id LIMIT $2`, tenantID.String(), easmseed.MaxSeedsPerTenant)
	if err != nil {
		return nil, fmt.Errorf("list network seeds: %w", err)
	}
	defer rows.Close()
	out := []easmseed.Seed{}
	for rows.Next() {
		sd, err := scanNetworkSeed(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sd)
	}
	return out, rows.Err()
}

// Get returns one seed of the tenant (shared.ErrNotFound otherwise).
func (r *EASMNetworkSeedRepository) Get(ctx context.Context, tenantID shared.ID, id string) (*easmseed.Seed, error) {
	if _, err := shared.IDFromString(id); err != nil {
		return nil, shared.ErrNotFound
	}
	sd, err := scanNetworkSeed(r.db.QueryRowContext(ctx, `SELECT `+networkSeedColumns+` FROM easm_network_seeds
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get network seed: %w", err)
	}
	return &sd, nil
}

// Create inserts a seed unless the tenant holds MaxSeedsPerTenant already
// (shared.ErrConflict for a duplicate or a full list; the count and the
// insert are one statement, so concurrent creates cannot exceed the cap).
func (r *EASMNetworkSeedRepository) Create(ctx context.Context, tenantID shared.ID, kind easmseed.Kind, value, label string, createdBy *shared.ID) (*easmseed.Seed, error) {
	var by any
	if createdBy != nil {
		by = createdBy.String()
	}
	sd, err := scanNetworkSeed(r.db.QueryRowContext(ctx, `
		INSERT INTO easm_network_seeds (tenant_id, kind, value, label, created_by)
		SELECT $1, $2, $3, $4, $5
		 WHERE (SELECT count(*) FROM easm_network_seeds WHERE tenant_id = $1) < $6
		ON CONFLICT (tenant_id, kind, lower(value)) DO NOTHING
		RETURNING `+networkSeedColumns, tenantID.String(), string(kind), value, label, by, easmseed.MaxSeedsPerTenant))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: the seed exists already or the organization has %d seeds", shared.ErrConflict, easmseed.MaxSeedsPerTenant)
	}
	if err != nil {
		return nil, fmt.Errorf("create network seed: %w", err)
	}
	return &sd, nil
}

// Delete removes a seed of the tenant (shared.ErrNotFound otherwise).
func (r *EASMNetworkSeedRepository) Delete(ctx context.Context, tenantID shared.ID, id string) error {
	if _, err := shared.IDFromString(id); err != nil {
		return shared.ErrNotFound
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM easm_network_seeds WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id)
	if err != nil {
		return fmt.Errorf("delete network seed: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// ClaimExpansion marks the seed as being expanded now unless it was within
// cooldown; false means too soon (or not the tenant's seed).
func (r *EASMNetworkSeedRepository) ClaimExpansion(ctx context.Context, tenantID shared.ID, id string, now time.Time, cooldown time.Duration) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE easm_network_seeds SET last_expanded_at = $3, updated_at = $3
		 WHERE tenant_id = $1 AND id = $2 AND (last_expanded_at IS NULL OR last_expanded_at <= $4)`,
		tenantID.String(), id, now, now.Add(-cooldown))
	if err != nil {
		return false, fmt.Errorf("claim network seed expansion: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// SaveExpansion stores what an expansion found. A failed expansion keeps the
// previous prefixes and suggestions and records the error.
func (r *EASMNetworkSeedRepository) SaveExpansion(ctx context.Context, tenantID shared.ID, id, holder string,
	prefixes []string, suggestions []easmseed.ASNSuggestion, expandErr string,
) error {
	if expandErr != "" {
		_, err := r.db.ExecContext(ctx, `UPDATE easm_network_seeds SET expand_error = $3, updated_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id, truncate(expandErr, 300))
		return err
	}
	if prefixes == nil {
		prefixes = []string{}
	}
	if suggestions == nil {
		suggestions = []easmseed.ASNSuggestion{}
	}
	b, err := json.Marshal(suggestions)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `UPDATE easm_network_seeds
		SET holder = $3, prefixes = $4, suggestions = $5, expand_error = '', updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id, truncate(holder, 300), pq.Array(prefixes), b)
	return err
}

// DueForExpansion lists seeds never expanded or last expanded before the cutoff.
func (r *EASMNetworkSeedRepository) DueForExpansion(ctx context.Context, before time.Time, limit int) ([]easmseed.Ref, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT tenant_id, id FROM easm_network_seeds
		WHERE last_expanded_at IS NULL OR last_expanded_at < $1
		ORDER BY last_expanded_at NULLS FIRST LIMIT $2`, before, limit)
	if err != nil {
		return nil, fmt.Errorf("network seeds due: %w", err)
	}
	defer rows.Close()
	var out []easmseed.Ref
	for rows.Next() {
		var tid, id string
		if err := rows.Scan(&tid, &id); err != nil {
			return nil, err
		}
		t, err := shared.IDFromString(tid)
		if err != nil {
			continue
		}
		out = append(out, easmseed.Ref{TenantID: t, ID: id})
	}
	return out, rows.Err()
}

// Networks returns the tenant's seeded AS numbers, organization names and
// announced prefixes.
func (r *EASMNetworkSeedRepository) Networks(ctx context.Context, tenantID shared.ID) (easmseed.Networks, error) {
	n := easmseed.Networks{ASNs: map[string]bool{}}
	seeds, err := r.List(ctx, tenantID)
	if err != nil {
		return n, err
	}
	for _, s := range seeds {
		switch s.Kind {
		case easmseed.KindASN:
			n.ASNs[s.Value] = true
			n.Prefixes = append(n.Prefixes, s.Prefixes...)
		case easmseed.KindOrgName:
			n.OrgNames = append(n.OrgNames, s.Value)
		}
	}
	return n, nil
}
