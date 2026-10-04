package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASMSeedRepository stores EASM seeds (easm_seeds, RFC-036 §6.3). Every
// query is tenant-scoped.
type EASMSeedRepository struct {
	db *DB
}

var (
	_ easm.SeedStore       = (*EASMSeedRepository)(nil)
	_ easm.VerifiedDomains = (*EASMSeedRepository)(nil)
)

// NewEASMSeedRepository creates the repository.
func NewEASMSeedRepository(db *DB) *EASMSeedRepository { return &EASMSeedRepository{db: db} }

const easmSeedColumns = `id, tenant_id, kind, value, label, discovery_enabled, attested_by, attested_at, created_by, created_at, updated_at`

func scanSeed(row interface{ Scan(...any) error }) (easmseed.Seed, error) {
	var (
		s                     easmseed.Seed
		id, tid, kind         string
		attestedBy, createdBy sql.NullString
	)
	if err := row.Scan(&id, &tid, &kind, &s.Value, &s.Label, &s.DiscoveryEnabled, &attestedBy, &s.AttestedAt,
		&createdBy, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return s, err
	}
	s.ID, _ = shared.IDFromString(id)
	s.TenantID, _ = shared.IDFromString(tid)
	s.Kind = easmseed.Kind(kind)
	if attestedBy.Valid {
		if u, err := shared.IDFromString(attestedBy.String); err == nil {
			s.AttestedBy = &u
		}
	}
	if createdBy.Valid {
		if u, err := shared.IDFromString(createdBy.String); err == nil {
			s.CreatedBy = &u
		}
	}
	return s, nil
}

// ListSeeds returns all the tenant's seeds (bounded by MaxPerTenant).
func (r *EASMSeedRepository) ListSeeds(ctx context.Context, tenantID shared.ID) ([]easmseed.Seed, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+easmSeedColumns+` FROM easm_seeds
		WHERE tenant_id = $1 ORDER BY kind, value LIMIT $2`, tenantID.String(), easmseed.MaxPerTenant)
	if err != nil {
		return nil, fmt.Errorf("list seeds: %w", err)
	}
	defer rows.Close()
	out := []easmseed.Seed{}
	for rows.Next() {
		s, err := scanSeed(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// CountSeeds counts the tenant's seeds.
func (r *EASMSeedRepository) CountSeeds(ctx context.Context, tenantID shared.ID) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM easm_seeds WHERE tenant_id = $1`, tenantID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count seeds: %w", err)
	}
	return n, nil
}

// CreateSeed inserts a seed. The same (kind, value) twice in one tenant is
// shared.ErrConflict; another tenant's identical seed does not matter.
func (r *EASMSeedRepository) CreateSeed(ctx context.Context, s easmseed.Seed) error {
	var attestedBy, createdBy any
	if s.AttestedBy != nil {
		attestedBy = s.AttestedBy.String()
	}
	if s.CreatedBy != nil {
		createdBy = s.CreatedBy.String()
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO easm_seeds (id, tenant_id, kind, value, label, discovery_enabled, attested_by, attested_at, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6,
		        (SELECT u.id FROM users u WHERE u.id = $7::uuid), $8,
		        (SELECT u.id FROM users u WHERE u.id = $9::uuid), $10, $10)`,
		s.ID.String(), s.TenantID.String(), string(s.Kind), s.Value, s.Label, s.DiscoveryEnabled,
		attestedBy, s.AttestedAt, createdBy, s.CreatedAt)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return fmt.Errorf("%w: this seed already exists", shared.ErrConflict)
		}
		return fmt.Errorf("create seed: %w", err)
	}
	return nil
}

// UpdateSeed changes label and discovery_enabled of the tenant's seed.
func (r *EASMSeedRepository) UpdateSeed(ctx context.Context, tenantID, id shared.ID, label string, discovery bool) (*easmseed.Seed, error) {
	s, err := scanSeed(r.db.QueryRowContext(ctx, `
		UPDATE easm_seeds SET label = $3, discovery_enabled = $4, updated_at = now()
		WHERE tenant_id = $1 AND id = $2
		RETURNING `+easmSeedColumns, tenantID.String(), id.String(), label, discovery))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("update seed: %w", err)
	}
	return &s, nil
}

// DeleteSeed removes the tenant's seed and returns it.
func (r *EASMSeedRepository) DeleteSeed(ctx context.Context, tenantID, id shared.ID) (*easmseed.Seed, error) {
	s, err := scanSeed(r.db.QueryRowContext(ctx, `
		DELETE FROM easm_seeds WHERE tenant_id = $1 AND id = $2 RETURNING `+easmSeedColumns,
		tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("delete seed: %w", err)
	}
	return &s, nil
}

// VerifiedDomainNames returns the tenant's verified domains.
func (r *EASMSeedRepository) VerifiedDomainNames(ctx context.Context, tenantID shared.ID) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT domain FROM verified_domains WHERE tenant_id = $1 AND status = 'verified'`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list verified domains: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DiscoveryRootDomains returns the tenant's root_domain seeds with discovery
// on: the names the Certificate Transparency monitor watches for it.
func (r *EASMSeedRepository) DiscoveryRootDomains(ctx context.Context, tenantID shared.ID) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT value FROM easm_seeds
		WHERE tenant_id = $1 AND kind = 'root_domain' AND discovery_enabled
		ORDER BY value LIMIT $2`, tenantID.String(), easmseed.MaxPerTenant)
	if err != nil {
		return nil, fmt.Errorf("list root domain seeds: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
