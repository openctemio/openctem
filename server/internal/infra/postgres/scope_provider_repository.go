package postgres

// The Scope page's provider addresses card (docs/architecture/
// provider-shared-addresses.md): the organization's keep-scanning
// decisions, the move of entries out of scope in one transaction, and the
// person-confirmed addresses listed under the card. Every statement carries
// the tenant.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	scopeapp "github.com/openctemio/openctem/server/internal/app/scope"
	"github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// ScopeProviderRepository implements scopeapp.ProviderAddressStore.
type ScopeProviderRepository struct {
	db *DB
}

// NewScopeProviderRepository creates the repository.
func NewScopeProviderRepository(db *DB) *ScopeProviderRepository {
	return &ScopeProviderRepository{db: db}
}

var _ scopeapp.ProviderAddressStore = (*ScopeProviderRepository)(nil)

// maxPersonConfirmedAddresses bounds the addresses read for the card.
const maxPersonConfirmedAddresses = 5000

// KeptEntryIDs are the tenant's entries a person chose to keep scanning.
func (r *ScopeProviderRepository) KeptEntryIDs(ctx context.Context, tenantID shared.ID) (map[shared.ID]bool, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT target_id FROM scope_provider_keeps WHERE tenant_id = $1`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list kept provider entries: %w", err)
	}
	defer rows.Close()
	out := map[shared.ID]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if pid, err := shared.IDFromString(id); err == nil {
			out[pid] = true
		}
	}
	return out, rows.Err()
}

// SaveKeeps records keep-scanning decisions; an entry already kept keeps
// its first decision. Only the tenant's own entries are recorded (the
// insert selects them by tenant).
func (r *ScopeProviderRepository) SaveKeeps(ctx context.Context, tenantID shared.ID, keeps []scopeapp.ProviderKeep) error {
	if len(keeps) == 0 {
		return nil
	}
	ids := make([]string, len(keeps))
	providers := make([]string, len(keeps))
	versions := make([]string, len(keeps))
	by := make([]string, len(keeps))
	for i, k := range keeps {
		ids[i], providers[i], versions[i], by[i] = k.TargetID.String(), k.Provider, k.DatasetVersion, k.DecidedBy
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO scope_provider_keeps (tenant_id, target_id, provider, dataset_version, decided_by, decided_at)
		SELECT t.tenant_id, t.id, k.provider, k.version, k.by, now()
		FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[]) AS k(id, provider, version, by)
		JOIN scope_targets t ON t.id = k.id AND t.tenant_id = $1
		ON CONFLICT (tenant_id, target_id) DO NOTHING`,
		tenantID.String(), pq.Array(ids), pq.Array(providers), pq.Array(versions), pq.Array(by))
	if err != nil {
		return fmt.Errorf("save kept provider entries: %w", err)
	}
	return nil
}

// SaveMove creates the exclusions and saves the deactivated entries in one
// transaction. Every row carries the tenant: an entry or exclusion of
// another tenant is refused and nothing is written.
func (r *ScopeProviderRepository) SaveMove(ctx context.Context, tenantID shared.ID, exclusions []*scope.Exclusion, deactivated []*scope.Target) error {
	for _, e := range exclusions {
		if e.TenantID() != tenantID {
			return fmt.Errorf("%w: exclusion of another tenant", shared.ErrValidation)
		}
	}
	for _, t := range deactivated {
		if t.TenantID() != tenantID {
			return fmt.Errorf("%w: entry of another tenant", shared.ErrValidation)
		}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin provider move: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, e := range exclusions {
		if err := insertScopeExclusion(ctx, tx, e); err != nil {
			return err
		}
	}
	targets := &ScopeTargetRepository{db: r.db}
	for _, t := range deactivated {
		if err := targets.updateInTx(ctx, tx, t); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PersonConfirmedAddresses lists the tenant's live ip_address assets whose
// attribution a person decided as confirmed, within the data scope ds (nil:
// the whole tenant). The caller keeps those inside a shared range.
func (r *ScopeProviderRepository) PersonConfirmedAddresses(ctx context.Context, tenantID shared.ID, ds *shared.DataScope) ([]scopeapp.ProviderConfirmed, error) {
	if ds != nil && !ds.TenantID.IsZero() && ds.TenantID != tenantID {
		return nil, nil // a scope for another tenant admits nothing (fail closed)
	}
	args := []any{tenantID.String()}
	sc, args := scopeClause("a.id", ds, args)
	//nolint:gosec // G202: the scope clause is fixed SQL with numbered placeholders
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name, aa.decided_at
		FROM assets a
		JOIN asset_attributions aa ON aa.tenant_id = a.tenant_id AND aa.asset_id = a.id
		WHERE a.tenant_id = $1 AND a.asset_type = 'ip_address' AND a.deleted_at IS NULL
		  AND a.status <> 'archived'
		  AND aa.state = 'confirmed' AND aa.decided_at IS NOT NULL`+sc+`
		ORDER BY a.name
		LIMIT `+fmt.Sprint(maxPersonConfirmedAddresses), args...)
	if err != nil {
		return nil, fmt.Errorf("list person-confirmed addresses: %w", err)
	}
	defer rows.Close()
	var out []scopeapp.ProviderConfirmed
	for rows.Next() {
		var (
			c  scopeapp.ProviderConfirmed
			at sql.NullTime
		)
		if err := rows.Scan(&c.AssetID, &c.Name, &at); err != nil {
			return nil, err
		}
		if at.Valid {
			t := at.Time.UTC()
			c.DecidedAt = &t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
