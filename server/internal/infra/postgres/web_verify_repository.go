package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/webverify"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// WebVerifyRepository stores the verification ledger of the web verification
// planner (internal/app/webverify). Every query is tenant-scoped, except the
// tenant list the platform job walks.
type WebVerifyRepository struct {
	db *DB
}

// NewWebVerifyRepository creates the repository.
func NewWebVerifyRepository(db *DB) *WebVerifyRepository { return &WebVerifyRepository{db: db} }

var _ webverify.Store = (*WebVerifyRepository)(nil)

// verifiable is the shared WHERE of a verification candidate: an active,
// in-scope GET endpoint of a catalog entry that answered 2xx, whose origin
// is a live asset, and that was not verified for its current response
// signature. A row planned but never run (refused by the gate, say) is
// retried after a day.
const verifiableSQL = `
	FROM web_endpoints e
	JOIN assets a ON a.id = e.origin_asset_id AND a.tenant_id = e.tenant_id AND a.deleted_at IS NULL
	LEFT JOIN web_endpoint_verifications v ON v.tenant_id = e.tenant_id AND v.endpoint_id = e.id
	WHERE e.state = 'active' AND e.in_scope AND e.exclusion_id IS NULL
	  AND e.method IN ('GET', 'ANY')
	  AND e.catalog_key = ANY($1::text[])
	  AND e.last_status BETWEEN 200 AND 299
	  AND (v.endpoint_id IS NULL
	       OR v.response_sig <> COALESCE(e.response_sig, '')
	       OR (v.run_id IS NULL AND v.planned_at < now() - interval '24 hours'))`

// TenantsWithCandidates lists tenants that have at least one candidate, so
// the platform job visits only those.
func (r *WebVerifyRepository) TenantsWithCandidates(ctx context.Context, keys []string, limit int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT e.tenant_id `+verifiableSQL+` LIMIT $2`, pq.Array(keys), limit)
	if err != nil {
		return nil, fmt.Errorf("tenants with web verification candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			continue
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Candidates returns the tenant's candidates, newest endpoints first.
func (r *WebVerifyRepository) Candidates(ctx context.Context, tenantID shared.ID, keys []string, limit int) ([]webverify.Candidate, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT e.id, e.origin_asset_id, a.name, e.method, e.path_template, COALESCE(e.example_path, ''),
		       e.catalog_key, COALESCE(e.response_sig, '')`+verifiableSQL+` AND e.tenant_id = $3
		ORDER BY e.first_seen_at DESC, e.id LIMIT $2`, pq.Array(keys), limit, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("web verification candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []webverify.Candidate
	for rows.Next() {
		var c webverify.Candidate
		var ep, origin string
		if err := rows.Scan(&ep, &origin, &c.OriginName, &c.Method, &c.PathTemplate, &c.ExamplePath, &c.CatalogKey, &c.ResponseSig); err != nil {
			return nil, err
		}
		if c.EndpointID, err = shared.IDFromString(ep); err != nil {
			continue
		}
		if c.OriginAssetID, err = shared.IDFromString(origin); err != nil {
			continue
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RunPlannedSince counts the tenant's endpoints whose verification ran
// since the time (the daily budget).
func (r *WebVerifyRepository) RunPlannedSince(ctx context.Context, tenantID shared.ID, since time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM web_endpoint_verifications
		WHERE tenant_id = $1 AND run_id IS NOT NULL AND planned_at > $2`, tenantID.String(), since).Scan(&n)
	if err != nil && err != sql.ErrNoRows {
		return 0, fmt.Errorf("count planned web verifications: %w", err)
	}
	return n, nil
}

// RecordPlanned writes the ledger rows. An endpoint id that is not the
// tenant's matches nothing.
func (r *WebVerifyRepository) RecordPlanned(ctx context.Context, tenantID shared.ID, rows []webverify.Planned) error {
	if len(rows) == 0 {
		return nil
	}
	ids, sigs, keys, runs := make([]string, len(rows)), make([]string, len(rows)), make([]string, len(rows)), make([]string, len(rows))
	for i, p := range rows {
		ids[i], sigs[i], keys[i] = p.EndpointID.String(), p.ResponseSig, p.CatalogKey
		if p.RunID != nil {
			runs[i] = p.RunID.String()
		}
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO web_endpoint_verifications (tenant_id, endpoint_id, response_sig, catalog_key, planned_at, run_id)
		SELECT $1::uuid, e.id, u.sig, u.key, now(), NULLIF(u.run, '')::uuid
		FROM unnest($2::text[], $3::text[], $4::text[], $5::text[]) AS u(id, sig, key, run)
		JOIN web_endpoints e ON e.tenant_id = $1::uuid AND e.id = u.id::uuid
		ON CONFLICT (tenant_id, endpoint_id) DO UPDATE SET
			response_sig = excluded.response_sig, catalog_key = excluded.catalog_key,
			planned_at = excluded.planned_at, run_id = excluded.run_id`,
		tenantID.String(), pq.Array(ids), pq.Array(sigs), pq.Array(keys), pq.Array(runs))
	if err != nil {
		return fmt.Errorf("record planned web verifications: %w", err)
	}
	return nil
}
