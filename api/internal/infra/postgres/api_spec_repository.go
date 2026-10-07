package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/apispec"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// APISpecRepository stores API descriptions of origin assets and their
// declared operations (RFC-056). Every query is tenant-scoped.
type APISpecRepository struct {
	db *DB
}

// NewAPISpecRepository creates an APISpecRepository.
func NewAPISpecRepository(db *DB) *APISpecRepository { return &APISpecRepository{db: db} }

var _ apispec.Repository = (*APISpecRepository)(nil)

const apiSpecColumns = `id, tenant_id, origin_asset_id, name, format, COALESCE(title, ''), COALESCE(spec_version, ''),
	digest, size_bytes, operation_count, truncated, uploaded_by, created_at`

func scanAPISpec(s interface{ Scan(...any) error }) (*apispec.Record, error) {
	var r apispec.Record
	var id, tenant, origin, format string
	var by sql.NullString
	if err := s.Scan(&id, &tenant, &origin, &r.Name, &format, &r.Title, &r.SpecVersion, &r.Digest,
		&r.SizeBytes, &r.OperationCount, &r.Truncated, &by, &r.CreatedAt); err != nil {
		return nil, err
	}
	r.ID, r.TenantID, r.OriginAssetID = shared.MustIDFromString(id), shared.MustIDFromString(tenant), shared.MustIDFromString(origin)
	r.Format, r.Digest = apispec.Format(format), strings.TrimSpace(r.Digest)
	if by.Valid {
		u, err := shared.IDFromString(by.String)
		if err == nil {
			r.UploadedBy = &u
		}
	}
	return &r, nil
}

// Create stores a description and its operations in one transaction. The
// composite foreign key ties it to an asset of the same tenant.
func (r *APISpecRepository) Create(ctx context.Context, rec *apispec.Record, ops []apispec.Operation) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var newID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO api_specs (tenant_id, origin_asset_id, name, format, title, spec_version,
			digest, size_bytes, operation_count, truncated, uploaded_by)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8, $9, $10, $11)
		RETURNING id, created_at`,
		rec.TenantID.String(), rec.OriginAssetID.String(), rec.Name, string(rec.Format), rec.Title, rec.SpecVersion,
		rec.Digest, rec.SizeBytes, rec.OperationCount, rec.Truncated, nullID(rec.UploadedBy),
	).Scan(&newID, &rec.CreatedAt); err != nil {
		return fmt.Errorf("create api spec: %w", err)
	}
	rec.ID = shared.MustIDFromString(newID)
	if len(ops) > 0 {
		methods, paths, keys, params := make([]string, len(ops)), make([]string, len(ops)), make([]string, len(ops)), make([]string, len(ops))
		deprecated := make([]bool, len(ops))
		for i, o := range ops {
			p, _ := json.Marshal(o.Params)
			if o.Params == nil || len(p) > 32768 {
				p = []byte("[]")
			}
			methods[i], paths[i], keys[i], params[i], deprecated[i] = o.Method, o.Path, apispec.MatchKey(o.Method, o.Path), string(p), o.Deprecated
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_spec_operations (tenant_id, spec_id, method, path, match_key, deprecated, params)
			SELECT $1::uuid, $2::uuid, u.m, u.p, u.k, u.d, u.j::jsonb
			FROM unnest($3::text[], $4::text[], $5::text[], $6::bool[], $7::text[]) AS u(m, p, k, d, j)
			ON CONFLICT DO NOTHING`,
			rec.TenantID.String(), rec.ID.String(), pq.Array(methods), pq.Array(paths), pq.Array(keys),
			pq.Array(deprecated), pq.Array(params)); err != nil {
			return fmt.Errorf("create api spec operations: %w", err)
		}
	}
	return tx.Commit()
}

// Get returns one description of the tenant, or shared.ErrNotFound.
func (r *APISpecRepository) Get(ctx context.Context, tenantID, id shared.ID) (*apispec.Record, error) {
	rec, err := scanAPISpec(r.db.QueryRowContext(ctx, "SELECT "+apiSpecColumns+" FROM api_specs WHERE tenant_id = $1 AND id = $2",
		tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get api spec: %w", err)
	}
	return rec, nil
}

// ListByOrigin lists an origin's descriptions, newest first.
func (r *APISpecRepository) ListByOrigin(ctx context.Context, tenantID, originAssetID shared.ID, limit int) ([]*apispec.Record, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+apiSpecColumns+` FROM api_specs
		WHERE tenant_id = $1 AND origin_asset_id = $2 ORDER BY created_at DESC LIMIT $3`,
		tenantID.String(), originAssetID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list api specs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []*apispec.Record{}
	for rows.Next() {
		rec, err := scanAPISpec(rows)
		if err != nil {
			return nil, fmt.Errorf("scan api spec: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// Operations returns a description's declared operations.
func (r *APISpecRepository) Operations(ctx context.Context, tenantID, specID shared.ID) ([]apispec.Operation, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT method, path, deprecated, params FROM api_spec_operations
		WHERE tenant_id = $1 AND spec_id = $2 ORDER BY path, method LIMIT $3`,
		tenantID.String(), specID.String(), apispec.MaxOperations)
	if err != nil {
		return nil, fmt.Errorf("list operations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []apispec.Operation{}
	for rows.Next() {
		var o apispec.Operation
		var params []byte
		if err := rows.Scan(&o.Method, &o.Path, &o.Deprecated, &params); err != nil {
			return nil, fmt.Errorf("scan operation: %w", err)
		}
		_ = json.Unmarshal(params, &o.Params)
		out = append(out, o)
	}
	return out, rows.Err()
}

// Observed returns the origin's active endpoints with their parameter
// names, for drift.
func (r *APISpecRepository) Observed(ctx context.Context, tenantID, originAssetID shared.ID, limit int) ([]apispec.Observed, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT e.id, e.method, e.path_template, COALESCE(e.last_status, 0), e.sources,
			COALESCE(array_agg(p.location || ':' || p.name ORDER BY p.location, p.name) FILTER (WHERE p.name IS NOT NULL), '{}')
		FROM web_endpoints e
		LEFT JOIN web_endpoint_params p ON p.endpoint_id = e.id AND p.tenant_id = e.tenant_id
		WHERE e.tenant_id = $1 AND e.origin_asset_id = $2 AND e.state = 'active' AND e.kind <> 'script'
		GROUP BY e.id ORDER BY e.path_template, e.method LIMIT $3`,
		tenantID.String(), originAssetID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("observed endpoints: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []apispec.Observed{}
	for rows.Next() {
		var o apispec.Observed
		var id string
		var sources, params pq.StringArray
		if err := rows.Scan(&id, &o.Method, &o.PathTemplate, &o.LastStatus, &sources, &params); err != nil {
			return nil, fmt.Errorf("scan observed: %w", err)
		}
		o.EndpointID, o.Sources, o.ParamNames = shared.MustIDFromString(id), []string(sources), []string(params)
		out = append(out, o)
	}
	return out, rows.Err()
}

// Delete removes a description of the tenant (its operations follow).
func (r *APISpecRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM api_specs WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("delete api spec: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}
