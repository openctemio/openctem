package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/codescan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CodeScanRepository stores code scanning settings and the baseline state of
// repository branches (docs/rfcs/RFC-091-code-scanning-baseline.md).
// repository_branches has no tenant column: every branch query goes through
// the repository asset and its tenant.
type CodeScanRepository struct {
	db *DB
}

var _ codescan.Repository = (*CodeScanRepository)(nil)

// NewCodeScanRepository creates the repository.
func NewCodeScanRepository(db *DB) *CodeScanRepository { return &CodeScanRepository{db: db} }

const codeScanSettingsColumns = `id, tenant_id, repository_asset_id, protected_branches, capabilities, schedule,
	routing, enabled, updated_by, created_at, updated_at`

func scanCodeScanSettings(row interface{ Scan(...any) error }) (codescan.Settings, error) {
	var (
		s                codescan.Settings
		id, tenant       string
		asset, updatedBy sql.NullString
		branches, caps   pq.StringArray
	)
	if err := row.Scan(&id, &tenant, &asset, &branches, &caps, &s.Schedule, &s.Routing, &s.Enabled,
		&updatedBy, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return s, err
	}
	s.ID, _ = shared.IDFromString(id)
	s.TenantID, _ = shared.IDFromString(tenant)
	if asset.Valid {
		a, _ := shared.IDFromString(asset.String)
		s.RepositoryAssetID = &a
	}
	if updatedBy.Valid {
		u, _ := shared.IDFromString(updatedBy.String)
		s.UpdatedBy = &u
	}
	s.ProtectedBranches, s.Capabilities = []string(branches), []string(caps)
	return s, nil
}

// GetSettings returns the template (assetID nil) or a repository's settings.
func (r *CodeScanRepository) GetSettings(ctx context.Context, tenantID shared.ID, assetID *shared.ID) (*codescan.Settings, error) {
	q := `SELECT ` + codeScanSettingsColumns + ` FROM code_scan_settings WHERE tenant_id = $1 AND repository_asset_id IS NULL`
	args := []any{tenantID.String()}
	if assetID != nil {
		q = `SELECT ` + codeScanSettingsColumns + ` FROM code_scan_settings WHERE tenant_id = $1 AND repository_asset_id = $2`
		args = append(args, assetID.String())
	}
	s, err := scanCodeScanSettings(r.db.QueryRowContext(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// UpsertSettings stores the template or a repository's settings. The
// repository must be the tenant's (composite foreign key).
func (r *CodeScanRepository) UpsertSettings(ctx context.Context, s *codescan.Settings) error {
	if s.ID.IsZero() {
		s.ID = shared.NewID()
	}
	var asset, updatedBy any
	if s.RepositoryAssetID != nil {
		asset = s.RepositoryAssetID.String()
	}
	if s.UpdatedBy != nil {
		updatedBy = s.UpdatedBy.String()
	}
	now := time.Now().UTC()
	err := r.db.QueryRowContext(ctx, `INSERT INTO code_scan_settings (id, tenant_id, repository_asset_id,
			protected_branches, capabilities, schedule, routing, enabled, updated_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
		ON CONFLICT ON CONSTRAINT uq_code_scan_settings_scope DO UPDATE SET
			protected_branches = EXCLUDED.protected_branches, capabilities = EXCLUDED.capabilities,
			schedule = EXCLUDED.schedule, routing = EXCLUDED.routing, enabled = EXCLUDED.enabled,
			updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at
		RETURNING id, created_at, updated_at`,
		s.ID.String(), s.TenantID.String(), asset, pq.Array(s.ProtectedBranches), pq.Array(s.Capabilities),
		s.Schedule, s.Routing, s.Enabled, updatedBy, now).Scan(new(string), &s.CreatedAt, &s.UpdatedAt)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23503" {
		return codescan.ErrNotFound
	}
	return err
}

// DeleteSettings removes a repository's own settings.
func (r *CodeScanRepository) DeleteSettings(ctx context.Context, tenantID, assetID shared.ID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM code_scan_settings WHERE tenant_id = $1 AND repository_asset_id = $2`,
		tenantID.String(), assetID.String())
	return err
}

const codeScanRepoColumns = `a.id, a.name, COALESCE(ar.default_branch, ''), COALESCE(ar.visibility, ''), COALESCE(ar.clone_url, '')`

func scanCodeScanRepo(row interface{ Scan(...any) error }) (codescan.RepositoryRef, error) {
	var ref codescan.RepositoryRef
	var id string
	err := row.Scan(&id, &ref.Name, &ref.DefaultBranch, &ref.Visibility, &ref.CloneURL)
	ref.AssetID, _ = shared.IDFromString(id)
	return ref, err
}

// GetRepository returns a repository asset of the tenant.
func (r *CodeScanRepository) GetRepository(ctx context.Context, tenantID, assetID shared.ID) (*codescan.RepositoryRef, error) {
	ref, err := scanCodeScanRepo(r.db.QueryRowContext(ctx, `SELECT `+codeScanRepoColumns+` FROM assets a
		LEFT JOIN asset_repositories ar ON ar.asset_id = a.id
		WHERE a.tenant_id = $1 AND a.id = $2 AND a.asset_type = 'repository' AND a.deleted_at IS NULL`,
		tenantID.String(), assetID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, codescan.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &ref, nil
}

// ListRepositories lists the tenant's repositories within a data scope.
func (r *CodeScanRepository) ListRepositories(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit, offset int) ([]codescan.RepositoryRef, int, error) {
	args := []any{tenantID.String()}
	cond, args := dataScopeCond("a.id", scope, args)
	where := `a.tenant_id = $1 AND a.asset_type = 'repository' AND a.deleted_at IS NULL AND ` + cond
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets a WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := r.db.QueryContext(ctx, `SELECT `+codeScanRepoColumns+` FROM assets a
		LEFT JOIN asset_repositories ar ON ar.asset_id = a.id
		WHERE `+where+fmt.Sprintf(` ORDER BY a.name, a.id LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	out := []codescan.RepositoryRef{}
	for rows.Next() {
		ref, err := scanCodeScanRepo(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, ref)
	}
	return out, total, rows.Err()
}

// RepositorySettings returns the repositories' own settings by asset id.
func (r *CodeScanRepository) RepositorySettings(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]codescan.Settings, error) {
	out := map[shared.ID]codescan.Settings{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+codeScanSettingsColumns+` FROM code_scan_settings
		WHERE tenant_id = $1 AND repository_asset_id = ANY($2::uuid[])`, tenantID.String(), pq.Array(codeScanIDs(assetIDs)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		s, err := scanCodeScanSettings(rows)
		if err != nil {
			return nil, err
		}
		out[*s.RepositoryAssetID] = s
	}
	return out, rows.Err()
}

// Branches returns the repositories' branches by asset id.
func (r *CodeScanRepository) Branches(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID][]codescan.Branch, error) {
	out := map[shared.ID][]codescan.Branch{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT b.repository_id, b.id, b.name, b.is_default, COALESCE(b.last_commit_sha, ''),
			b.baseline_state, COALESCE(b.baseline_commit, ''), b.baseline_at, COALESCE(b.baseline_error, ''),
			b.last_full_scan_at, COALESCE(b.last_full_scan_trigger, '')
		FROM repository_branches b
		JOIN assets a ON a.id = b.repository_id AND a.tenant_id = $1
		WHERE b.repository_id = ANY($2::uuid[])
		ORDER BY b.is_default DESC, b.name`, tenantID.String(), pq.Array(codeScanIDs(assetIDs)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			b          codescan.Branch
			repo, id   string
			baselineAt sql.NullTime
			fullAt     sql.NullTime
		)
		if err := rows.Scan(&repo, &id, &b.Name, &b.IsDefault, &b.LastCommitSHA, &b.BaselineState, &b.BaselineCommit,
			&baselineAt, &b.BaselineError, &fullAt, &b.LastFullScanTrigger); err != nil {
			return nil, err
		}
		b.ID, _ = shared.IDFromString(id)
		if baselineAt.Valid {
			t := baselineAt.Time
			b.BaselineAt = &t
		}
		if fullAt.Valid {
			t := fullAt.Time
			b.LastFullScanAt = &t
		}
		rid, _ := shared.IDFromString(repo)
		out[rid] = append(out[rid], b)
	}
	return out, rows.Err()
}

// EnsureDefaultBranch records the default branch when no branch of that name
// is known. The repository must be the tenant's and have its repository row.
func (r *CodeScanRepository) EnsureDefaultBranch(ctx context.Context, tenantID, assetID shared.ID, name string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO repository_branches (repository_id, name, branch_type, is_default)
		SELECT ar.asset_id, $3, 'main', true FROM asset_repositories ar
		JOIN assets a ON a.id = ar.asset_id AND a.tenant_id = $1
		WHERE ar.asset_id = $2
		ON CONFLICT (repository_id, name) DO NOTHING`, tenantID.String(), assetID.String(), name)
	return err
}

// QueueFullScan marks branches queued for a full scan.
func (r *CodeScanRepository) QueueFullScan(ctx context.Context, tenantID, assetID shared.ID, branchIDs []shared.ID, trigger string) (int, error) {
	if len(branchIDs) == 0 {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, `UPDATE repository_branches b SET baseline_state = 'queued',
			last_full_scan_trigger = $4, baseline_error = NULL, updated_at = NOW()
		FROM assets a
		WHERE a.id = b.repository_id AND a.tenant_id = $1 AND b.repository_id = $2
		  AND b.id = ANY($3::uuid[]) AND b.baseline_state NOT IN ('queued', 'running')`,
		tenantID.String(), assetID.String(), pq.Array(codeScanIDs(branchIDs)), trigger)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func codeScanIDs(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}
