package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RepositoryIdentityRepository finds a tenant's repository asset by the code
// host's immutable repository id (GitHub repository_id, GitLab project_id,
// Bitbucket repository UUID) instead of its name, which changes on a rename
// or transfer and is written differently by repository import and CI.
//
// The id lives on the repository extension (asset_repositories.repo_id) with
// the host taken from its web or clone URL, so one id on two hosts (a GitHub
// id and a GitLab id that happen to be equal) never matches. Every query is
// scoped to the tenant through assets.tenant_id.
type RepositoryIdentityRepository struct {
	db *DB
}

// NewRepositoryIdentityRepository creates the repository.
func NewRepositoryIdentityRepository(db *DB) *RepositoryIdentityRepository {
	return &RepositoryIdentityRepository{db: db}
}

// repoHostSQL is the lower-case host of a repository extension's web URL
// (else clone URL), "" when neither is an absolute URL.
const repoHostSQL = `lower(COALESCE(substring(COALESCE(NULLIF(r.web_url, ''), r.clone_url, '') from '^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^@/]*@)?([^/]+)'), ''))`

// FindRepositoryByProviderID returns the tenant's oldest repository asset
// whose extension carries the repository id on that host.
func (r *RepositoryIdentityRepository) FindRepositoryByProviderID(ctx context.Context, tenantID shared.ID, host, repoID string) (shared.ID, bool, error) {
	if host == "" || repoID == "" {
		return shared.ID{}, false, nil
	}
	var id string
	err := r.db.QueryRowContext(ctx, `SELECT a.id FROM asset_repositories r JOIN assets a ON a.id = r.asset_id
		WHERE a.tenant_id = $1 AND a.asset_type = 'repository' AND r.repo_id = $3 AND `+repoHostSQL+` = lower($2)
		ORDER BY a.created_at, a.id LIMIT 1`, tenantID.String(), host, repoID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return shared.ID{}, false, nil
	}
	if err != nil {
		return shared.ID{}, false, fmt.Errorf("find repository by provider id: %w", err)
	}
	out, err := shared.IDFromString(id)
	return out, err == nil, err
}

// StampRepositoryIdentity records the repository id and web address on a
// repository asset's extension where they are still empty, so later lookups
// by id find it. An id already recorded is never replaced.
func (r *RepositoryIdentityRepository) StampRepositoryIdentity(ctx context.Context, tenantID, assetID shared.ID, host, path, repoID string) error {
	if host == "" || path == "" || repoID == "" {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `UPDATE asset_repositories r SET
			repo_id = CASE WHEN COALESCE(r.repo_id, '') = '' THEN $3 ELSE r.repo_id END,
			web_url = CASE WHEN COALESCE(r.web_url, '') = '' THEN $4 ELSE r.web_url END
		FROM assets a
		WHERE a.id = r.asset_id AND a.tenant_id = $1 AND r.asset_id = $2 AND a.asset_type = 'repository'
		  AND (COALESCE(r.repo_id, '') = '' OR COALESCE(r.web_url, '') = '')`,
		tenantID.String(), assetID.String(), repoID, "https://"+host+"/"+path)
	if err != nil {
		return fmt.Errorf("stamp repository identity: %w", err)
	}
	return nil
}

// RenameRepositoryAsset gives a repository asset a new name when no other
// asset of the tenant holds it; renamed says whether it did.
func (r *RepositoryIdentityRepository) RenameRepositoryAsset(ctx context.Context, tenantID, assetID shared.ID, name string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE assets SET name = $3, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND asset_type = 'repository' AND name <> $3
		  AND NOT EXISTS (SELECT 1 FROM assets o WHERE o.tenant_id = $1 AND o.name = $3)`,
		tenantID.String(), assetID.String(), name)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return false, nil
		}
		return false, fmt.Errorf("rename repository asset: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RepositoryAssetOfPipelineRepo returns the repository asset of the tenant's
// most recently updated CI pipeline for a provider's repository id: the
// asset a renamed or transferred repository already has.
func (r *RepositoryIdentityRepository) RepositoryAssetOfPipelineRepo(ctx context.Context, tenantID shared.ID, provider, issuer, externalRepoID string) (shared.ID, bool, error) {
	var id string
	err := r.db.QueryRowContext(ctx, `SELECT p.repository_asset_id FROM ci_pipelines p
		JOIN assets a ON a.id = p.repository_asset_id AND a.tenant_id = p.tenant_id AND a.asset_type = 'repository'
		WHERE p.tenant_id = $1 AND p.provider = $2 AND p.issuer = $3 AND p.external_repo_id = $4
		ORDER BY p.updated_at DESC LIMIT 1`, tenantID.String(), provider, issuer, externalRepoID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return shared.ID{}, false, nil
	}
	if err != nil {
		return shared.ID{}, false, fmt.Errorf("find pipeline repository: %w", err)
	}
	out, err := shared.IDFromString(id)
	return out, err == nil, err
}
