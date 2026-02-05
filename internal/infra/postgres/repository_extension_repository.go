package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// RepositoryExtensionRepository implements asset.RepositoryExtensionRepository using PostgreSQL.
type RepositoryExtensionRepository struct {
	db *DB
}

// NewRepositoryExtensionRepository creates a new RepositoryExtensionRepository.
func NewRepositoryExtensionRepository(db *DB) *RepositoryExtensionRepository {
	return &RepositoryExtensionRepository{db: db}
}

// Create persists a new repository extension.
func (r *RepositoryExtensionRepository) Create(ctx context.Context, repo *asset.RepositoryExtension) error {
	languages, err := json.Marshal(repo.Languages())
	if err != nil {
		return fmt.Errorf("failed to marshal languages: %w", err)
	}

	query := `
		INSERT INTO asset_repositories (
			asset_id, repo_id, full_name, scm_organization, clone_url, web_url, ssh_url,
			default_branch, visibility, language, languages, topics,
			stars, forks, watchers, open_issues, contributors_count, size_kb,
			risk_score, scan_enabled, scan_schedule, last_scanned_at,
			branch_count, protected_branch_count, component_count, vulnerable_component_count,
			repo_created_at, repo_updated_at, repo_pushed_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29)
	`

	_, err = r.db.ExecContext(ctx, query,
		repo.AssetID().String(),
		nullString(repo.RepoID()),
		repo.FullName(),
		nullString(repo.SCMOrganization()),
		nullString(repo.CloneURL()),
		nullString(repo.WebURL()),
		nullString(repo.SSHURL()),
		repo.DefaultBranch(),
		repo.Visibility().String(),
		nullString(repo.Language()),
		languages,
		pq.Array(repo.Topics()),
		repo.Stars(),
		repo.Forks(),
		repo.Watchers(),
		repo.OpenIssues(),
		repo.ContributorsCount(),
		repo.SizeKB(),
		repo.RiskScore(),
		repo.ScanEnabled(),
		nullString(repo.ScanSchedule()),
		nullTime(repo.LastScannedAt()),
		repo.BranchCount(),
		repo.ProtectedBranchCount(),
		repo.ComponentCount(),
		repo.VulnerableComponentCount(),
		nullTime(repo.RepoCreatedAt()),
		nullTime(repo.RepoUpdatedAt()),
		nullTime(repo.RepoPushedAt()),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("repository extension for asset %s already exists", repo.AssetID())
		}
		return fmt.Errorf("failed to create repository extension: %w", err)
	}

	return nil
}

// GetByAssetID retrieves a repository extension by asset ID.
func (r *RepositoryExtensionRepository) GetByAssetID(ctx context.Context, assetID shared.ID) (*asset.RepositoryExtension, error) {
	query := r.selectQuery() + " WHERE ar.asset_id = $1"

	row := r.db.QueryRowContext(ctx, query, assetID.String())
	return r.scanRepo(row, assetID)
}

// Update updates an existing repository extension.
func (r *RepositoryExtensionRepository) Update(ctx context.Context, repo *asset.RepositoryExtension) error {
	languages, err := json.Marshal(repo.Languages())
	if err != nil {
		return fmt.Errorf("failed to marshal languages: %w", err)
	}

	query := `
		UPDATE asset_repositories
		SET repo_id = $2, full_name = $3, scm_organization = $4, clone_url = $5, web_url = $6, ssh_url = $7,
		    default_branch = $8, visibility = $9, language = $10, languages = $11, topics = $12,
		    stars = $13, forks = $14, watchers = $15, open_issues = $16, contributors_count = $17, size_kb = $18,
		    risk_score = $19, scan_enabled = $20, scan_schedule = $21, last_scanned_at = $22,
		    branch_count = $23, protected_branch_count = $24, component_count = $25, vulnerable_component_count = $26,
		    repo_created_at = $27, repo_updated_at = $28, repo_pushed_at = $29
		WHERE asset_id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		repo.AssetID().String(),
		nullString(repo.RepoID()),
		repo.FullName(),
		nullString(repo.SCMOrganization()),
		nullString(repo.CloneURL()),
		nullString(repo.WebURL()),
		nullString(repo.SSHURL()),
		repo.DefaultBranch(),
		repo.Visibility().String(),
		nullString(repo.Language()),
		languages,
		pq.Array(repo.Topics()),
		repo.Stars(),
		repo.Forks(),
		repo.Watchers(),
		repo.OpenIssues(),
		repo.ContributorsCount(),
		repo.SizeKB(),
		repo.RiskScore(),
		repo.ScanEnabled(),
		nullString(repo.ScanSchedule()),
		nullTime(repo.LastScannedAt()),
		repo.BranchCount(),
		repo.ProtectedBranchCount(),
		repo.ComponentCount(),
		repo.VulnerableComponentCount(),
		nullTime(repo.RepoCreatedAt()),
		nullTime(repo.RepoUpdatedAt()),
		nullTime(repo.RepoPushedAt()),
	)

	if err != nil {
		return fmt.Errorf("failed to update repository extension: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete removes a repository extension by asset ID.
func (r *RepositoryExtensionRepository) Delete(ctx context.Context, assetID shared.ID) error {
	query := `DELETE FROM asset_repositories WHERE asset_id = $1`

	result, err := r.db.ExecContext(ctx, query, assetID.String())
	if err != nil {
		return fmt.Errorf("failed to delete repository extension: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// GetByFullName retrieves a repository by full name.
func (r *RepositoryExtensionRepository) GetByFullName(ctx context.Context, tenantID shared.ID, fullName string) (*asset.RepositoryExtension, error) {
	query := r.selectQuery() + `
		WHERE ar.full_name = $1
		AND ar.asset_id IN (SELECT id FROM assets WHERE tenant_id = $2)
	`

	row := r.db.QueryRowContext(ctx, query, fullName, tenantID.String())
	return r.scanRepo(row, shared.ID{})
}

// ListByTenant retrieves all repositories for a tenant.
func (r *RepositoryExtensionRepository) ListByTenant(ctx context.Context, tenantID shared.ID, opts asset.ListOptions, page pagination.Pagination) (pagination.Result[*asset.RepositoryExtension], error) {
	baseQuery := r.selectQuery() + `
		WHERE ar.asset_id IN (SELECT id FROM assets WHERE tenant_id = $1)
	`
	countQuery := `
		SELECT COUNT(*) FROM asset_repositories ar
		WHERE ar.asset_id IN (SELECT id FROM assets WHERE tenant_id = $1)
	`

	// Apply sorting (default to full_name ASC)
	orderBy := "ar.full_name ASC"
	if opts.Sort != nil && !opts.Sort.IsEmpty() {
		orderBy = "ar." + opts.Sort.SQLWithDefault("full_name ASC")
	}
	baseQuery += " ORDER BY " + orderBy
	baseQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", page.Limit(), page.Offset())

	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, tenantID.String()).Scan(&total)
	if err != nil {
		return pagination.Result[*asset.RepositoryExtension]{}, fmt.Errorf("failed to count repositories: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, baseQuery, tenantID.String())
	if err != nil {
		return pagination.Result[*asset.RepositoryExtension]{}, fmt.Errorf("failed to query repositories: %w", err)
	}
	defer rows.Close()

	var repos []*asset.RepositoryExtension
	for rows.Next() {
		repo, err := r.scanRepoFromRows(rows)
		if err != nil {
			return pagination.Result[*asset.RepositoryExtension]{}, err
		}
		repos = append(repos, repo)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*asset.RepositoryExtension]{}, fmt.Errorf("failed to iterate repositories: %w", err)
	}

	return pagination.NewResult(repos, total, page), nil
}

// Helper methods

func (r *RepositoryExtensionRepository) selectQuery() string {
	return `
		SELECT ar.asset_id, ar.repo_id, ar.full_name, ar.scm_organization, ar.clone_url, ar.web_url, ar.ssh_url,
			   ar.default_branch, ar.visibility, ar.language, ar.languages, ar.topics,
			   ar.stars, ar.forks, ar.watchers, ar.open_issues, ar.contributors_count, ar.size_kb,
			   COALESCE((SELECT COUNT(*) FROM findings f WHERE f.asset_id = ar.asset_id), 0) as finding_count,
			   ar.risk_score, ar.scan_enabled, ar.scan_schedule, ar.last_scanned_at,
			   ar.branch_count, ar.protected_branch_count, ar.component_count, ar.vulnerable_component_count,
			   ar.repo_created_at, ar.repo_updated_at, ar.repo_pushed_at
		FROM asset_repositories ar
	`
}

func (r *RepositoryExtensionRepository) scanRepo(row *sql.Row, assetID shared.ID) (*asset.RepositoryExtension, error) {
	repo, err := r.doScan(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan repository extension: %w", err)
	}
	return repo, nil
}

func (r *RepositoryExtensionRepository) scanRepoFromRows(rows *sql.Rows) (*asset.RepositoryExtension, error) {
	return r.doScan(rows.Scan)
}

func (r *RepositoryExtensionRepository) doScan(scan func(dest ...any) error) (*asset.RepositoryExtension, error) {
	var (
		assetIDStr               string
		repoID                   sql.NullString
		fullName                 string
		scmOrganization          sql.NullString
		cloneURL                 sql.NullString
		webURL                   sql.NullString
		sshURL                   sql.NullString
		defaultBranch            string
		visibility               string
		language                 sql.NullString
		languages                []byte
		topics                   pq.StringArray
		stars                    int
		forks                    int
		watchers                 int
		openIssues               int
		contributorsCount        int
		sizeKB                   int
		findingCount             int
		riskScore                float64
		scanEnabled              bool
		scanSchedule             sql.NullString
		lastScannedAt            sql.NullTime
		branchCount              int
		protectedBranchCount     int
		componentCount           int
		vulnerableComponentCount int
		repoCreatedAt            sql.NullTime
		repoUpdatedAt            sql.NullTime
		repoPushedAt             sql.NullTime
	)

	err := scan(
		&assetIDStr, &repoID, &fullName, &scmOrganization, &cloneURL, &webURL, &sshURL,
		&defaultBranch, &visibility, &language, &languages, &topics,
		&stars, &forks, &watchers, &openIssues, &contributorsCount, &sizeKB,
		&findingCount, &riskScore, &scanEnabled, &scanSchedule, &lastScannedAt,
		&branchCount, &protectedBranchCount, &componentCount, &vulnerableComponentCount,
		&repoCreatedAt, &repoUpdatedAt, &repoPushedAt,
	)
	if err != nil {
		return nil, err
	}

	parsedAssetID, err := shared.IDFromString(assetIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse asset_id: %w", err)
	}

	var languagesMap map[string]int64
	if len(languages) > 0 {
		if err := json.Unmarshal(languages, &languagesMap); err != nil {
			languagesMap = make(map[string]int64)
		}
	}

	var lastScanned *time.Time
	if lastScannedAt.Valid {
		lastScanned = &lastScannedAt.Time
	}

	var repoCreated *time.Time
	if repoCreatedAt.Valid {
		repoCreated = &repoCreatedAt.Time
	}

	var repoUpdated *time.Time
	if repoUpdatedAt.Valid {
		repoUpdated = &repoUpdatedAt.Time
	}

	var repoPushed *time.Time
	if repoPushedAt.Valid {
		repoPushed = &repoPushedAt.Time
	}

	return asset.ReconstituteRepositoryExtension(
		parsedAssetID,
		nullStringValue(repoID),
		fullName,
		nullStringValue(scmOrganization),
		nullStringValue(cloneURL),
		nullStringValue(webURL),
		nullStringValue(sshURL),
		defaultBranch,
		asset.RepoVisibility(visibility),
		nullStringValue(language),
		languagesMap,
		[]string(topics),
		stars,
		forks,
		watchers,
		openIssues,
		contributorsCount,
		sizeKB,
		findingCount,
		riskScore,
		scanEnabled,
		nullStringValue(scanSchedule),
		lastScanned,
		branchCount,
		protectedBranchCount,
		componentCount,
		vulnerableComponentCount,
		repoCreated,
		repoUpdated,
		repoPushed,
	), nil
}
