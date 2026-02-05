package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
)

// IntegrationSCMExtensionRepository implements integration.SCMExtensionRepository using PostgreSQL.
type IntegrationSCMExtensionRepository struct {
	db              *DB
	integrationRepo *IntegrationRepository
}

// NewIntegrationSCMExtensionRepository creates a new IntegrationSCMExtensionRepository.
func NewIntegrationSCMExtensionRepository(db *DB, integrationRepo *IntegrationRepository) *IntegrationSCMExtensionRepository {
	return &IntegrationSCMExtensionRepository{
		db:              db,
		integrationRepo: integrationRepo,
	}
}

// Ensure IntegrationSCMExtensionRepository implements integration.SCMExtensionRepository
var _ integration.SCMExtensionRepository = (*IntegrationSCMExtensionRepository)(nil)

// Create creates a new SCM extension.
func (r *IntegrationSCMExtensionRepository) Create(ctx context.Context, ext *integration.SCMExtension) error {
	query := `
		INSERT INTO integration_scm_extensions (
			integration_id, scm_organization, repository_count,
			webhook_id, webhook_secret, webhook_url,
			default_branch_pattern, auto_import_repos,
			import_private_repos, import_archived_repos,
			include_patterns, exclude_patterns, last_repo_sync_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)
	`

	_, err := r.db.ExecContext(ctx, query,
		ext.IntegrationID().String(),
		ext.SCMOrganization(),
		ext.RepositoryCount(),
		ext.WebhookID(),
		ext.WebhookSecret(),
		ext.WebhookURL(),
		ext.DefaultBranchPattern(),
		ext.AutoImportRepos(),
		ext.ImportPrivateRepos(),
		ext.ImportArchivedRepos(),
		pq.Array(ext.IncludePatterns()),
		pq.Array(ext.ExcludePatterns()),
		ext.LastRepoSyncAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return shared.ErrAlreadyExists
		}
		return fmt.Errorf("create scm extension: %w", err)
	}

	return nil
}

// GetByIntegrationID retrieves an SCM extension by integration ID.
func (r *IntegrationSCMExtensionRepository) GetByIntegrationID(ctx context.Context, integrationID integration.ID) (*integration.SCMExtension, error) {
	query := `
		SELECT integration_id, scm_organization, repository_count,
			   webhook_id, webhook_secret, webhook_url,
			   default_branch_pattern, auto_import_repos,
			   import_private_repos, import_archived_repos,
			   include_patterns, exclude_patterns, last_repo_sync_at
		FROM integration_scm_extensions
		WHERE integration_id = $1
	`

	row := r.db.QueryRowContext(ctx, query, integrationID.String())
	return r.scanSCMExtension(row)
}

// Update updates an existing SCM extension.
func (r *IntegrationSCMExtensionRepository) Update(ctx context.Context, ext *integration.SCMExtension) error {
	query := `
		UPDATE integration_scm_extensions SET
			scm_organization = $2,
			repository_count = $3,
			webhook_id = $4,
			webhook_secret = $5,
			webhook_url = $6,
			default_branch_pattern = $7,
			auto_import_repos = $8,
			import_private_repos = $9,
			import_archived_repos = $10,
			include_patterns = $11,
			exclude_patterns = $12,
			last_repo_sync_at = $13
		WHERE integration_id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		ext.IntegrationID().String(),
		ext.SCMOrganization(),
		ext.RepositoryCount(),
		ext.WebhookID(),
		ext.WebhookSecret(),
		ext.WebhookURL(),
		ext.DefaultBranchPattern(),
		ext.AutoImportRepos(),
		ext.ImportPrivateRepos(),
		ext.ImportArchivedRepos(),
		pq.Array(ext.IncludePatterns()),
		pq.Array(ext.ExcludePatterns()),
		ext.LastRepoSyncAt(),
	)
	if err != nil {
		return fmt.Errorf("update scm extension: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return integration.ErrSCMExtensionNotFound
	}

	return nil
}

// Delete deletes an SCM extension by integration ID.
func (r *IntegrationSCMExtensionRepository) Delete(ctx context.Context, integrationID integration.ID) error {
	query := `DELETE FROM integration_scm_extensions WHERE integration_id = $1`

	result, err := r.db.ExecContext(ctx, query, integrationID.String())
	if err != nil {
		return fmt.Errorf("delete scm extension: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return integration.ErrSCMExtensionNotFound
	}

	return nil
}

// GetIntegrationWithSCM retrieves an integration with its SCM extension.
func (r *IntegrationSCMExtensionRepository) GetIntegrationWithSCM(ctx context.Context, id integration.ID) (*integration.IntegrationWithSCM, error) {
	// Get the integration
	intg, err := r.integrationRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Check if it's an SCM integration
	if intg.Category() != integration.CategorySCM {
		return nil, fmt.Errorf("%w: integration is not an SCM type", shared.ErrValidation)
	}

	// Get the SCM extension
	ext, err := r.GetByIntegrationID(ctx, id)
	if err != nil {
		// Extension might not exist, that's okay for backward compatibility
		if errors.Is(err, integration.ErrSCMExtensionNotFound) {
			return integration.NewIntegrationWithSCM(intg, nil), nil
		}
		return nil, err
	}

	return integration.NewIntegrationWithSCM(intg, ext), nil
}

// ListIntegrationsWithSCM lists all SCM integrations with their extensions.
func (r *IntegrationSCMExtensionRepository) ListIntegrationsWithSCM(ctx context.Context, tenantID integration.ID) ([]*integration.IntegrationWithSCM, error) {
	query := `
		SELECT
			i.id, i.tenant_id, i.name, i.description, i.category, i.provider,
			i.status, i.status_message, i.auth_type, i.base_url, i.credentials_encrypted,
			i.last_sync_at, i.next_sync_at, i.sync_interval_minutes, i.sync_error,
			i.config, i.metadata, i.stats, i.created_at, i.updated_at, i.created_by,
			s.scm_organization, s.repository_count, s.webhook_id, s.webhook_secret,
			s.webhook_url, s.default_branch_pattern, s.auto_import_repos,
			s.import_private_repos, s.import_archived_repos,
			s.include_patterns, s.exclude_patterns, s.last_repo_sync_at
		FROM integrations i
		LEFT JOIN integration_scm_extensions s ON i.id = s.integration_id
		WHERE i.tenant_id = $1 AND i.category = 'scm'
		ORDER BY i.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list scm integrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make([]*integration.IntegrationWithSCM, 0)
	for rows.Next() {
		intgWithSCM, err := r.scanIntegrationWithSCMRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, intgWithSCM)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return result, nil
}

// scanSCMExtension scans a single row into an SCMExtension.
func (r *IntegrationSCMExtensionRepository) scanSCMExtension(row *sql.Row) (*integration.SCMExtension, error) {
	var (
		integrationID        string
		scmOrganization      sql.NullString
		repositoryCount      int
		webhookID            sql.NullString
		webhookSecret        sql.NullString
		webhookURL           sql.NullString
		defaultBranchPattern sql.NullString
		autoImportRepos      bool
		importPrivateRepos   bool
		importArchivedRepos  bool
		includePatterns      pq.StringArray
		excludePatterns      pq.StringArray
		lastRepoSyncAt       sql.NullTime
	)

	err := row.Scan(
		&integrationID, &scmOrganization, &repositoryCount,
		&webhookID, &webhookSecret, &webhookURL,
		&defaultBranchPattern, &autoImportRepos,
		&importPrivateRepos, &importArchivedRepos,
		&includePatterns, &excludePatterns, &lastRepoSyncAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, integration.ErrSCMExtensionNotFound
		}
		return nil, fmt.Errorf("scan scm extension: %w", err)
	}

	var lastSync *time.Time
	if lastRepoSyncAt.Valid {
		lastSync = &lastRepoSyncAt.Time
	}

	intgID, _ := shared.IDFromString(integrationID)

	return integration.ReconstructSCMExtension(
		intgID,
		scmOrganization.String,
		repositoryCount,
		webhookID.String,
		webhookSecret.String,
		webhookURL.String,
		defaultBranchPattern.String,
		autoImportRepos,
		importPrivateRepos,
		importArchivedRepos,
		[]string(includePatterns),
		[]string(excludePatterns),
		lastSync,
	), nil
}

// scanIntegrationWithSCMRow scans a row from sql.Rows into an IntegrationWithSCM.
func (r *IntegrationSCMExtensionRepository) scanIntegrationWithSCMRow(rows *sql.Rows) (*integration.IntegrationWithSCM, error) {
	var (
		// Integration fields
		id                   string
		tenantID             string
		name                 string
		description          sql.NullString
		category             string
		provider             string
		status               string
		statusMessage        sql.NullString
		authType             string
		baseURL              sql.NullString
		credentialsEncrypted sql.NullString
		lastSyncAt           sql.NullTime
		nextSyncAt           sql.NullTime
		syncIntervalMinutes  int
		syncError            sql.NullString
		configJSON           []byte
		metadataJSON         []byte
		statsJSON            []byte
		createdAt            time.Time
		updatedAt            time.Time
		createdBy            sql.NullString
		// SCM extension fields (nullable due to LEFT JOIN)
		scmOrganization      sql.NullString
		repositoryCount      sql.NullInt32
		webhookID            sql.NullString
		webhookSecret        sql.NullString
		webhookURL           sql.NullString
		defaultBranchPattern sql.NullString
		autoImportRepos      sql.NullBool
		importPrivateRepos   sql.NullBool
		importArchivedRepos  sql.NullBool
		includePatterns      pq.StringArray
		excludePatterns      pq.StringArray
		lastRepoSyncAt       sql.NullTime
	)

	err := rows.Scan(
		// Integration
		&id, &tenantID, &name, &description, &category, &provider,
		&status, &statusMessage, &authType, &baseURL, &credentialsEncrypted,
		&lastSyncAt, &nextSyncAt, &syncIntervalMinutes, &syncError,
		&configJSON, &metadataJSON, &statsJSON, &createdAt, &updatedAt, &createdBy,
		// SCM extension
		&scmOrganization, &repositoryCount, &webhookID, &webhookSecret,
		&webhookURL, &defaultBranchPattern, &autoImportRepos,
		&importPrivateRepos, &importArchivedRepos,
		&includePatterns, &excludePatterns, &lastRepoSyncAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan integration with scm row: %w", err)
	}

	// Reconstruct integration
	intg, err := r.integrationRepo.reconstructIntegration(
		id, tenantID, name, description.String, category, provider,
		status, statusMessage.String, authType, baseURL.String, credentialsEncrypted.String,
		lastSyncAt, nextSyncAt, syncIntervalMinutes, syncError.String,
		configJSON, metadataJSON, statsJSON, createdAt, updatedAt, createdBy,
	)
	if err != nil {
		return nil, err
	}

	// Reconstruct SCM extension if it exists
	var scmExt *integration.SCMExtension
	if repositoryCount.Valid {
		var lastSync *time.Time
		if lastRepoSyncAt.Valid {
			lastSync = &lastRepoSyncAt.Time
		}

		intgID, _ := shared.IDFromString(id)
		scmExt = integration.ReconstructSCMExtension(
			intgID,
			scmOrganization.String,
			int(repositoryCount.Int32),
			webhookID.String,
			webhookSecret.String,
			webhookURL.String,
			defaultBranchPattern.String,
			autoImportRepos.Bool,
			importPrivateRepos.Bool,
			importArchivedRepos.Bool,
			[]string(includePatterns),
			[]string(excludePatterns),
			lastSync,
		)
	}

	return integration.NewIntegrationWithSCM(intg, scmExt), nil
}
