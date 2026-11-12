package postgres

// SCM app installations (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scmapp"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SCMAppInstallationRepository stores code-host app installations.
type SCMAppInstallationRepository struct {
	db *DB
}

var _ scmapp.Repository = (*SCMAppInstallationRepository)(nil)

// NewSCMAppInstallationRepository creates the repository.
func NewSCMAppInstallationRepository(db *DB) *SCMAppInstallationRepository {
	return &SCMAppInstallationRepository{db: db}
}

const scmAppColumns = `id, tenant_id, provider, installation_id, account_login, account_id, account_type,
	repository_selection, status, created_by, created_at, updated_at`

func scanSCMApp(row ciScanner) (scmapp.Installation, error) {
	var (
		i         scmapp.Installation
		id, tid   string
		createdBy sql.NullString
	)
	if err := row.Scan(&id, &tid, &i.Provider, &i.InstallationID, &i.AccountLogin, &i.AccountID, &i.AccountType,
		&i.RepositorySelection, &i.Status, &createdBy, &i.CreatedAt, &i.UpdatedAt); err != nil {
		return i, err
	}
	i.ID, _ = shared.IDFromString(id)
	i.TenantID, _ = shared.IDFromString(tid)
	i.CreatedBy = parseOptID(createdBy)
	return i, nil
}

// Create binds an installation to a tenant. The same tenant binding it again
// refreshes it and re-activates it; another tenant gets ErrBoundElsewhere.
func (r *SCMAppInstallationRepository) Create(ctx context.Context, inst *scmapp.Installation) error {
	row := r.db.QueryRowContext(ctx, `INSERT INTO scm_app_installations (id, tenant_id, provider, installation_id,
			account_login, account_id, account_type, repository_selection, status, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9)
		ON CONFLICT (provider, installation_id) DO UPDATE SET
			account_login = EXCLUDED.account_login, account_id = EXCLUDED.account_id,
			account_type = EXCLUDED.account_type, repository_selection = EXCLUDED.repository_selection,
			status = 'active', updated_at = NOW()
		WHERE scm_app_installations.tenant_id = EXCLUDED.tenant_id
		RETURNING `+scmAppColumns,
		inst.ID.String(), inst.TenantID.String(), inst.Provider, inst.InstallationID, inst.AccountLogin,
		inst.AccountID, inst.AccountType, inst.RepositorySelection, nullID(inst.CreatedBy))
	got, err := scanSCMApp(row)
	if errors.Is(err, sql.ErrNoRows) {
		// The conflict's WHERE did not match: another tenant holds it.
		return scmapp.ErrBoundElsewhere
	}
	if err != nil {
		return fmt.Errorf("bind SCM app installation: %w", err)
	}
	*inst = got
	return nil
}

// List returns the tenant's installations.
func (r *SCMAppInstallationRepository) List(ctx context.Context, tenantID shared.ID) ([]scmapp.Installation, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+scmAppColumns+` FROM scm_app_installations
		WHERE tenant_id = $1 ORDER BY provider, lower(account_login) LIMIT 500`, tenantID.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []scmapp.Installation{}
	for rows.Next() {
		i, err := scanSCMApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// Get returns one of the tenant's installations.
func (r *SCMAppInstallationRepository) Get(ctx context.Context, tenantID, id shared.ID) (*scmapp.Installation, error) {
	i, err := scanSCMApp(r.db.QueryRowContext(ctx, `SELECT `+scmAppColumns+` FROM scm_app_installations
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, scmapp.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// ActiveForAccount returns the tenant's active installation on an account.
func (r *SCMAppInstallationRepository) ActiveForAccount(ctx context.Context, tenantID shared.ID, provider, accountLogin string) (*scmapp.Installation, error) {
	i, err := scanSCMApp(r.db.QueryRowContext(ctx, `SELECT `+scmAppColumns+` FROM scm_app_installations
		WHERE tenant_id = $1 AND provider = $2 AND lower(account_login) = lower($3) AND status = 'active'
		ORDER BY updated_at DESC LIMIT 1`, tenantID.String(), provider, accountLogin))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, scmapp.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// Delete unbinds one of the tenant's installations.
func (r *SCMAppInstallationRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM scm_app_installations WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String())
	if err != nil {
		return err
	}
	return requireOneRow(res, scmapp.ErrNotFound)
}

// GetByInstallationID finds an installation by the code host's id (webhook).
func (r *SCMAppInstallationRepository) GetByInstallationID(ctx context.Context, provider string, installationID int64) (*scmapp.Installation, error) {
	i, err := scanSCMApp(r.db.QueryRowContext(ctx, `SELECT `+scmAppColumns+` FROM scm_app_installations
		WHERE provider = $1 AND installation_id = $2`, provider, installationID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, scmapp.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// SetStatusByInstallationID records a status the code host reported.
func (r *SCMAppInstallationRepository) SetStatusByInstallationID(ctx context.Context, provider string, installationID int64, status string) (int64, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE scm_app_installations SET status = $3, updated_at = NOW()
		WHERE provider = $1 AND installation_id = $2 AND status <> $3`, provider, installationID, status)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------------------------------------------------------------- gitlab ---

var _ scmapp.GitLabRepository = (*SCMAppInstallationRepository)(nil)

const scmGitLabColumns = `id, tenant_id, host, group_path, group_id, token_encrypted, token_user_id, token_expires_at,
	status, created_by, created_at, updated_at`

func scanGitLabConnection(row ciScanner) (scmapp.GitLabConnection, error) {
	var (
		c         scmapp.GitLabConnection
		id, tid   string
		expires   sql.NullTime
		createdBy sql.NullString
	)
	if err := row.Scan(&id, &tid, &c.Host, &c.GroupPath, &c.GroupID, &c.TokenEncrypted, &c.TokenUserID, &expires,
		&c.Status, &createdBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return c, err
	}
	c.ID, _ = shared.IDFromString(id)
	c.TenantID, _ = shared.IDFromString(tid)
	c.TokenExpiresAt = optTime(expires)
	c.CreatedBy = parseOptID(createdBy)
	return c, nil
}

// CreateGitLab stores a connection; the same group again replaces its token.
func (r *SCMAppInstallationRepository) CreateGitLab(ctx context.Context, c *scmapp.GitLabConnection) error {
	got, err := scanGitLabConnection(r.db.QueryRowContext(ctx, `INSERT INTO scm_gitlab_connections (id, tenant_id, host,
			group_path, group_id, token_encrypted, token_user_id, token_expires_at, status, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9)
		ON CONFLICT (tenant_id, host, group_id) DO UPDATE SET group_path = EXCLUDED.group_path,
			token_encrypted = EXCLUDED.token_encrypted, token_user_id = EXCLUDED.token_user_id,
			token_expires_at = EXCLUDED.token_expires_at, status = 'active', updated_at = NOW()
		RETURNING `+scmGitLabColumns,
		c.ID.String(), c.TenantID.String(), c.Host, c.GroupPath, c.GroupID, c.TokenEncrypted, c.TokenUserID,
		c.TokenExpiresAt, nullID(c.CreatedBy)))
	if err != nil {
		return fmt.Errorf("store GitLab connection: %w", err)
	}
	*c = got
	return nil
}

// ListGitLab returns the tenant's connections.
func (r *SCMAppInstallationRepository) ListGitLab(ctx context.Context, tenantID shared.ID) ([]scmapp.GitLabConnection, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+scmGitLabColumns+` FROM scm_gitlab_connections
		WHERE tenant_id = $1 ORDER BY host, group_path LIMIT 500`, tenantID.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []scmapp.GitLabConnection{}
	for rows.Next() {
		c, err := scanGitLabConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteGitLab removes one of the tenant's connections and returns it.
func (r *SCMAppInstallationRepository) DeleteGitLab(ctx context.Context, tenantID, id shared.ID) (*scmapp.GitLabConnection, error) {
	c, err := scanGitLabConnection(r.db.QueryRowContext(ctx, `DELETE FROM scm_gitlab_connections
		WHERE tenant_id = $1 AND id = $2 RETURNING `+scmGitLabColumns, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, scmapp.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// GitLabForProject returns the tenant's active connection whose group holds
// the project, the deepest group first.
func (r *SCMAppInstallationRepository) GitLabForProject(ctx context.Context, tenantID shared.ID, host, projectPath string) (*scmapp.GitLabConnection, error) {
	c, err := scanGitLabConnection(r.db.QueryRowContext(ctx, `SELECT `+scmGitLabColumns+` FROM scm_gitlab_connections
		WHERE tenant_id = $1 AND lower(host) = lower($2) AND status = 'active'
		  AND lower($3) LIKE replace(replace(replace(lower(group_path), '\', '\\'), '%', '\%'), '_', '\_') || '/%'
		ORDER BY length(group_path) DESC LIMIT 1`, tenantID.String(), host, projectPath))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, scmapp.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}
