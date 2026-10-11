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
