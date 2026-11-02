package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/wordlist"
)

// TenantWordlistRepository stores organization wordlists (migration
// tenant_wordlists_and_content_pins). tenant_id is part of every predicate:
// a list of another organization is not found.
type TenantWordlistRepository struct {
	db *DB
}

// NewTenantWordlistRepository creates a TenantWordlistRepository.
func NewTenantWordlistRepository(db *DB) *TenantWordlistRepository {
	return &TenantWordlistRepository{db: db}
}

var _ wordlist.Repository = (*TenantWordlistRepository)(nil)

const tenantWordlistColumns = `id, tenant_id, name, description, purpose, enabled, version, lines, sha256, content,
	created_by, updated_by, created_at, updated_at`

func scanTenantWordlist(row interface{ Scan(...any) error }) (*wordlist.Wordlist, error) {
	var (
		w                    wordlist.Wordlist
		id, tenantID         string
		createdBy, updatedBy sql.NullString
	)
	if err := row.Scan(&id, &tenantID, &w.Name, &w.Description, &w.Purpose, &w.Enabled, &w.Version, &w.Lines,
		&w.SHA256, &w.Content, &createdBy, &updatedBy, &w.CreatedAt, &w.UpdatedAt); err != nil {
		return nil, err
	}
	w.ID, _ = shared.IDFromString(id)
	w.TenantID, _ = shared.IDFromString(tenantID)
	if createdBy.Valid {
		v, _ := shared.IDFromString(createdBy.String)
		w.CreatedBy = &v
	}
	if updatedBy.Valid {
		v, _ := shared.IDFromString(updatedBy.String)
		w.UpdatedBy = &v
	}
	return &w, nil
}

func (r *TenantWordlistRepository) query(ctx context.Context, q string, args ...any) ([]*wordlist.Wordlist, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list wordlists: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*wordlist.Wordlist, 0, wordlist.MaxLists)
	for rows.Next() {
		w, err := scanTenantWordlist(rows)
		if err != nil {
			return nil, fmt.Errorf("scan wordlist: %w", err)
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// List returns the organization's lists by name (at most MaxLists exist).
func (r *TenantWordlistRepository) List(ctx context.Context, tenantID shared.ID) ([]*wordlist.Wordlist, error) {
	return r.query(ctx, `SELECT `+tenantWordlistColumns+` FROM tenant_wordlists
		WHERE tenant_id = $1 ORDER BY name LIMIT $2`, tenantID.String(), wordlist.MaxLists)
}

// Enabled returns the organization's enabled lists of a purpose, oldest
// first, so a job's list keeps a stable order.
func (r *TenantWordlistRepository) Enabled(ctx context.Context, tenantID shared.ID, purpose string) ([]*wordlist.Wordlist, error) {
	return r.query(ctx, `SELECT `+tenantWordlistColumns+` FROM tenant_wordlists
		WHERE tenant_id = $1 AND purpose = $2 AND enabled
		ORDER BY created_at, id LIMIT $3`, tenantID.String(), purpose, wordlist.MaxLists)
}

// Get returns one list of the organization.
func (r *TenantWordlistRepository) Get(ctx context.Context, tenantID, id shared.ID) (*wordlist.Wordlist, error) {
	w, err := scanTenantWordlist(r.db.QueryRowContext(ctx, `SELECT `+tenantWordlistColumns+` FROM tenant_wordlists
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, wordlist.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get wordlist: %w", err)
	}
	return w, nil
}

// Create stores a list. The count check and the insert are one statement,
// so concurrent creates cannot pass MaxLists.
func (r *TenantWordlistRepository) Create(ctx context.Context, w *wordlist.Wordlist) error {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_wordlists (id, tenant_id, name, description, purpose, enabled, version, lines, sha256,
			content, created_by, updated_by, created_at, updated_at)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, $12, $12
		WHERE (SELECT count(*) FROM tenant_wordlists WHERE tenant_id = $2) < $13`,
		w.ID.String(), w.TenantID.String(), w.Name, w.Description, w.Purpose, w.Enabled, w.Version, w.Lines,
		w.SHA256, w.Content, nullableID(w.CreatedBy), w.CreatedAt, wordlist.MaxLists)
	if err != nil {
		if isUniqueViolation(err) {
			return wordlist.ErrNameTaken
		}
		return fmt.Errorf("create wordlist: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return wordlist.ErrTooMany
	}
	return nil
}

// Update stores a list's name, description, enabled flag, content and
// version.
func (r *TenantWordlistRepository) Update(ctx context.Context, w *wordlist.Wordlist) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE tenant_wordlists SET name = $3, description = $4, enabled = $5, version = $6, lines = $7,
			sha256 = $8, content = $9, updated_by = $10, updated_at = $11
		WHERE tenant_id = $1 AND id = $2`,
		w.TenantID.String(), w.ID.String(), w.Name, w.Description, w.Enabled, w.Version, w.Lines, w.SHA256,
		w.Content, nullableID(w.UpdatedBy), w.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return wordlist.ErrNameTaken
		}
		return fmt.Errorf("update wordlist: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return wordlist.ErrNotFound
	}
	return nil
}

// Delete removes one list of the organization.
func (r *TenantWordlistRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM tenant_wordlists WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("delete wordlist: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return wordlist.ErrNotFound
	}
	return nil
}
