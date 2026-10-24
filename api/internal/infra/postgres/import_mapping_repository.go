package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	appimportmapping "github.com/openctemio/openctem/api/internal/app/importmapping"
	"github.com/openctemio/openctem/api/pkg/domain/importmapping"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ImportMappingRepository stores import mappings and their versions
// (docs/rfcs/RFC-126-import-mappings.md). Every query is tenant-scoped.
type ImportMappingRepository struct {
	db *DB
}

// NewImportMappingRepository creates the repository.
func NewImportMappingRepository(db *DB) *ImportMappingRepository {
	return &ImportMappingRepository{db: db}
}

var _ appimportmapping.Repository = (*ImportMappingRepository)(nil)

// ErrImportMappingNotFound is returned for a missing mapping or version.
var ErrImportMappingNotFound = fmt.Errorf("%w: import mapping not found", shared.ErrNotFound)

var errImportMappingName = fmt.Errorf("%w: an import mapping with this name already exists", shared.ErrConflict)

const imCols = `id, tenant_id, name, description, source, latest_version, created_by, created_at, updated_at`

const imvSummaryCols = `mapping_id, tenant_id, version, digest, identity, identity_changed, note, created_by, created_at`

// Create inserts a mapping and its first version in one transaction.
func (r *ImportMappingRepository) Create(ctx context.Context, m *importmapping.Mapping, v *importmapping.Version) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO import_mappings (`+imCols+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			m.ID.String(), m.TenantID.String(), m.Name, m.Description, m.Source, m.LatestVersion,
			nullID(m.CreatedBy), m.CreatedAt, m.UpdatedAt)
		if err != nil {
			if isUniqueViolation(err) {
				return errImportMappingName
			}
			return fmt.Errorf("create import mapping: %w", err)
		}
		return insertImportMappingVersion(ctx, tx, v)
	})
}

func insertImportMappingVersion(ctx context.Context, tx *sql.Tx, v *importmapping.Version) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO import_mapping_versions
		(mapping_id, tenant_id, version, document, digest, identity, identity_changed, note, created_by, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		v.MappingID.String(), v.TenantID.String(), v.Version, []byte(v.Document), v.Digest, pq.Array(v.Identity),
		v.IdentityChanged, v.Note, nullID(v.CreatedBy), v.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: the mapping changed meanwhile; reload it", shared.ErrConflict)
		}
		return fmt.Errorf("insert import mapping version: %w", err)
	}
	return nil
}

func scanImportMapping(s rowScanner) (*importmapping.Mapping, error) {
	var (
		m         importmapping.Mapping
		id, tid   string
		createdBy sql.NullString
	)
	if err := s.Scan(&id, &tid, &m.Name, &m.Description, &m.Source, &m.LatestVersion, &createdBy, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return nil, err
	}
	m.ID, _ = shared.IDFromString(id)
	m.TenantID, _ = shared.IDFromString(tid)
	m.CreatedBy = optionalID(createdBy)
	return &m, nil
}

func scanImportMappingVersion(s rowScanner, withDocument bool) (*importmapping.Version, error) {
	var (
		v         importmapping.Version
		mid, tid  string
		identity  pq.StringArray
		createdBy sql.NullString
		doc       []byte
		createdAt time.Time
	)
	dest := []any{&mid, &tid, &v.Version, &v.Digest, &identity, &v.IdentityChanged, &v.Note, &createdBy, &createdAt}
	if withDocument {
		dest = append(dest, &doc)
	}
	if err := s.Scan(dest...); err != nil {
		return nil, err
	}
	v.MappingID, _ = shared.IDFromString(mid)
	v.TenantID, _ = shared.IDFromString(tid)
	v.Identity = []string(identity)
	if v.Identity == nil {
		v.Identity = []string{}
	}
	v.CreatedBy = optionalID(createdBy)
	v.CreatedAt = createdAt
	if withDocument {
		v.Document = doc
	}
	return &v, nil
}

// List returns the organization's mappings by name.
func (r *ImportMappingRepository) List(ctx context.Context, tenantID shared.ID) ([]*importmapping.Mapping, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+imCols+` FROM import_mappings WHERE tenant_id = $1 ORDER BY name LIMIT $2`,
		tenantID.String(), importmapping.MaxPerTenant)
	if err != nil {
		return nil, fmt.Errorf("list import mappings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []*importmapping.Mapping{}
	for rows.Next() {
		m, err := scanImportMapping(rows)
		if err != nil {
			return nil, fmt.Errorf("scan import mapping: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Count returns how many mappings the organization has.
func (r *ImportMappingRepository) Count(ctx context.Context, tenantID shared.ID) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM import_mappings WHERE tenant_id = $1`, tenantID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count import mappings: %w", err)
	}
	return n, nil
}

func (r *ImportMappingRepository) getOne(ctx context.Context, where string, args ...any) (*importmapping.Mapping, error) {
	m, err := scanImportMapping(r.db.QueryRowContext(ctx, `SELECT `+imCols+` FROM import_mappings WHERE `+where, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrImportMappingNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get import mapping: %w", err)
	}
	return m, nil
}

// Get returns one mapping of the organization.
func (r *ImportMappingRepository) Get(ctx context.Context, tenantID, id shared.ID) (*importmapping.Mapping, error) {
	return r.getOne(ctx, `tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
}

// GetByName returns the organization's mapping of that name.
func (r *ImportMappingRepository) GetByName(ctx context.Context, tenantID shared.ID, name string) (*importmapping.Mapping, error) {
	return r.getOne(ctx, `tenant_id = $1 AND name = $2`, tenantID.String(), name)
}

// GetVersion returns one version with its document; version 0 is the
// latest.
func (r *ImportMappingRepository) GetVersion(ctx context.Context, tenantID, id shared.ID, version int) (*importmapping.Version, error) {
	q := `SELECT v.mapping_id, v.tenant_id, v.version, v.digest, v.identity, v.identity_changed, v.note, v.created_by, v.created_at, v.document
		FROM import_mapping_versions v
		JOIN import_mappings m ON m.tenant_id = v.tenant_id AND m.id = v.mapping_id
		WHERE v.tenant_id = $1 AND v.mapping_id = $2 AND v.version = `
	args := []any{tenantID.String(), id.String()}
	if version > 0 {
		q += `$3`
		args = append(args, version)
	} else {
		q += `m.latest_version`
	}
	v, err := scanImportMappingVersion(r.db.QueryRowContext(ctx, q, args...), true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrImportMappingNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get import mapping version: %w", err)
	}
	return v, nil
}

// ListVersions returns the versions, newest first, without documents.
func (r *ImportMappingRepository) ListVersions(ctx context.Context, tenantID, id shared.ID) ([]*importmapping.Version, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+imvSummaryCols+` FROM import_mapping_versions
		WHERE tenant_id = $1 AND mapping_id = $2 ORDER BY version DESC LIMIT $3`,
		tenantID.String(), id.String(), importmapping.MaxVersions)
	if err != nil {
		return nil, fmt.Errorf("list import mapping versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []*importmapping.Version{}
	for rows.Next() {
		v, err := scanImportMappingVersion(rows, false)
		if err != nil {
			return nil, fmt.Errorf("scan import mapping version: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// AddVersion stores v when the mapping's latest version is still
// expectedLatest: the bump and the insert are one transaction, so two
// concurrent saves cannot both become the same version.
func (r *ImportMappingRepository) AddVersion(ctx context.Context, v *importmapping.Version, expectedLatest int) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE import_mappings SET latest_version = $4, updated_at = $5
			WHERE tenant_id = $1 AND id = $2 AND latest_version = $3`,
			v.TenantID.String(), v.MappingID.String(), expectedLatest, v.Version, v.CreatedAt)
		if err != nil {
			return fmt.Errorf("bump import mapping version: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("%w: the mapping changed meanwhile; reload it", shared.ErrConflict)
		}
		return insertImportMappingVersion(ctx, tx, v)
	})
}

// Update sets the name and description.
func (r *ImportMappingRepository) Update(ctx context.Context, tenantID, id shared.ID, name, description string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE import_mappings SET name = $3, description = $4, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String(), name, description)
	if err != nil {
		if isUniqueViolation(err) {
			return errImportMappingName
		}
		return fmt.Errorf("update import mapping: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrImportMappingNotFound
	}
	return nil
}

// Delete removes a mapping and, by cascade, its versions.
func (r *ImportMappingRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM import_mappings WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("delete import mapping: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrImportMappingNotFound
	}
	return nil
}
