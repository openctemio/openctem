package postgres

// Lifecycle schemes and their versions (docs/rfcs/RFC-110-tenant-lifecycles.md).
// Every statement is tenant-scoped. The database keeps a published version
// immutable and allows one draft per scheme and one default scheme per kind.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/findinglifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// LifecycleSchemeRepository implements findinglifecycle.SchemeRepository.
type LifecycleSchemeRepository struct {
	db *DB
}

// NewLifecycleSchemeRepository returns the repository.
func NewLifecycleSchemeRepository(db *DB) *LifecycleSchemeRepository {
	return &LifecycleSchemeRepository{db: db}
}

var _ findinglifecycle.SchemeRepository = (*LifecycleSchemeRepository)(nil)

const lifecycleSchemeColumns = `id, tenant_id, object_kind, key, name, description, priority, context,
	published_version_id, archived_at, created_at, created_by, updated_at, updated_by`

const lifecycleVersionColumns = `id, tenant_id, scheme_id, version, state, spec, spec_hash, note,
	created_at, created_by, published_at, published_by`

func encodeContext(c []findinglifecycle.Condition) (any, error) {
	if len(c) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("encode lifecycle context: %w", err)
	}
	return raw, nil
}

// CreateScheme stores a new scheme.
func (r *LifecycleSchemeRepository) CreateScheme(ctx context.Context, s *findinglifecycle.Scheme) error {
	ctxJSON, err := encodeContext(s.Context())
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO lifecycle_schemes (id, tenant_id, object_kind, key, name, description, priority, context,
			created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		s.ID().String(), s.TenantID().String(), string(s.Kind()), s.Key(), s.Name(), s.Description(), s.Priority(),
		ctxJSON, s.CreatedAt(), nullID(s.CreatedBy()), s.UpdatedAt(), nullID(s.UpdatedBy()))
	return schemeWriteError(err, "create lifecycle")
}

// UpdateScheme writes a scheme's name, description, priority, context and
// archive state.
func (r *LifecycleSchemeRepository) UpdateScheme(ctx context.Context, s *findinglifecycle.Scheme) error {
	ctxJSON, err := encodeContext(s.Context())
	if err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE lifecycle_schemes
		SET name = $3, description = $4, priority = $5, context = $6, archived_at = $7, updated_at = $8, updated_by = $9
		WHERE tenant_id = $1 AND id = $2`,
		s.TenantID().String(), s.ID().String(), s.Name(), s.Description(), s.Priority(), ctxJSON,
		s.ArchivedAt(), s.UpdatedAt(), nullID(s.UpdatedBy()))
	if err := schemeWriteError(err, "update lifecycle"); err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return findinglifecycle.ErrSchemeNotFound
	}
	return nil
}

func schemeWriteError(err error, what string) error {
	if err == nil {
		return nil
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		if pqErr.Constraint == "uq_lifecycle_schemes_default" {
			return findinglifecycle.ErrDefaultExists
		}
		return findinglifecycle.ErrSchemeKeyTaken
	}
	return fmt.Errorf("%s: %w", what, err)
}

// GetScheme returns one of the tenant's schemes.
func (r *LifecycleSchemeRepository) GetScheme(ctx context.Context, tenantID, id shared.ID) (*findinglifecycle.Scheme, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+lifecycleSchemeColumns+`
		FROM lifecycle_schemes WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
	s, err := scanLifecycleScheme(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, findinglifecycle.ErrSchemeNotFound
	}
	return s, err
}

// ListSchemes returns the tenant's schemes of a kind: the default first,
// then the context schemes by priority.
func (r *LifecycleSchemeRepository) ListSchemes(ctx context.Context, tenantID shared.ID, kind findinglifecycle.ObjectKind, includeArchived bool) ([]*findinglifecycle.Scheme, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+lifecycleSchemeColumns+`
		FROM lifecycle_schemes
		WHERE tenant_id = $1 AND object_kind = $2 AND ($3 OR archived_at IS NULL)
		ORDER BY (context IS NOT NULL), priority, name, id
		LIMIT 100`, tenantID.String(), string(kind), includeArchived)
	if err != nil {
		return nil, fmt.Errorf("list lifecycles: %w", err)
	}
	defer rows.Close()
	out := make([]*findinglifecycle.Scheme, 0)
	for rows.Next() {
		s, err := scanLifecycleScheme(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate lifecycles: %w", err)
	}
	return out, nil
}

// CountLive counts the tenant's schemes of kind that are not archived.
func (r *LifecycleSchemeRepository) CountLive(ctx context.Context, tenantID shared.ID, kind findinglifecycle.ObjectKind) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM lifecycle_schemes WHERE tenant_id = $1 AND object_kind = $2 AND archived_at IS NULL`,
		tenantID.String(), string(kind)).Scan(&n); err != nil {
		return 0, fmt.Errorf("count lifecycles: %w", err)
	}
	return n, nil
}

// CreateVersion stores a new version (a draft).
func (r *LifecycleSchemeRepository) CreateVersion(ctx context.Context, v *findinglifecycle.Version) error {
	raw, hash, err := findinglifecycle.EncodeSpec(v.Spec)
	if err != nil {
		return err
	}
	v.SpecHash = hash
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO lifecycle_scheme_versions (id, tenant_id, scheme_id, version, state, spec, spec_hash, note, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		v.ID.String(), v.TenantID.String(), v.SchemeID.String(), v.Number, string(v.State), raw, hash, v.Note,
		v.CreatedAt, nullID(v.CreatedBy))
	if err != nil {
		if isUniqueViolation(err) {
			return findinglifecycle.ErrDraftExists
		}
		return fmt.Errorf("create lifecycle version: %w", err)
	}
	return nil
}

// UpdateDraft replaces a draft's spec when nobody changed it since it was read.
func (r *LifecycleSchemeRepository) UpdateDraft(ctx context.Context, v *findinglifecycle.Version, expectedHash string) error {
	raw, hash, err := findinglifecycle.EncodeSpec(v.Spec)
	if err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE lifecycle_scheme_versions SET spec = $4, spec_hash = $5, note = $6
		WHERE tenant_id = $1 AND scheme_id = $2 AND version = $3 AND state = 'draft' AND spec_hash = $7`,
		v.TenantID.String(), v.SchemeID.String(), v.Number, raw, hash, v.Note, expectedHash)
	if err != nil {
		return fmt.Errorf("update lifecycle draft: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		cur, err := r.GetVersion(ctx, v.TenantID, v.SchemeID, v.Number)
		if err != nil {
			return err
		}
		if cur.State != findinglifecycle.VersionDraft {
			return findinglifecycle.ErrNotDraft
		}
		return findinglifecycle.ErrStaleDraft
	}
	v.SpecHash = hash
	return nil
}

// GetVersion returns version number of one of the tenant's schemes.
func (r *LifecycleSchemeRepository) GetVersion(ctx context.Context, tenantID, schemeID shared.ID, number int) (*findinglifecycle.Version, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+lifecycleVersionColumns+`
		FROM lifecycle_scheme_versions WHERE tenant_id = $1 AND scheme_id = $2 AND version = $3`,
		tenantID.String(), schemeID.String(), number)
	v, err := scanLifecycleVersion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, findinglifecycle.ErrVersionNotFound
	}
	return v, err
}

// ListVersions returns a scheme's versions, newest first.
func (r *LifecycleSchemeRepository) ListVersions(ctx context.Context, tenantID, schemeID shared.ID) ([]*findinglifecycle.Version, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+lifecycleVersionColumns+`
		FROM lifecycle_scheme_versions WHERE tenant_id = $1 AND scheme_id = $2
		ORDER BY version DESC LIMIT 200`, tenantID.String(), schemeID.String())
	if err != nil {
		return nil, fmt.Errorf("list lifecycle versions: %w", err)
	}
	defer rows.Close()
	out := make([]*findinglifecycle.Version, 0)
	for rows.Next() {
		v, err := scanLifecycleVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate lifecycle versions: %w", err)
	}
	return out, nil
}

// NextVersionNumber is one above the scheme's highest version.
func (r *LifecycleSchemeRepository) NextVersionNumber(ctx context.Context, tenantID, schemeID shared.ID) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(max(version), 0) + 1 FROM lifecycle_scheme_versions WHERE tenant_id = $1 AND scheme_id = $2`,
		tenantID.String(), schemeID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("next lifecycle version: %w", err)
	}
	return n, nil
}

// Publish makes the draft v the scheme's published version in one
// transaction: the previous published version becomes superseded and the
// scheme points at v. The scheme row is locked first, so two publishes of
// one scheme run one after the other.
func (r *LifecycleSchemeRepository) Publish(ctx context.Context, v *findinglifecycle.Version, note string, actor *shared.ID, at time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin publish: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var archived sql.NullTime
	if err := tx.QueryRowContext(ctx, `
		SELECT archived_at FROM lifecycle_schemes WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		v.TenantID.String(), v.SchemeID.String()).Scan(&archived); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return findinglifecycle.ErrSchemeNotFound
		}
		return fmt.Errorf("lock lifecycle: %w", err)
	}
	if archived.Valid {
		return findinglifecycle.ErrSchemeArchived
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE lifecycle_scheme_versions SET state = 'superseded'
		WHERE tenant_id = $1 AND scheme_id = $2 AND state = 'published'`,
		v.TenantID.String(), v.SchemeID.String()); err != nil {
		return fmt.Errorf("supersede lifecycle version: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE lifecycle_scheme_versions
		SET state = 'published', published_at = $5, published_by = $6, note = $7
		WHERE tenant_id = $1 AND scheme_id = $2 AND id = $3 AND state = 'draft' AND spec_hash = $4`,
		v.TenantID.String(), v.SchemeID.String(), v.ID.String(), v.SpecHash, at, nullID(actor), note)
	if err != nil {
		return fmt.Errorf("publish lifecycle version: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return findinglifecycle.ErrStaleDraft
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE lifecycle_schemes SET published_version_id = $3, updated_at = $4, updated_by = $5
		WHERE tenant_id = $1 AND id = $2`,
		v.TenantID.String(), v.SchemeID.String(), v.ID.String(), at, nullID(actor)); err != nil {
		return fmt.Errorf("point lifecycle at version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit publish: %w", err)
	}
	v.State, v.PublishedAt, v.PublishedBy, v.Note = findinglifecycle.VersionPublished, &at, actor, note
	return nil
}

// Published returns the tenant's live schemes of kind with their published
// version, in selection order (context schemes by priority, then the
// default).
func (r *LifecycleSchemeRepository) Published(ctx context.Context, tenantID shared.ID, kind findinglifecycle.ObjectKind) ([]findinglifecycle.PublishedScheme, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.id, s.tenant_id, s.object_kind, s.key, s.name, s.description, s.priority, s.context,
		       s.published_version_id, s.archived_at, s.created_at, s.created_by, s.updated_at, s.updated_by,
		       v.id, v.tenant_id, v.scheme_id, v.version, v.state, v.spec, v.spec_hash, v.note,
		       v.created_at, v.created_by, v.published_at, v.published_by
		FROM lifecycle_schemes s
		JOIN lifecycle_scheme_versions v ON v.tenant_id = s.tenant_id AND v.id = s.published_version_id
		WHERE s.tenant_id = $1 AND s.object_kind = $2 AND s.archived_at IS NULL
		ORDER BY (s.context IS NULL), s.priority, s.id
		LIMIT $3`, tenantID.String(), string(kind), findinglifecycle.MaxSchemesPerKind)
	if err != nil {
		return nil, fmt.Errorf("list published lifecycles: %w", err)
	}
	defer rows.Close()
	out := make([]findinglifecycle.PublishedScheme, 0)
	for rows.Next() {
		s, v, err := scanSchemeAndVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, findinglifecycle.PublishedScheme{Scheme: s, Version: v})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate published lifecycles: %w", err)
	}
	return out, nil
}

// SubStatusPublished reports whether a live scheme's published version uses
// the sub-status.
func (r *LifecycleSchemeRepository) SubStatusPublished(ctx context.Context, tenantID, subStatusID shared.ID) (bool, error) {
	var used bool
	if err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM lifecycle_schemes s
			JOIN lifecycle_scheme_versions v ON v.tenant_id = s.tenant_id AND v.id = s.published_version_id
			WHERE s.tenant_id = $1 AND s.archived_at IS NULL AND v.spec->'sub_statuses' ? $2)`,
		tenantID.String(), subStatusID.String()).Scan(&used); err != nil {
		return false, fmt.Errorf("check sub-status use: %w", err)
	}
	return used, nil
}

func scanLifecycleScheme(row rowScanner) (*findinglifecycle.Scheme, error) {
	var d schemeRow
	if err := row.Scan(d.targets()...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("scan lifecycle: %w", err)
	}
	return d.scheme()
}

func scanLifecycleVersion(row rowScanner) (*findinglifecycle.Version, error) {
	var d versionRow
	if err := row.Scan(d.targets()...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("scan lifecycle version: %w", err)
	}
	return d.version()
}

func scanSchemeAndVersion(row rowScanner) (*findinglifecycle.Scheme, *findinglifecycle.Version, error) {
	var s schemeRow
	var v versionRow
	if err := row.Scan(append(s.targets(), v.targets()...)...); err != nil {
		return nil, nil, fmt.Errorf("scan published lifecycle: %w", err)
	}
	scheme, err := s.scheme()
	if err != nil {
		return nil, nil, err
	}
	version, err := v.version()
	if err != nil {
		return nil, nil, err
	}
	return scheme, version, nil
}

type schemeRow struct {
	id, tenant, kind, key, name, description string
	priority                                 int
	context                                  []byte
	published                                sql.NullString
	archivedAt                               sql.NullTime
	createdAt, updatedAt                     time.Time
	createdBy, updatedBy                     sql.NullString
}

func (d *schemeRow) targets() []any {
	return []any{&d.id, &d.tenant, &d.kind, &d.key, &d.name, &d.description, &d.priority, &d.context,
		&d.published, &d.archivedAt, &d.createdAt, &d.createdBy, &d.updatedAt, &d.updatedBy}
}

func (d *schemeRow) scheme() (*findinglifecycle.Scheme, error) {
	id, err := shared.IDFromString(d.id)
	if err != nil {
		return nil, fmt.Errorf("scan lifecycle id: %w", err)
	}
	tenant, err := shared.IDFromString(d.tenant)
	if err != nil {
		return nil, fmt.Errorf("scan lifecycle tenant: %w", err)
	}
	out := findinglifecycle.SchemeData{
		ID: id, TenantID: tenant, Kind: findinglifecycle.ObjectKind(d.kind), Key: d.key, Name: d.name,
		Description: d.description, Priority: d.priority, CreatedAt: d.createdAt, UpdatedAt: d.updatedAt,
		CreatedBy: optionalID(d.createdBy), UpdatedBy: optionalID(d.updatedBy), PublishedVersionID: optionalID(d.published),
	}
	if len(d.context) > 0 {
		if err := json.Unmarshal(d.context, &out.Context); err != nil {
			return nil, fmt.Errorf("scan lifecycle context: %w", err)
		}
	}
	if d.archivedAt.Valid {
		t := d.archivedAt.Time
		out.ArchivedAt = &t
	}
	return findinglifecycle.ReconstituteScheme(out), nil
}

type versionRow struct {
	id, tenant, scheme, state, hash, note string
	number                                int
	spec                                  []byte
	createdAt                             time.Time
	createdBy, publishedBy                sql.NullString
	publishedAt                           sql.NullTime
}

func (d *versionRow) targets() []any {
	return []any{&d.id, &d.tenant, &d.scheme, &d.number, &d.state, &d.spec, &d.hash, &d.note,
		&d.createdAt, &d.createdBy, &d.publishedAt, &d.publishedBy}
}

func (d *versionRow) version() (*findinglifecycle.Version, error) {
	id, err := shared.IDFromString(d.id)
	if err != nil {
		return nil, fmt.Errorf("scan lifecycle version id: %w", err)
	}
	tenant, err := shared.IDFromString(d.tenant)
	if err != nil {
		return nil, fmt.Errorf("scan lifecycle version tenant: %w", err)
	}
	scheme, err := shared.IDFromString(d.scheme)
	if err != nil {
		return nil, fmt.Errorf("scan lifecycle version scheme: %w", err)
	}
	spec, err := findinglifecycle.ParseSpec(d.spec)
	if err != nil {
		return nil, fmt.Errorf("scan lifecycle version spec: %w", err)
	}
	v := &findinglifecycle.Version{
		ID: id, TenantID: tenant, SchemeID: scheme, Number: d.number, State: findinglifecycle.VersionState(d.state),
		Spec: spec, SpecHash: d.hash, Note: d.note, CreatedAt: d.createdAt, CreatedBy: optionalID(d.createdBy),
		PublishedBy: optionalID(d.publishedBy),
	}
	if d.publishedAt.Valid {
		t := d.publishedAt.Time
		v.PublishedAt = &t
	}
	return v, nil
}
