package postgres

// Issue-definition catalog repositories.
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-044-issue-definitions-and-findings.md
//
// Definitions live in the vulnerabilities table (extended in place). Tenant
// isolation is enforced twice: every statement here carries the caller's
// tenant, and the schema refuses any row that would point a tenant at another
// tenant's definition (migration 000823).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/definition"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// definitionVisible is the read predicate on vulnerabilities for tenant $1:
// global definitions and the tenant's own.
const definitionVisible = "(tenant_id IS NULL OR tenant_id = $1)"

// definitionColumns lists, in scanDefinition's order, the definition columns
// of vulnerabilities qualified with prefix ("" or "d.").
func definitionColumns(prefix string) string {
	return strings.NewReplacer("@", prefix).Replace(`@id, @tenant_id, @kind, @namespace, @external_id, @title,
		COALESCE(@description, ''), COALESCE(@remediation, ''), @severity, @lifecycle,
		@merged_into, @origin, @nicknames, @created_at, @updated_at`)
}

// DefinitionRepository implements definition.Repository.
type DefinitionRepository struct {
	db *DB
}

// NewDefinitionRepository creates a DefinitionRepository.
func NewDefinitionRepository(db *DB) *DefinitionRepository {
	return &DefinitionRepository{db: db}
}

var _ definition.Repository = (*DefinitionRepository)(nil)

func requireTenant(tenant shared.ID) error {
	if tenant.IsZero() {
		return fmt.Errorf("%w: no tenant", definition.ErrInvalid)
	}
	return nil
}

// GetByID returns a definition visible to tenant.
func (r *DefinitionRepository) GetByID(ctx context.Context, tenant, id shared.ID) (*definition.Definition, error) {
	if err := requireTenant(tenant); err != nil {
		return nil, err
	}
	row := r.db.QueryRowContext(ctx,
		`SELECT `+definitionColumns("")+` FROM vulnerabilities WHERE `+definitionVisible+` AND id = $2`,
		tenant.String(), id.String())
	return scanDefinition(row.Scan)
}

// Resolve returns the definition an identifier names: a global identifier
// first, then the tenant's own.
func (r *DefinitionRepository) Resolve(ctx context.Context, tenant shared.ID, namespace, externalID string) (*definition.Definition, error) {
	if err := requireTenant(tenant); err != nil {
		return nil, err
	}
	id, err := definition.NormalizeID(namespace, externalID)
	if err != nil {
		return nil, err
	}
	row := r.db.QueryRowContext(ctx, `
		SELECT `+definitionColumns("d.")+`
		FROM definition_identifiers i
		JOIN vulnerabilities d ON d.id = i.definition_id AND d.scope_tenant_id = i.scope_tenant_id
		WHERE i.namespace = $2 AND i.external_id = $3
		  AND (i.tenant_id IS NULL OR i.tenant_id = $1)
		ORDER BY (i.tenant_id IS NULL) DESC
		LIMIT 1`, tenant.String(), namespace, id)
	return scanDefinition(row.Scan)
}

// scopeOf returns the scope of a definition visible to tenant, else
// definition.ErrNotFound.
func (r *DefinitionRepository) scopeOf(ctx context.Context, q queryer, tenant, id shared.ID) (definition.Scope, error) {
	var owner sql.NullString
	err := q.QueryRowContext(ctx,
		`SELECT tenant_id FROM vulnerabilities WHERE `+definitionVisible+` AND id = $2`,
		tenant.String(), id.String()).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return definition.Scope{}, definition.ErrNotFound
	}
	if err != nil {
		return definition.Scope{}, fmt.Errorf("read definition scope: %w", err)
	}
	return scopeFromNull(owner)
}

// writableScope returns tenant's scope when the definition is tenant's own;
// a visible global definition is ErrNotWritable, anything else ErrNotFound.
func (r *DefinitionRepository) writableScope(ctx context.Context, tenant, id shared.ID) (definition.Scope, error) {
	scope, err := r.scopeOf(ctx, r.db, tenant, id)
	if err != nil {
		return definition.Scope{}, err
	}
	if !scope.WritableBy(tenant) {
		return definition.Scope{}, definition.ErrNotWritable
	}
	return scope, nil
}

// ListIdentifiers returns the identifiers of a definition visible to tenant,
// the primary first.
func (r *DefinitionRepository) ListIdentifiers(ctx context.Context, tenant, definitionID shared.ID) ([]definition.Identifier, error) {
	if err := requireTenant(tenant); err != nil {
		return nil, err
	}
	if _, err := r.scopeOf(ctx, r.db, tenant, definitionID); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT namespace, external_id, tenant_id, definition_id, is_primary, asserted_by
		FROM definition_identifiers
		WHERE `+definitionVisible+` AND definition_id = $2
		ORDER BY is_primary DESC, namespace, external_id`, tenant.String(), definitionID.String())
	if err != nil {
		return nil, fmt.Errorf("list definition identifiers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []definition.Identifier
	for rows.Next() {
		var (
			ident  definition.Identifier
			owner  sql.NullString
			defID  string
			source string
		)
		if err := rows.Scan(&ident.Namespace, &ident.ExternalID, &owner, &defID, &ident.IsPrimary, &source); err != nil {
			return nil, fmt.Errorf("scan definition identifier: %w", err)
		}
		if ident.Scope, err = scopeFromNull(owner); err != nil {
			return nil, err
		}
		if ident.DefinitionID, err = shared.IDFromString(defID); err != nil {
			return nil, fmt.Errorf("parse definition id: %w", err)
		}
		ident.AssertedBy = definition.Source(source)
		out = append(out, ident)
	}
	return out, rows.Err()
}

// ListRelations returns the edges from or to a definition visible to tenant:
// global edges and the tenant's own.
func (r *DefinitionRepository) ListRelations(ctx context.Context, tenant, definitionID shared.ID) ([]definition.Relation, error) {
	if err := requireTenant(tenant); err != nil {
		return nil, err
	}
	if _, err := r.scopeOf(ctx, r.db, tenant, definitionID); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, tenant_id, from_id, from_scope, to_id, to_scope, relation, asserted_by
		FROM definition_relations
		WHERE `+definitionVisible+` AND (from_id = $2 OR to_id = $2)
		ORDER BY relation, created_at`, tenant.String(), definitionID.String())
	if err != nil {
		return nil, fmt.Errorf("list definition relations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []definition.Relation
	for rows.Next() {
		var (
			rel                              definition.Relation
			owner                            sql.NullString
			id, from, fromScope, to, toScope string
			typ, source                      string
		)
		if err := rows.Scan(&id, &owner, &from, &fromScope, &to, &toScope, &typ, &source); err != nil {
			return nil, fmt.Errorf("scan definition relation: %w", err)
		}
		if rel.Scope, err = scopeFromNull(owner); err != nil {
			return nil, err
		}
		if rel.FromScope, err = definition.ScopeFromKey(fromScope); err != nil {
			return nil, fmt.Errorf("parse relation scope: %w", err)
		}
		if rel.ToScope, err = definition.ScopeFromKey(toScope); err != nil {
			return nil, fmt.Errorf("parse relation scope: %w", err)
		}
		if rel.ID, err = shared.IDFromString(id); err != nil {
			return nil, fmt.Errorf("parse relation id: %w", err)
		}
		if rel.FromID, err = shared.IDFromString(from); err != nil {
			return nil, fmt.Errorf("parse relation id: %w", err)
		}
		if rel.ToID, err = shared.IDFromString(to); err != nil {
			return nil, fmt.Errorf("parse relation id: %w", err)
		}
		rel.Type, rel.AssertedBy = definition.RelationType(typ), definition.Source(source)
		out = append(out, rel)
	}
	return out, rows.Err()
}

// ListTaxonomy returns the taxonomy links of a definition visible to tenant.
func (r *DefinitionRepository) ListTaxonomy(ctx context.Context, tenant, definitionID shared.ID) ([]definition.TaxonomyLink, error) {
	if err := requireTenant(tenant); err != nil {
		return nil, err
	}
	if _, err := r.scopeOf(ctx, r.db, tenant, definitionID); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT definition_id, tenant_id, namespace, external_id, asserted_by
		FROM definition_taxonomy
		WHERE `+definitionVisible+` AND definition_id = $2
		ORDER BY namespace, external_id`, tenant.String(), definitionID.String())
	if err != nil {
		return nil, fmt.Errorf("list definition taxonomy: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []definition.TaxonomyLink
	for rows.Next() {
		var (
			link          definition.TaxonomyLink
			defID, source string
			owner         sql.NullString
		)
		if err := rows.Scan(&defID, &owner, &link.Namespace, &link.ExternalID, &source); err != nil {
			return nil, fmt.Errorf("scan taxonomy link: %w", err)
		}
		if link.Scope, err = scopeFromNull(owner); err != nil {
			return nil, err
		}
		if link.DefinitionID, err = shared.IDFromString(defID); err != nil {
			return nil, fmt.Errorf("parse definition id: %w", err)
		}
		link.AssertedBy = definition.Source(source)
		out = append(out, link)
	}
	return out, rows.Err()
}

// CreateTenantDefinition stores one of tenant's definitions. Its primary
// identifier is written by the vulnerabilities_primary_identifier trigger.
func (r *DefinitionRepository) CreateTenantDefinition(ctx context.Context, tenant shared.ID, d *definition.Definition) error {
	if err := requireTenant(tenant); err != nil {
		return err
	}
	if d == nil || !d.Scope().WritableBy(tenant) || !d.Origin().IsTenantSource() {
		return definition.ErrNotWritable
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, tenant_id, kind, namespace, external_id, title, description,
			remediation, severity, lifecycle, origin, nicknames, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		d.ID().String(), tenant.String(), string(d.Kind()), d.Namespace(), d.ExternalID(), d.Title(),
		nullString(d.Description()), nullString(d.Remediation()), d.Severity(), string(d.Lifecycle()),
		string(d.Origin()), pq.Array(nonNilStrings(d.Nicknames())), d.CreatedAt(), d.UpdatedAt())
	if err != nil {
		if isUniqueViolation(err) {
			return definition.ErrAlreadyExists
		}
		return fmt.Errorf("create tenant definition: %w", err)
	}
	return nil
}

// EnsureGlobalStub returns the global definition an advisory id names,
// creating an identity-only stub when none exists. An existing definition,
// global identifier or alias is never changed.
func (r *DefinitionRepository) EnsureGlobalStub(ctx context.Context, d *definition.Definition) (shared.ID, error) {
	if d == nil || !d.Scope().IsGlobal() || d.Origin() != definition.SourceReport {
		return shared.ID{}, definition.ErrNotWritable
	}
	ns, ok := definition.Lookup(d.Namespace())
	if !ok || !ns.Advisory || !ns.GlobalCapable {
		return shared.ID{}, fmt.Errorf("%w: no global stub in namespace %s", definition.ErrInvalid, d.Namespace())
	}

	// An alias a feed already asserted resolves to its definition.
	if id, found, err := r.globalByIdentifier(ctx, d.Namespace(), d.ExternalID()); err != nil || found {
		return id, err
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, kind, namespace, external_id, cve_id, title, severity, lifecycle,
			origin, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'unknown', 'published', 'report', $7, $7)
		ON CONFLICT DO NOTHING`,
		d.ID().String(), string(d.Kind()), d.Namespace(), d.ExternalID(), nullString(d.CVEID()), d.Title(), d.CreatedAt())
	if err != nil {
		return shared.ID{}, fmt.Errorf("create global stub: %w", err)
	}
	id, found, err := r.globalByIdentifier(ctx, d.Namespace(), d.ExternalID())
	if err != nil {
		return shared.ID{}, err
	}
	if !found {
		// The insert lost a race to a definition with the same identity
		// whose identifier is not written yet: read the definition itself.
		var s string
		err := r.db.QueryRowContext(ctx, `SELECT id FROM vulnerabilities
			WHERE tenant_id IS NULL AND namespace = $1 AND external_id = $2`, d.Namespace(), d.ExternalID()).Scan(&s)
		if err != nil {
			return shared.ID{}, fmt.Errorf("read global stub: %w", err)
		}
		return shared.IDFromString(s)
	}
	return id, nil
}

func (r *DefinitionRepository) globalByIdentifier(ctx context.Context, namespace, externalID string) (shared.ID, bool, error) {
	var s string
	err := r.db.QueryRowContext(ctx, `
		SELECT definition_id FROM definition_identifiers
		WHERE tenant_id IS NULL AND namespace = $1 AND external_id = $2`, namespace, externalID).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return shared.ID{}, false, nil
	}
	if err != nil {
		return shared.ID{}, false, fmt.Errorf("resolve global identifier: %w", err)
	}
	id, err := shared.IDFromString(s)
	return id, err == nil, err
}

// AddTenantIdentifier adds an alias to one of tenant's definitions.
func (r *DefinitionRepository) AddTenantIdentifier(ctx context.Context, tenant shared.ID, ident definition.Identifier) error {
	if err := requireTenant(tenant); err != nil {
		return err
	}
	scope, err := r.writableScope(ctx, tenant, ident.DefinitionID)
	if err != nil {
		return err
	}
	if ident.IsPrimary {
		return fmt.Errorf("%w: a definition's primary identifier is its own id", definition.ErrInvalid)
	}
	if err := ident.Validate(scope); err != nil {
		return err
	}
	extID, err := definition.NormalizeID(ident.Namespace, ident.ExternalID)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO definition_identifiers (namespace, external_id, tenant_id, scope_tenant_id, definition_id, is_primary, asserted_by)
		VALUES ($1, $2, $3, $3, $4, FALSE, $5)`,
		ident.Namespace, extID, tenant.String(), ident.DefinitionID.String(), string(ident.AssertedBy))
	if err != nil {
		if isUniqueViolation(err) {
			return definition.ErrAlreadyExists
		}
		return fmt.Errorf("add tenant identifier: %w", err)
	}
	return nil
}

// AddTenantRelation adds an edge in tenant's scope. Both ends must be visible
// to tenant; their scopes are read from the catalog, not taken from rel.
func (r *DefinitionRepository) AddTenantRelation(ctx context.Context, tenant shared.ID, rel definition.Relation) error {
	if err := requireTenant(tenant); err != nil {
		return err
	}
	var err error
	if rel.FromScope, err = r.scopeOf(ctx, r.db, tenant, rel.FromID); err != nil {
		return err
	}
	if rel.ToScope, err = r.scopeOf(ctx, r.db, tenant, rel.ToID); err != nil {
		return err
	}
	rel.Scope = definition.TenantScope(tenant)
	if err := rel.Validate(); err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO definition_relations (tenant_id, scope_tenant_id, from_id, from_scope, to_id, to_scope, relation, asserted_by)
		VALUES ($1, $1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (scope_tenant_id, from_id, to_id, relation) DO NOTHING`,
		tenant.String(), rel.FromID.String(), rel.FromScope.Key(), rel.ToID.String(), rel.ToScope.Key(),
		string(rel.Type), string(rel.AssertedBy))
	if err != nil {
		return fmt.Errorf("add tenant relation: %w", err)
	}
	return nil
}

// AddTenantTaxonomy maps one of tenant's definitions to a taxonomy entry.
func (r *DefinitionRepository) AddTenantTaxonomy(ctx context.Context, tenant shared.ID, link definition.TaxonomyLink) error {
	if err := requireTenant(tenant); err != nil {
		return err
	}
	scope, err := r.writableScope(ctx, tenant, link.DefinitionID)
	if err != nil {
		return err
	}
	link.Scope = scope
	if err := link.Validate(scope); err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO definition_taxonomy (definition_id, tenant_id, scope_tenant_id, namespace, external_id, asserted_by)
		VALUES ($1, $2, $2, $3, $4, $5)
		ON CONFLICT (definition_id, namespace, external_id) DO NOTHING`,
		link.DefinitionID.String(), tenant.String(), link.Namespace, strings.TrimSpace(link.ExternalID), string(link.AssertedBy))
	if err != nil {
		return fmt.Errorf("add tenant taxonomy link: %w", err)
	}
	return nil
}

// FindingDefinitionRepository implements definition.FindingLinkRepository.
type FindingDefinitionRepository struct {
	db *DB
}

// NewFindingDefinitionRepository creates a FindingDefinitionRepository.
func NewFindingDefinitionRepository(db *DB) *FindingDefinitionRepository {
	return &FindingDefinitionRepository{db: db}
}

var _ definition.FindingLinkRepository = (*FindingDefinitionRepository)(nil)

// ListByFinding returns the links of one of tenant's findings, by ord.
func (r *FindingDefinitionRepository) ListByFinding(ctx context.Context, tenant, findingID shared.ID) ([]definition.FindingLink, error) {
	if err := requireTenant(tenant); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT definition_id, definition_scope, role, ord, asserted_by
		FROM finding_definitions
		WHERE tenant_id = $1 AND finding_id = $2
		ORDER BY ord`, tenant.String(), findingID.String())
	if err != nil {
		return nil, fmt.Errorf("list finding definitions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []definition.FindingLink
	for rows.Next() {
		var (
			defID, scope, role, source string
			ord                        int
		)
		if err := rows.Scan(&defID, &scope, &role, &ord, &source); err != nil {
			return nil, fmt.Errorf("scan finding definition: %w", err)
		}
		link := definition.FindingLink{FindingID: findingID, TenantID: tenant, Role: definition.Role(role),
			Ord: ord, AssertedBy: definition.LinkSource(source)}
		if link.DefinitionID, err = shared.IDFromString(defID); err != nil {
			return nil, fmt.Errorf("parse definition id: %w", err)
		}
		if link.DefinitionScope, err = definition.ScopeFromKey(scope); err != nil {
			return nil, fmt.Errorf("parse definition scope: %w", err)
		}
		out = append(out, link)
	}
	return out, rows.Err()
}

// ReplaceForFinding replaces the links of one of tenant's findings and sets
// findings.definition_id to the primary, in one transaction. The scope of
// every definition is read from the catalog (never trusted from links); a
// definition tenant cannot see, or a finding of another tenant, is
// definition.ErrNotFound and nothing changes.
func (r *FindingDefinitionRepository) ReplaceForFinding(ctx context.Context, tenant, findingID shared.ID, links []definition.FindingLink) error {
	if err := requireTenant(tenant); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var one int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM findings WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		tenant.String(), findingID.String()).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return definition.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock finding: %w", err)
	}

	resolved, err := visibleScopes(ctx, tx, tenant, links)
	if err != nil {
		return err
	}
	for i := range links {
		links[i].DefinitionScope = resolved[links[i].DefinitionID]
	}
	if err := definition.ValidateFindingLinks(tenant, findingID, links); err != nil {
		return err
	}

	// findings.definition_id must name one of the finding's links (an
	// immediate key): drop the pointer, replace the links, set it again.
	if _, err := tx.ExecContext(ctx, `
		UPDATE findings SET definition_id = NULL
		WHERE tenant_id = $1 AND id = $2 AND definition_id IS NOT NULL`,
		tenant.String(), findingID.String()); err != nil {
		return fmt.Errorf("release primary definition: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM finding_definitions WHERE tenant_id = $1 AND finding_id = $2`,
		tenant.String(), findingID.String()); err != nil {
		return fmt.Errorf("clear finding definitions: %w", err)
	}
	for _, l := range links {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO finding_definitions (finding_id, tenant_id, definition_id, definition_scope, role, ord, asserted_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			findingID.String(), tenant.String(), l.DefinitionID.String(), l.DefinitionScope.Key(),
			string(l.Role), l.Ord, string(l.AssertedBy)); err != nil {
			return fmt.Errorf("link finding definition: %w", err)
		}
	}

	if p, ok := definition.PrimaryOf(links); ok {
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET definition_id = $3 WHERE tenant_id = $1 AND id = $2`,
			tenant.String(), findingID.String(), p.String()); err != nil {
			return fmt.Errorf("set primary definition: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit finding definitions: %w", err)
	}
	return nil
}

// visibleScopes returns the scope of every definition links name, read from
// the catalog with tenant's visibility; one it cannot see is ErrNotFound.
func visibleScopes(ctx context.Context, tx *sql.Tx, tenant shared.ID, links []definition.FindingLink) (map[shared.ID]definition.Scope, error) {
	out := make(map[shared.ID]definition.Scope, len(links))
	if len(links) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(links))
	for _, l := range links {
		ids = append(ids, l.DefinitionID.String())
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT id, tenant_id FROM vulnerabilities WHERE `+definitionVisible+` AND id = ANY($2::uuid[])`,
		tenant.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read definition scopes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		var owner sql.NullString
		if err := rows.Scan(&id, &owner); err != nil {
			return nil, fmt.Errorf("scan definition scope: %w", err)
		}
		parsed, err := shared.IDFromString(id)
		if err != nil {
			return nil, fmt.Errorf("parse definition id: %w", err)
		}
		if out[parsed], err = scopeFromNull(owner); err != nil {
			return nil, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate definition scopes: %w", err)
	}
	for _, l := range links {
		if _, ok := out[l.DefinitionID]; !ok {
			return nil, definition.ErrNotFound
		}
	}
	return out, nil
}

// queryer is what scopeOf needs from a *DB or a *sql.Tx.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func scopeFromNull(owner sql.NullString) (definition.Scope, error) {
	if !owner.Valid {
		return definition.Global(), nil
	}
	id, err := shared.IDFromString(owner.String)
	if err != nil {
		return definition.Scope{}, fmt.Errorf("parse definition tenant: %w", err)
	}
	return definition.TenantScope(id), nil
}

func scanDefinition(scan func(dest ...any) error) (*definition.Definition, error) {
	var (
		id, kind, namespace, externalID, title string
		description, remediation, severity     string
		lifecycle, origin                      string
		owner, mergedInto                      sql.NullString
		nicknames                              pq.StringArray
		createdAt, updatedAt                   time.Time
	)
	err := scan(&id, &owner, &kind, &namespace, &externalID, &title, &description, &remediation,
		&severity, &lifecycle, &mergedInto, &origin, &nicknames, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, definition.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan definition: %w", err)
	}
	parsed, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("parse definition id: %w", err)
	}
	scope, err := scopeFromNull(owner)
	if err != nil {
		return nil, err
	}
	var merged *shared.ID
	if mergedInto.Valid {
		m, err := shared.IDFromString(mergedInto.String)
		if err != nil {
			return nil, fmt.Errorf("parse merged_into: %w", err)
		}
		merged = &m
	}
	return definition.Reconstitute(definition.ReconstituteParams{
		ID: parsed, Scope: scope, Kind: definition.Kind(kind), Namespace: namespace, ExternalID: externalID,
		Title: title, Description: description, Remediation: remediation, Severity: severity,
		Lifecycle: definition.Lifecycle(lifecycle), MergedInto: merged, Origin: definition.Source(origin),
		Nicknames: []string(nicknames), CreatedAt: createdAt, UpdatedAt: updatedAt,
	}), nil
}
