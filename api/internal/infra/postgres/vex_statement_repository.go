package postgres

// Tenant VEX statements and the findings they act on. Design:
// api/docs/rfcs/RFC-070-software-components-inventory.md.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vex"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// VEXStatementRepository implements vex.Repository.
type VEXStatementRepository struct {
	db *DB
}

var _ vex.Repository = (*VEXStatementRepository)(nil)

// NewVEXStatementRepository creates the repository.
func NewVEXStatementRepository(db *DB) *VEXStatementRepository {
	return &VEXStatementRepository{db: db}
}

const vexStatementColumns = `s.id, s.tenant_id, s.vuln_id, s.product_id, s.versions, s.version_range, s.asset_id,
	s.status, s.justification, s.impact_statement, s.action_statement, s.origin, s.document_ref,
	s.expires_at, s.expired_at, s.created_by, s.updated_by, s.created_at, s.updated_at`

func scanVEXStatement(row interface{ Scan(...any) error }) (*vex.Statement, error) {
	var (
		s                                 vex.Statement
		id, tenant, product               string
		versions                          pq.StringArray
		rng, just, impact, action, docRef sql.NullString
		asset, createdBy, updatedBy       sql.NullString
		expiresAt, expiredAt              sql.NullTime
		status                            string
	)
	if err := row.Scan(&id, &tenant, &s.VulnID, &product, &versions, &rng, &asset, &status, &just, &impact,
		&action, &s.Origin, &docRef, &expiresAt, &expiredAt, &createdBy, &updatedBy, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	var err error
	if s.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("vex statement id: %w", err)
	}
	if s.TenantID, err = shared.IDFromString(tenant); err != nil {
		return nil, fmt.Errorf("vex statement tenant: %w", err)
	}
	if s.ProductID, err = shared.IDFromString(product); err != nil {
		return nil, fmt.Errorf("vex statement product: %w", err)
	}
	s.Versions = []string(versions)
	if s.Versions == nil {
		s.Versions = []string{}
	}
	s.VersionRange = rng.String
	s.AssetID = parseNullID(asset)
	s.Status = vex.Status(status)
	s.Justification, s.ImpactStatement, s.ActionStatement, s.DocumentRef = just.String, impact.String, action.String, docRef.String
	s.ExpiresAt, s.ExpiredAt = nullTimeValue(expiresAt), nullTimeValue(expiredAt)
	s.CreatedBy, s.UpdatedBy = parseNullID(createdBy), parseNullID(updatedBy)
	return &s, nil
}

func versionsArray(v []string) pq.StringArray {
	if v == nil {
		return pq.StringArray{}
	}
	return pq.StringArray(v)
}

func mapVEXWriteError(err error) error {
	switch {
	case isUniqueViolation(err):
		return vex.ErrConflict
	case isCheckViolation(err):
		return fmt.Errorf("%w: the statement refers to a package or asset that does not exist", shared.ErrValidation)
	}
	return err
}

// Create inserts a statement.
func (r *VEXStatementRepository) Create(ctx context.Context, s *vex.Statement) error {
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO vex_statements (id, tenant_id, vuln_id, product_id, versions, version_range, asset_id, status,
			justification, impact_statement, action_statement, origin, document_ref, expires_at, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $15)
		RETURNING created_at, updated_at`,
		s.ID.String(), s.TenantID.String(), s.VulnID, s.ProductID.String(), versionsArray(s.Versions),
		nullString(s.VersionRange), nullID(s.AssetID), string(s.Status), nullString(s.Justification),
		nullString(s.ImpactStatement), nullString(s.ActionStatement), s.Origin, nullString(s.DocumentRef),
		nullTime(s.ExpiresAt), nullID(s.CreatedBy)).Scan(&s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			return fmt.Errorf("%w: the package or asset does not exist", shared.ErrValidation)
		}
		return mapVEXWriteError(err)
	}
	return nil
}

// Update rewrites a statement's content (its subject is fixed) and clears
// its expired mark, so a statement given a new expiry applies again.
func (r *VEXStatementRepository) Update(ctx context.Context, s *vex.Statement) error {
	err := r.db.QueryRowContext(ctx, `
		UPDATE vex_statements SET versions = $3, version_range = $4, status = $5, justification = $6,
			impact_statement = $7, action_statement = $8, document_ref = $9, expires_at = $10,
			expired_at = NULL, updated_by = $11, updated_at = clock_timestamp()
		WHERE tenant_id = $1 AND id = $2
		RETURNING updated_at`,
		s.TenantID.String(), s.ID.String(), versionsArray(s.Versions), nullString(s.VersionRange), string(s.Status),
		nullString(s.Justification), nullString(s.ImpactStatement), nullString(s.ActionStatement),
		nullString(s.DocumentRef), nullTime(s.ExpiresAt), nullID(s.UpdatedBy)).Scan(&s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return vex.ErrNotFound
	}
	if err != nil {
		return mapVEXWriteError(err)
	}
	s.ExpiredAt = nil
	return nil
}

// Delete removes a statement.
func (r *VEXStatementRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM vex_statements WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("delete vex statement: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return vex.ErrNotFound
	}
	return nil
}

// Get returns one statement of the tenant.
func (r *VEXStatementRepository) Get(ctx context.Context, tenantID, id shared.ID) (*vex.Statement, error) {
	s, err := scanVEXStatement(r.db.QueryRowContext(ctx, `SELECT `+vexStatementColumns+`
		FROM vex_statements s WHERE s.tenant_id = $1 AND s.id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, vex.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get vex statement: %w", err)
	}
	return s, nil
}

// FindBySubject returns the statement with the same subject.
func (r *VEXStatementRepository) FindBySubject(ctx context.Context, in *vex.Statement) (*vex.Statement, error) {
	s, err := scanVEXStatement(r.db.QueryRowContext(ctx, `SELECT `+vexStatementColumns+`
		FROM vex_statements s
		WHERE s.tenant_id = $1 AND s.vuln_id = $2 AND s.product_id = $3
		  AND s.asset_id IS NOT DISTINCT FROM $4::uuid AND s.versions = $5::text[]
		  AND COALESCE(s.version_range, '') = $6`,
		in.TenantID.String(), in.VulnID, in.ProductID.String(), nullID(in.AssetID), versionsArray(in.Versions),
		in.VersionRange))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, vex.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find vex statement: %w", err)
	}
	return s, nil
}

// List returns a page of the tenant's statements, newest first.
func (r *VEXStatementRepository) List(ctx context.Context, f vex.Filter, page pagination.Pagination) (pagination.Result[*vex.Statement], error) {
	args := &sqlArgs{}
	where := []string{"s.tenant_id = " + args.add(f.TenantID.String())}
	if f.VulnID != "" {
		where = append(where, "s.vuln_id = "+args.add(f.VulnID))
	}
	if f.ProductID != nil {
		where = append(where, "s.product_id = "+args.add(f.ProductID.String()))
	}
	if f.AssetID != nil {
		where = append(where, "s.asset_id = "+args.add(f.AssetID.String()))
	}
	if f.Status != "" {
		where = append(where, "s.status = "+args.add(string(f.Status)))
	}
	if f.Scope != nil {
		// Asset-bound statements on an in-scope asset; tenant-wide statements
		// whose package an in-scope asset uses.
		assetScoped := vexScopeCond(args, "s.asset_id", f.Scope)
		linkScoped := vexScopeCond(args, "l.asset_id", f.Scope)
		where = append(where, `((s.asset_id IS NOT NULL AND `+assetScoped+`)
			OR (s.asset_id IS NULL AND EXISTS (
				SELECT 1 FROM asset_software l
				WHERE l.tenant_id = s.tenant_id AND l.product_id = s.product_id AND l.source = 'package'
				  AND `+linkScoped+`)))`)
	}
	cond := strings.Join(where, " AND ")
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM vex_statements s WHERE `+cond, args.vals...).Scan(&total); err != nil {
		return pagination.Result[*vex.Statement]{}, fmt.Errorf("count vex statements: %w", err)
	}
	limit := args.add(page.Limit())
	offset := args.add(page.Offset())
	rows, err := r.db.QueryContext(ctx, `SELECT `+vexStatementColumns+`
		FROM vex_statements s WHERE `+cond+`
		ORDER BY s.updated_at DESC, s.id
		LIMIT `+limit+` OFFSET `+offset, args.vals...)
	if err != nil {
		return pagination.Result[*vex.Statement]{}, fmt.Errorf("list vex statements: %w", err)
	}
	defer rows.Close()
	// Not preallocated from the page size (a caller-chosen number).
	out := []*vex.Statement{}
	for rows.Next() {
		s, err := scanVEXStatement(rows)
		if err != nil {
			return pagination.Result[*vex.Statement]{}, fmt.Errorf("scan vex statement: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*vex.Statement]{}, fmt.Errorf("iterate vex statements: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

func (r *VEXStatementRepository) queryStatements(ctx context.Context, query string, args ...any) ([]*vex.Statement, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query vex statements: %w", err)
	}
	defer rows.Close()
	var out []*vex.Statement
	for rows.Next() {
		s, err := scanVEXStatement(rows)
		if err != nil {
			return nil, fmt.Errorf("scan vex statement: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate vex statements: %w", err)
	}
	return out, nil
}

// ActiveForProducts returns the tenant's unexpired statements about the packages.
func (r *VEXStatementRepository) ActiveForProducts(ctx context.Context, tenantID shared.ID, productIDs []shared.ID, now time.Time) ([]*vex.Statement, error) {
	if len(productIDs) == 0 {
		return nil, nil
	}
	return r.queryStatements(ctx, `SELECT `+vexStatementColumns+`
		FROM vex_statements s
		WHERE s.tenant_id = $1 AND s.product_id = ANY($2::uuid[])
		  AND (s.expires_at IS NULL OR s.expires_at > $3)`,
		tenantID.String(), pq.Array(vexIDStrings(productIDs)), now)
}

// TenantHasActive reports whether the tenant has an unexpired statement.
func (r *VEXStatementRepository) TenantHasActive(ctx context.Context, tenantID shared.ID, now time.Time) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM vex_statements
		WHERE tenant_id = $1 AND (expires_at IS NULL OR expires_at > $2))`, tenantID.String(), now).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("vex statements exist: %w", err)
	}
	return ok, nil
}

// DueForExpiry returns expired statements of every tenant not yet withdrawn.
func (r *VEXStatementRepository) DueForExpiry(ctx context.Context, now time.Time, limit int) ([]*vex.Statement, error) {
	return r.queryStatements(ctx, `SELECT `+vexStatementColumns+`
		FROM vex_statements s
		WHERE s.expires_at IS NOT NULL AND s.expires_at <= $1 AND s.expired_at IS NULL
		ORDER BY s.expires_at, s.id
		LIMIT $2`, now, limit)
}

// MarkExpired records that the statement was withdrawn from its findings.
func (r *VEXStatementRepository) MarkExpired(ctx context.Context, tenantID, id shared.ID, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE vex_statements SET expired_at = $3
		WHERE tenant_id = $1 AND id = $2 AND expired_at IS NULL`, tenantID.String(), id.String(), at)
	if err != nil {
		return fmt.Errorf("mark vex statement expired: %w", err)
	}
	return nil
}

// findingRefSelect reads a finding as a vex.FindingRef: its package version
// (product and raw version) and every vulnerability id it carries.
const findingRefSelect = `
	SELECT f.id::text, f.asset_id::text, v.product_id::text, v.raw, f.status, f.source,
		COALESCE(f.resolution_method, ''), f.vex_statement_id::text, f.vex_at,
		array_remove(ARRAY[upper(f.cve_id), upper(f.rule_id)], NULL)
		|| COALESCE((SELECT array_agg(upper(x)) FROM unnest(f.cve_ids::text[]) x), '{}')
		|| COALESCE((SELECT array_agg(upper(e->>'id')) FROM jsonb_array_elements(
			CASE WHEN jsonb_typeof(f.vulnerability_ids) = 'array' THEN f.vulnerability_ids ELSE '[]'::jsonb END) e
			WHERE e->>'id' IS NOT NULL), '{}')
	FROM findings f
	JOIN software_versions v ON v.id = f.component_id`

func (r *VEXStatementRepository) queryFindingRefs(ctx context.Context, query string, args ...any) ([]vex.FindingRef, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query vex findings: %w", err)
	}
	defer rows.Close()
	var out []vex.FindingRef
	for rows.Next() {
		var (
			id, asset, product string
			stmt               sql.NullString
			vexAt              sql.NullTime
			ids                pq.StringArray
			f                  vex.FindingRef
		)
		if err := rows.Scan(&id, &asset, &product, &f.Version, &f.Status, &f.Source, &f.ResolutionMethod,
			&stmt, &vexAt, &ids); err != nil {
			return nil, fmt.Errorf("scan vex finding: %w", err)
		}
		var e1, e2, e3 error
		f.ID, e1 = shared.IDFromString(id)
		f.AssetID, e2 = shared.IDFromString(asset)
		f.ProductID, e3 = shared.IDFromString(product)
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		f.StatementID = parseNullID(stmt)
		f.VEXAt = nullTimeValue(vexAt)
		f.VulnIDs = []string(ids)
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate vex findings: %w", err)
	}
	return out, nil
}

// CandidateFindings returns findings the subject may cover.
func (r *VEXStatementRepository) CandidateFindings(ctx context.Context, tenantID, productID shared.ID, vulnID string,
	assetID *shared.ID, after shared.ID, limit int) ([]vex.FindingRef, error) {
	return r.queryFindingRefs(ctx, findingRefSelect+`
		WHERE f.tenant_id = $1 AND v.product_id = $2
		  AND (upper(f.cve_id) = $3 OR $3 = ANY(f.cve_ids::text[]) OR upper(f.rule_id) = $3
		       OR (jsonb_typeof(f.vulnerability_ids) = 'array' AND EXISTS (
		           SELECT 1 FROM jsonb_array_elements(f.vulnerability_ids) e WHERE upper(e->>'id') = $3)))
		  AND ($4::uuid IS NULL OR f.asset_id = $4::uuid)
		  AND f.id > $5::uuid
		ORDER BY f.id
		LIMIT $6`,
		tenantID.String(), productID.String(), vulnID, nullID(assetID), after.String(), limit)
}

// FindingsWithStatement returns the findings carrying the statement.
func (r *VEXStatementRepository) FindingsWithStatement(ctx context.Context, tenantID, statementID shared.ID,
	after shared.ID, limit int) ([]vex.FindingRef, error) {
	return r.queryFindingRefs(ctx, findingRefSelect+`
		WHERE f.tenant_id = $1 AND f.vex_statement_id = $2 AND f.id > $3::uuid
		ORDER BY f.id
		LIMIT $4`,
		tenantID.String(), statementID.String(), after.String(), limit)
}

// FindingsByFingerprints returns the package findings with these fingerprints.
func (r *VEXStatementRepository) FindingsByFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) ([]vex.FindingRef, error) {
	if len(fingerprints) == 0 {
		return nil, nil
	}
	return r.queryFindingRefs(ctx, findingRefSelect+`
		WHERE f.tenant_id = $1 AND f.fingerprint = ANY($2::text[])`,
		tenantID.String(), pq.Array(fingerprints))
}

// WriteEffects applies the effects in one transaction.
func (r *VEXStatementRepository) WriteEffects(ctx context.Context, tenantID shared.ID, effects []vex.Effect) ([]shared.ID, error) {
	if len(effects) == 0 {
		return nil, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin vex effects: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	moved := make([]shared.ID, 0, len(effects))
	for i := range effects {
		e := &effects[i]
		var (
			status, just, statement, source, stmtID sql.NullString
			at                                      sql.NullTime
		)
		if s := e.Statement; s != nil {
			status = nullString(string(s.Status))
			just = nullString(s.Justification)
			text := s.ImpactStatement
			if text == "" {
				text = s.ActionStatement
			}
			statement = nullString(text)
			src := "organization VEX statement"
			if s.DocumentRef != "" {
				src = s.DocumentRef
			}
			source = nullString(src)
			at = sql.NullTime{Time: s.UpdatedAt, Valid: true}
			stmtID = nullIDValue(s.ID)
		}
		var newStatus sql.NullString
		if e.Changes() {
			newStatus = nullString(e.NewStatus)
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE findings SET
				vex_status = $3, vex_justification = $4, vex_statement = $5, vex_source = $6, vex_at = $7,
				vex_statement_id = $8,
				status            = COALESCE($9, status),
				resolution        = CASE WHEN $9::text IS NULL THEN resolution ELSE NULLIF($10, '') END,
				resolution_method = CASE WHEN $9::text IS NULL THEN resolution_method ELSE NULLIF($11, '') END,
				resolved_at       = CASE WHEN $9::text IS NULL THEN resolved_at
				                         WHEN $9 IN ('false_positive', 'resolved') THEN NOW() ELSE NULL END,
				resolved_by       = CASE WHEN $9::text IS NULL THEN resolved_by ELSE NULL END,
				updated_at        = NOW()
			WHERE tenant_id = $1 AND id = $2 AND status = $12`,
			tenantID.String(), e.FindingID.String(), status, just, statement, source, at, stmtID,
			newStatus, e.Resolution, e.ResolutionMethod, e.OldStatus)
		if err != nil {
			return nil, fmt.Errorf("write vex effect: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 || !e.Changes() {
			continue
		}
		reason := "vex_statement_withdrawn"
		var sid any
		if e.Statement != nil {
			reason = "vex_statement"
			sid = e.Statement.ID.String()
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO finding_activities (id, tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, created_at)
			VALUES (gen_random_uuid(), $1, $2, 'status_changed', 'system', 'system: VEX statement',
				jsonb_build_object('old_status', $3::text, 'new_status', $4::text, 'reason', $5::text,
					'vex_statement_id', $6::text, 'resolution_method', NULLIF($7, '')),
				'auto', NOW())`,
			tenantID.String(), e.FindingID.String(), e.OldStatus, e.NewStatus, reason, sid, e.ResolutionMethod); err != nil {
			return nil, fmt.Errorf("record vex activity: %w", err)
		}
		moved = append(moved, e.FindingID)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit vex effects: %w", err)
	}
	return moved, nil
}

// ResolveProduct returns the tenant's own package product, else the global one.
func (r *VEXStatementRepository) ResolveProduct(ctx context.Context, tenantID shared.ID, purlType, namespace, name string) (shared.ID, error) {
	var id string
	err := r.db.QueryRowContext(ctx, `
		SELECT id::text FROM software_products
		WHERE purl_type = $2 AND purl_namespace = $3 AND purl_name = $4
		  AND (tenant_id = $1 OR tenant_id IS NULL)
		ORDER BY tenant_id IS NULL
		LIMIT 1`, tenantID.String(), purlType, namespace, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return shared.ID{}, fmt.Errorf("%w: package not in the inventory", shared.ErrNotFound)
	}
	if err != nil {
		return shared.ID{}, fmt.Errorf("resolve package: %w", err)
	}
	return shared.IDFromString(id)
}

// ProductVisible reports whether the product is a global or own package product.
func (r *VEXStatementRepository) ProductVisible(ctx context.Context, tenantID, productID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM software_products
		WHERE id = $2 AND purl_type IS NOT NULL AND (tenant_id = $1 OR tenant_id IS NULL))`,
		tenantID.String(), productID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("package visible: %w", err)
	}
	return ok, nil
}

// ProductInScope reports whether an in-scope asset uses the package.
func (r *VEXStatementRepository) ProductInScope(ctx context.Context, tenantID, productID shared.ID, scope *shared.DataScope) (bool, error) {
	args := &sqlArgs{}
	tenant := args.add(tenantID.String())
	product := args.add(productID.String())
	cond := "TRUE"
	if scope != nil {
		cond = vexScopeCond(args, "l.asset_id", scope)
	}
	var ok bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM asset_software l
		WHERE l.tenant_id = `+tenant+` AND l.product_id = `+product+` AND l.source = 'package' AND `+cond+`)`,
		args.vals...).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("package in scope: %w", err)
	}
	return ok, nil
}

// vexScopeCond is the data-scope predicate on assetExpr, its values added to args.
func vexScopeCond(args *sqlArgs, assetExpr string, s *shared.DataScope) string {
	cond, vals := dataScopeCondAt(assetExpr, s, len(args.vals)+1)
	args.vals = append(args.vals, vals...)
	return cond
}

func vexIDStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}
