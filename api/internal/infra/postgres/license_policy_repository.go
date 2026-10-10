package postgres

// License policy evaluation rows: verdicts on package links and license
// findings. Design: api/docs/rfcs/RFC-070-software-components-inventory.md.

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	licapp "github.com/openctemio/openctem/api/internal/app/licensepolicy"
	"github.com/openctemio/openctem/api/pkg/domain/licensepolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
)

// LicensePolicyRepository implements licensepolicy.Store.
type LicensePolicyRepository struct {
	db *DB
}

var _ licapp.Store = (*LicensePolicyRepository)(nil)

// NewLicensePolicyRepository creates the repository.
func NewLicensePolicyRepository(db *DB) *LicensePolicyRepository {
	return &LicensePolicyRepository{db: db}
}

// licenseSetKeySQL joins a link's licenses into one comparable key (unit
// separator; normalized licenses carry no control characters).
const licenseSetKeySQL = `array_to_string(s.licenses, E'\x1f')`

const licenseToolName = `'` + licapp.ToolName + `'`

// assetFilter is "AND <col> = ANY($n)" when assetIDs is not empty.
func assetFilter(args *sqlArgs, col string, assetIDs []shared.ID) string {
	if len(assetIDs) == 0 {
		return ""
	}
	return " AND " + col + " = ANY(" + args.add(pq.Array(vexIDStrings(assetIDs))) + "::uuid[])"
}

// Catalog returns the global SPDX catalog: lower-case id -> category.
func (r *LicensePolicyRepository) Catalog(ctx context.Context) (licensepolicy.Catalog, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT lower(COALESCE(spdx_id, id)), COALESCE(category, 'unknown') FROM licenses`)
	if err != nil {
		return nil, fmt.Errorf("license catalog: %w", err)
	}
	defer rows.Close()
	cat := licensepolicy.Catalog{}
	for rows.Next() {
		var id, category string
		if err := rows.Scan(&id, &category); err != nil {
			return nil, fmt.Errorf("scan license: %w", err)
		}
		cat[id] = category
	}
	return cat, rows.Err()
}

// LicenseSets returns the distinct (licenses, scope) pairs of package links.
func (r *LicensePolicyRepository) LicenseSets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]licapp.LicenseSet, error) {
	args := &sqlArgs{}
	tenant := args.add(tenantID.String())
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT s.licenses, COALESCE(s.dep_scope, '')
		FROM asset_software s
		WHERE s.tenant_id = `+tenant+` AND s.source = 'package'`+assetFilter(args, "s.asset_id", assetIDs), args.vals...)
	if err != nil {
		return nil, fmt.Errorf("license sets: %w", err)
	}
	defer rows.Close()
	var out []licapp.LicenseSet
	for rows.Next() {
		var l pq.StringArray
		var set licapp.LicenseSet
		if err := rows.Scan(&l, &set.Scope); err != nil {
			return nil, fmt.Errorf("scan license set: %w", err)
		}
		set.Licenses = []string(l)
		out = append(out, set)
	}
	return out, rows.Err()
}

// SetVerdicts writes each set's verdict on its links; only changed rows.
func (r *LicensePolicyRepository) SetVerdicts(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, verdicts []licapp.SetVerdict) (int64, error) {
	if len(verdicts) == 0 {
		return 0, nil
	}
	keys := make([]string, len(verdicts))
	scopes := make([]string, len(verdicts))
	actions := make([]string, len(verdicts))
	rules := make([]string, len(verdicts))
	for i, v := range verdicts {
		keys[i] = joinUnit(v.Set.Licenses)
		scopes[i] = v.Set.Scope
		actions[i] = string(v.Verdict.Action)
		rules[i] = truncateRule(v.Verdict.Rule)
	}
	args := &sqlArgs{}
	tenant := args.add(tenantID.String())
	k, sc, ac, ru := args.add(pq.Array(keys)), args.add(pq.Array(scopes)), args.add(pq.Array(actions)), args.add(pq.Array(rules))
	res, err := r.db.ExecContext(ctx, `
		UPDATE asset_software s SET license_verdict = v.verdict, license_rule = v.rule
		FROM unnest(`+k+`::text[], `+sc+`::text[], `+ac+`::text[], `+ru+`::text[]) AS v(k, scope, verdict, rule)
		WHERE s.tenant_id = `+tenant+` AND s.source = 'package'
		  AND `+licenseSetKeySQL+` = v.k AND COALESCE(s.dep_scope, '') = v.scope
		  AND (s.license_verdict IS DISTINCT FROM v.verdict OR s.license_rule IS DISTINCT FROM v.rule)`+
		assetFilter(args, "s.asset_id", assetIDs), args.vals...)
	if err != nil {
		return 0, fmt.Errorf("set license verdicts: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func joinUnit(l []string) string {
	out := ""
	for i, s := range l {
		if i > 0 {
			out += "\x1f"
		}
		out += s
	}
	return out
}

func truncateRule(s string) string {
	if len(s) > 160 {
		return s[:160]
	}
	return s
}

// ClearVerdicts removes verdicts (policy off).
func (r *LicensePolicyRepository) ClearVerdicts(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error {
	args := &sqlArgs{}
	tenant := args.add(tenantID.String())
	_, err := r.db.ExecContext(ctx, `UPDATE asset_software s SET license_verdict = NULL, license_rule = NULL
		WHERE s.tenant_id = `+tenant+` AND s.source = 'package' AND s.license_verdict IS NOT NULL`+
		assetFilter(args, "s.asset_id", assetIDs), args.vals...)
	if err != nil {
		return fmt.Errorf("clear license verdicts: %w", err)
	}
	return nil
}

// Violations returns the links with a review or deny verdict.
func (r *LicensePolicyRepository) Violations(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]licapp.Violation, error) {
	args := &sqlArgs{}
	tenant := args.add(tenantID.String())
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.asset_id::text, s.product_id::text, s.software_version_id::text, p.purl_type,
		       COALESCE(p.purl_namespace, ''), p.purl_name, v.raw, s.licenses, s.license_verdict, COALESCE(s.license_rule, '')
		FROM asset_software s
		JOIN software_products p ON p.id = s.product_id
		JOIN software_versions v ON v.id = s.software_version_id
		WHERE s.tenant_id = `+tenant+` AND s.source = 'package' AND s.license_verdict IN ('review', 'deny')
		  AND p.purl_type IS NOT NULL`+assetFilter(args, "s.asset_id", assetIDs)+`
		ORDER BY s.asset_id, s.product_id, s.software_version_id`, args.vals...)
	if err != nil {
		return nil, fmt.Errorf("license violations: %w", err)
	}
	defer rows.Close()
	var out []licapp.Violation
	for rows.Next() {
		var (
			asset, product, version, typ, ns, name, raw, verdict, rule string
			lic                                                        pq.StringArray
		)
		if err := rows.Scan(&asset, &product, &version, &typ, &ns, &name, &raw, &lic, &verdict, &rule); err != nil {
			return nil, fmt.Errorf("scan license violation: %w", err)
		}
		v := licapp.Violation{
			PURL: software.PURL{Type: typ, Namespace: ns, Name: name}, Version: raw, Licenses: []string(lic),
			Verdict: licensepolicy.Verdict{Action: licensepolicy.Action(verdict), Rule: rule},
		}
		var e1, e2, e3 error
		v.AssetID, e1 = shared.IDFromString(asset)
		v.ProductID, e2 = shared.IDFromString(product)
		v.VersionID, e3 = shared.IDFromString(version)
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// LicenseFindings returns the license findings (reserved tool name).
func (r *LicensePolicyRepository) LicenseFindings(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]licapp.ExistingFinding, error) {
	args := &sqlArgs{}
	tenant := args.add(tenantID.String())
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id::text, f.fingerprint, f.status, f.severity, COALESCE(f.resolution_method, '')
		FROM findings f
		WHERE f.tenant_id = `+tenant+` AND f.tool_name = `+licenseToolName+` AND f.finding_type = 'license'`+
		assetFilter(args, "f.asset_id", assetIDs), args.vals...)
	if err != nil {
		return nil, fmt.Errorf("license findings: %w", err)
	}
	defer rows.Close()
	var out []licapp.ExistingFinding
	for rows.Next() {
		var e licapp.ExistingFinding
		var id string
		if err := rows.Scan(&id, &e.Fingerprint, &e.Status, &e.Severity, &e.ResolutionMethod); err != nil {
			return nil, fmt.Errorf("scan license finding: %w", err)
		}
		parsed, perr := shared.IDFromString(id)
		if perr != nil {
			continue
		}
		e.ID = parsed
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *LicensePolicyRepository) moveFindings(ctx context.Context, query string, tenantID shared.ID, ids []shared.ID) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, query, tenantID.String(), pq.Array(vexIDStrings(ids)))
	if err != nil {
		return 0, fmt.Errorf("move license findings: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ResolveFindings closes license findings the policy no longer flags, with
// an activity entry each.
func (r *LicensePolicyRepository) ResolveFindings(ctx context.Context, tenantID shared.ID, ids []shared.ID) (int, error) {
	return r.moveFindings(ctx, `
		WITH moved AS (
			UPDATE findings f SET status = 'resolved',
				resolution = 'The license policy no longer flags this package',
				resolution_method = '`+licapp.ResolutionMethod+`', resolved_at = NOW(), resolved_by = NULL, updated_at = NOW()
			WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[]) AND f.tool_name = `+licenseToolName+`
			  AND f.status IN `+autoResolveFromSQL+`
			RETURNING f.id
		)
		INSERT INTO finding_activities (id, tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, created_at)
		SELECT gen_random_uuid(), $1, m.id, 'status_changed', 'system', 'system: license policy',
			jsonb_build_object('new_status', 'resolved', 'reason', 'license_policy'), 'auto', NOW()
		FROM moved m`, tenantID, ids)
}

// ReopenFindings reopens license findings the policy closed and flags again.
func (r *LicensePolicyRepository) ReopenFindings(ctx context.Context, tenantID shared.ID, ids []shared.ID) (int, error) {
	return r.moveFindings(ctx, `
		WITH moved AS (
			UPDATE findings f SET status = 'confirmed', resolution = NULL, resolution_method = NULL,
				resolved_at = NULL, resolved_by = NULL, updated_at = NOW()
			WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[]) AND f.tool_name = `+licenseToolName+`
			  AND f.status IN `+fixedReopenFromSQL+` AND f.resolution_method = '`+licapp.ResolutionMethod+`'
			RETURNING f.id
		)
		INSERT INTO finding_activities (id, tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, created_at)
		SELECT gen_random_uuid(), $1, m.id, 'status_changed', 'system', 'system: license policy',
			jsonb_build_object('old_status', 'resolved', 'new_status', 'confirmed', 'reason', 'license_policy'), 'auto', NOW()
		FROM moved m`, tenantID, ids)
}

// SetFindingSeverity changes the severity of license findings (the verdict
// moved between review and deny).
func (r *LicensePolicyRepository) SetFindingSeverity(ctx context.Context, tenantID shared.ID, ids []shared.ID, severity string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `UPDATE findings SET severity = $3, updated_at = NOW()
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND tool_name = `+licenseToolName,
		tenantID.String(), pq.Array(vexIDStrings(ids)), severity)
	if err != nil {
		return fmt.Errorf("set license finding severity: %w", err)
	}
	return nil
}
