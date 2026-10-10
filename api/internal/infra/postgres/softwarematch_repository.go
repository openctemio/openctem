package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// SoftwareMatchRepository is the storage of the inventory vulnerability
// matcher (RFC-066). Version evaluation touches global rows only; every
// tenant method filters on the tenant.
type SoftwareMatchRepository struct {
	db *DB
}

// NewSoftwareMatchRepository creates a SoftwareMatchRepository.
func NewSoftwareMatchRepository(db *DB) *SoftwareMatchRepository {
	return &SoftwareMatchRepository{db: db}
}

var _ softwarematch.Store = (*SoftwareMatchRepository)(nil)

// matcherOwnedSQL selects findings the matcher created and no scanner has
// reported since: only these does it close or reopen.
const matcherOwnedSQL = `f.tool_name = '` + softwarematch.ToolName + `'
	AND COALESCE(f.last_seen_tool, f.tool_name) = '` + softwarematch.ToolName + `'`

// PendingVersions (see softwarematch.Store).
func (r *SoftwareMatchRepository) PendingVersions(ctx context.Context, limit int) ([]softwarematch.Version, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, product_id, raw, scheme, edition FROM software_versions
		WHERE matched_at IS NULL AND tenant_id IS NULL AND normalized IS NOT NULL
		ORDER BY created_at LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("pending versions: %w", err)
	}
	defer rows.Close()
	var out []softwarematch.Version
	for rows.Next() {
		var v softwarematch.Version
		var id, pid, scheme string
		if err := rows.Scan(&id, &pid, &v.Raw, &scheme, &v.Edition); err != nil {
			return nil, fmt.Errorf("pending versions: %w", err)
		}
		v.ID, v.ProductID, v.Scheme = shared.MustIDFromString(id), shared.MustIDFromString(pid), vulnmatch.Scheme(scheme)
		out = append(out, v)
	}
	return out, rows.Err()
}

// RangesForProduct (see softwarematch.Store).
func (r *SoftwareMatchRepository) RangesForProduct(ctx context.Context, productID shared.ID) ([]softwarematch.AffectedRange, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, cve_id, scheme, COALESCE(exact_version, ''), COALESCE(v_start, ''), v_start_incl,
			COALESCE(v_end, ''), v_end_incl, edition, target, COALESCE(condition_product_id::text, '')
		FROM vulnerability_affected WHERE product_id = $1 ORDER BY id`, productID.String())
	if err != nil {
		return nil, fmt.Errorf("product ranges: %w", err)
	}
	defer rows.Close()
	var out []softwarematch.AffectedRange
	for rows.Next() {
		var a softwarematch.AffectedRange
		var scheme string
		rg := &a.Range
		if err := rows.Scan(&a.ID, &rg.VulnID, &scheme, &rg.Exact, &rg.Start, &rg.StartIncl,
			&rg.End, &rg.EndIncl, &rg.Edition, &rg.Target, &rg.Condition); err != nil {
			return nil, fmt.Errorf("product ranges: %w", err)
		}
		rg.Scheme = vulnmatch.Scheme(scheme)
		rg.ID = fmt.Sprint(a.ID)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ReplaceVersionVulns (see softwarematch.Store).
func (r *SoftwareMatchRepository) ReplaceVersionVulns(ctx context.Context, versionID shared.ID, vulns []softwarematch.VersionVuln) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	before, err := versionVulnKeys(ctx, tx, versionID)
	if err != nil {
		return false, err
	}
	after := make([]string, 0, len(vulns))
	cves := make([]string, 0, len(vulns))
	affected := make([]int64, 0, len(vulns))
	texts := make([]string, 0, len(vulns))
	all := make([]bool, 0, len(vulns))
	adj := make([]int, 0, len(vulns))
	reasons := make([]string, 0, len(vulns))
	conds := make([]sql.NullString, 0, len(vulns))
	for _, v := range vulns {
		after = append(after, fmt.Sprintf("%s|%t|%d", v.CVEID, v.AllVersions, v.Adjustment))
		cves = append(cves, v.CVEID)
		affected = append(affected, v.AffectedID)
		texts = append(texts, clipStr(v.RangeText, 200))
		all = append(all, v.AllVersions)
		adj = append(adj, v.Adjustment)
		reasons = append(reasons, strings.Join(v.Reasons, ","))
		var c sql.NullString
		if v.ConditionProductID != nil {
			c = sql.NullString{String: v.ConditionProductID.String(), Valid: true}
		}
		conds = append(conds, c)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM software_version_vulns WHERE software_version_id = $1`, versionID.String()); err != nil {
		return false, fmt.Errorf("version vulns: %w", err)
	}
	if len(vulns) > 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO software_version_vulns (software_version_id, cve_id, affected_id, range_text,
				all_versions, adjustment, reasons, condition_product_id)
			SELECT $1, c, a, t, al, ad, CASE WHEN rs = '' THEN '{}'::text[] ELSE string_to_array(rs, ',') END, cp
			FROM unnest($2::text[], $3::bigint[], $4::text[], $5::bool[], $6::int[], $7::text[], $8::uuid[])
				AS u(c, a, t, al, ad, rs, cp)
			ON CONFLICT (software_version_id, cve_id) DO NOTHING`,
			versionID.String(), pq.Array(cves), pq.Array(affected), pq.Array(texts), pq.Array(all),
			pq.Array(adj), pq.Array(reasons), pq.Array(conds)); err != nil {
			return false, fmt.Errorf("version vulns: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE software_versions SET matched_at = now()
		WHERE id = $1 AND tenant_id IS NULL`, versionID.String()); err != nil {
		return false, fmt.Errorf("version evaluated: %w", err)
	}
	sort.Strings(before)
	sort.Strings(after)
	changed := strings.Join(before, ";") != strings.Join(after, ";")
	if changed {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vuln_match_queue (tenant_id)
			SELECT DISTINCT tenant_id FROM asset_software WHERE software_version_id = $1
			ON CONFLICT (tenant_id) DO NOTHING`, versionID.String()); err != nil {
			return false, fmt.Errorf("queue tenants: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return changed, nil
}

// versionVulnKeys reads the stored results of a version as comparable keys.
func versionVulnKeys(ctx context.Context, tx *sql.Tx, versionID shared.ID) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT cve_id || '|' || all_versions::text || '|' || adjustment::text
		FROM software_version_vulns WHERE software_version_id = $1`, versionID.String())
	if err != nil {
		return nil, fmt.Errorf("version vulns: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("version vulns: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ResetVersionsForCVEsSince (see softwarematch.Store). A feed page writes
// many CVEs with the same synced_at, so the batch always ends on a whole
// timestamp: every CVE synced at the boundary is included.
func (r *SoftwareMatchRepository) ResetVersionsForCVEsSince(ctx context.Context, since time.Time, limit int) (time.Time, int, error) {
	var boundary sql.NullTime
	if err := r.db.QueryRowContext(ctx, `
		SELECT max(synced_at) FROM (
			SELECT synced_at FROM cve_records WHERE synced_at > $1 ORDER BY synced_at LIMIT $2
		) b`, since, limit).Scan(&boundary); err != nil {
		return since, 0, fmt.Errorf("feed delta: %w", err)
	}
	if !boundary.Valid {
		return since, 0, nil
	}
	res, err := r.db.ExecContext(ctx, `
		WITH c AS (SELECT cve_id FROM cve_records WHERE synced_at > $1 AND synced_at <= $2)
		UPDATE software_versions v SET matched_at = NULL
		WHERE v.tenant_id IS NULL AND v.normalized IS NOT NULL AND v.matched_at IS NOT NULL
		  AND (v.product_id IN (SELECT a.product_id FROM vulnerability_affected a JOIN c ON c.cve_id = a.cve_id)
		    OR v.id IN (SELECT m.software_version_id FROM software_version_vulns m JOIN c ON c.cve_id = m.cve_id))`,
		since, boundary.Time)
	if err != nil {
		return since, 0, fmt.Errorf("feed delta: %w", err)
	}
	n, _ := res.RowsAffected()
	return boundary.Time, int(n), nil
}

// State (see softwarematch.Store); the zero time when unset.
func (r *SoftwareMatchRepository) State(ctx context.Context, name string) (time.Time, error) {
	var at time.Time
	err := r.db.QueryRowContext(ctx, `SELECT at FROM vuln_match_state WHERE name = $1`, name).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("matcher state: %w", err)
	}
	return at, nil
}

// SetState (see softwarematch.Store).
func (r *SoftwareMatchRepository) SetState(ctx context.Context, name string, at time.Time) error {
	if _, err := r.db.ExecContext(ctx, `
		INSERT INTO vuln_match_state (name, at) VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET at = EXCLUDED.at, updated_at = now()`, name, at); err != nil {
		return fmt.Errorf("matcher state: %w", err)
	}
	return nil
}

// QueueTenants (see softwarematch.Store).
func (r *SoftwareMatchRepository) QueueTenants(ctx context.Context, tenantIDs []shared.ID) error {
	if len(tenantIDs) == 0 {
		return nil
	}
	ids := make([]string, len(tenantIDs))
	for i, id := range tenantIDs {
		ids[i] = id.String()
	}
	if _, err := r.db.ExecContext(ctx, `
		INSERT INTO vuln_match_queue (tenant_id) SELECT DISTINCT unnest($1::uuid[])
		ON CONFLICT (tenant_id) DO NOTHING`, pq.Array(ids)); err != nil {
		return fmt.Errorf("queue tenants: %w", err)
	}
	return nil
}

// QueueAllTenantsWithSoftware (see softwarematch.Store).
func (r *SoftwareMatchRepository) QueueAllTenantsWithSoftware(ctx context.Context) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO vuln_match_queue (tenant_id) SELECT DISTINCT tenant_id FROM asset_software
		ON CONFLICT (tenant_id) DO NOTHING`)
	if err != nil {
		return 0, fmt.Errorf("queue tenants: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// DequeueTenants (see softwarematch.Store).
func (r *SoftwareMatchRepository) DequeueTenants(ctx context.Context, limit int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		DELETE FROM vuln_match_queue WHERE tenant_id IN (
			SELECT tenant_id FROM vuln_match_queue ORDER BY queued_at LIMIT $1 FOR UPDATE SKIP LOCKED)
		RETURNING tenant_id::text`, limit)
	if err != nil {
		return nil, fmt.Errorf("dequeue tenants: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("dequeue tenants: %w", err)
		}
		out = append(out, shared.MustIDFromString(s))
	}
	return out, rows.Err()
}

// TenantMatches (see softwarematch.Store).
func (r *SoftwareMatchRepository) TenantMatches(ctx context.Context, tenantID shared.ID, currentSince time.Time, limit int) ([]softwarematch.Match, error) {
	return r.matches(ctx, `s.tenant_id = $1 AND s.superseded_at IS NULL AND s.last_seen_at >= $2`, limit,
		tenantID.String(), currentSince)
}

// AssetMatches (see softwarematch.Store).
func (r *SoftwareMatchRepository) AssetMatches(ctx context.Context, tenantID, assetID shared.ID) ([]softwarematch.Match, error) {
	return r.matches(ctx, `s.tenant_id = $1 AND s.asset_id = $2 AND s.superseded_at IS NULL`, 10_000,
		tenantID.String(), assetID.String())
}

// matches reads current links joined with their versions' matches; where
// must filter on the tenant ($1) and uses $2; $3 is the limit.
func (r *SoftwareMatchRepository) matches(ctx context.Context, where string, limit int, a1, a2 any) ([]softwarematch.Match, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.asset_id, (a.exposure = 'public' OR COALESCE(a.is_internet_accessible, false)),
			s.confidence, s.location, COALESCE(s.port, 0), COALESCE(s.transport, ''), s.evidence,
			p.id, p.name, p.vendor, v.id, v.raw, v.qualifier,
			m.cve_id, COALESCE(m.affected_id, 0), m.range_text, m.all_versions, m.adjustment, m.reasons,
			m.condition_product_id::text,
			(m.condition_product_id IS NOT NULL AND EXISTS (
				SELECT 1 FROM asset_software c
				WHERE c.tenant_id = s.tenant_id AND c.asset_id = s.asset_id
				  AND c.product_id = m.condition_product_id AND c.superseded_at IS NULL)),
			r.description, COALESCE(r.severity, ''), r.cvss_score, COALESCE(r.cvss_vector, ''), r.cwes,
			(k.cve_id IS NOT NULL), COALESCE(e.epss_score, 0)
		FROM asset_software s
		JOIN assets a ON a.id = s.asset_id AND a.tenant_id = s.tenant_id
		JOIN software_products p ON p.id = s.product_id
		JOIN software_versions v ON v.id = s.software_version_id
		JOIN software_version_vulns m ON m.software_version_id = s.software_version_id
		JOIN cve_records r ON r.cve_id = m.cve_id AND r.status <> 'Rejected'
		LEFT JOIN kev_catalog k ON k.cve_id = m.cve_id
		LEFT JOIN epss_scores e ON e.cve_id = m.cve_id
		WHERE `+where+`
		ORDER BY s.asset_id, m.cve_id
		LIMIT $3`, a1, a2, limit)
	if err != nil {
		return nil, fmt.Errorf("tenant matches: %w", err)
	}
	defer rows.Close()
	var out []softwarematch.Match
	for rows.Next() {
		var m softwarematch.Match
		var asset, pid, vid string
		var cond sql.NullString
		var desc sql.NullString
		var score sql.NullFloat64
		var reasons, cwes []string
		if err := rows.Scan(&asset, &m.InternetFacing, &m.LinkConfidence, &m.Location, &m.Port, &m.Transport, &m.Evidence,
			&pid, &m.Product, &m.Vendor, &vid, &m.Version, &m.Qualifier,
			&m.Result.CVEID, &m.Result.AffectedID, &m.Result.RangeText, &m.Result.AllVersions, &m.Result.Adjustment,
			pq.Array(&reasons), &cond, &m.ConditionMet,
			&desc, &m.CVE.Severity, &score, &m.CVE.CVSSVector, pq.Array(&cwes),
			&m.CVE.InKEV, &m.CVE.EPSS); err != nil {
			return nil, fmt.Errorf("tenant matches: %w", err)
		}
		m.AssetID, m.ProductID, m.VersionID = shared.MustIDFromString(asset), shared.MustIDFromString(pid), shared.MustIDFromString(vid)
		m.Result.Reasons = reasons
		if cond.Valid {
			id := shared.MustIDFromString(cond.String)
			m.Result.ConditionProductID = &id
		}
		m.CVE.ID = m.Result.CVEID
		m.CVE.Description = desc.String
		if score.Valid {
			s := score.Float64
			m.CVE.CVSSScore = &s
		}
		m.CVE.CWEs = cwes
		out = append(out, m)
	}
	return out, rows.Err()
}

// MatcherFindings (see softwarematch.Store).
func (r *SoftwareMatchRepository) MatcherFindings(ctx context.Context, tenantID shared.ID) ([]softwarematch.MatcherFinding, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id, f.asset_id, COALESCE(f.cve_id, ''), f.fingerprint, f.status,
			f.metadata->'version_match'->>'product_id', f.metadata->'version_match'->>'version_id',
			COALESCE(f.metadata->'version_match'->>'location', ''), COALESCE(r.status = 'Rejected', false)
		FROM findings f
		LEFT JOIN cve_records r ON r.cve_id = f.cve_id
		WHERE f.tenant_id = $1 AND `+matcherOwnedSQL+` AND f.asset_id IS NOT NULL
		LIMIT 200000`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("matcher findings: %w", err)
	}
	defer rows.Close()
	var out []softwarematch.MatcherFinding
	for rows.Next() {
		var f softwarematch.MatcherFinding
		var id, asset string
		var pid, vid sql.NullString
		if err := rows.Scan(&id, &asset, &f.CVEID, &f.Fingerprint, &f.Status, &pid, &vid, &f.Location, &f.CVERejected); err != nil {
			return nil, fmt.Errorf("matcher findings: %w", err)
		}
		f.ID, f.AssetID = shared.MustIDFromString(id), shared.MustIDFromString(asset)
		if p, err := shared.IDFromString(pid.String); pid.Valid && err == nil {
			f.ProductID = &p
		}
		if v, err := shared.IDFromString(vid.String); vid.Valid && err == nil {
			f.VersionID = &v
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// OpenCVEsOnAssets (see softwarematch.Store).
func (r *SoftwareMatchRepository) OpenCVEsOnAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]map[string]bool, error) {
	out := map[shared.ID]map[string]bool{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		ids[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.asset_id, upper(f.cve_id) FROM findings f
		WHERE f.tenant_id = $1 AND f.asset_id = ANY($2::uuid[]) AND f.cve_id IS NOT NULL AND f.cve_id <> ''
		  AND f.status IN ('new', 'confirmed', 'in_progress', 'fix_applied')`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("open cves: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var asset, cve string
		if err := rows.Scan(&asset, &cve); err != nil {
			return nil, fmt.Errorf("open cves: %w", err)
		}
		a := shared.MustIDFromString(asset)
		if out[a] == nil {
			out[a] = map[string]bool{}
		}
		out[a][cve] = true
	}
	return out, rows.Err()
}

// ExistingFingerprints (see softwarematch.Store).
func (r *SoftwareMatchRepository) ExistingFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(fingerprints) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT fingerprint FROM findings WHERE tenant_id = $1 AND fingerprint = ANY($2)`,
		tenantID.String(), pq.Array(fingerprints))
	if err != nil {
		return nil, fmt.Errorf("existing fingerprints: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, fmt.Errorf("existing fingerprints: %w", err)
		}
		out[fp] = true
	}
	return out, rows.Err()
}

// LinkStates (see softwarematch.Store).
func (r *SoftwareMatchRepository) LinkStates(ctx context.Context, tenantID shared.ID, keys []softwarematch.LinkKey, currentSince time.Time) (map[softwarematch.LinkKey]softwarematch.LinkInfo, error) {
	out := make(map[softwarematch.LinkKey]softwarematch.LinkInfo, len(keys))
	for _, k := range keys {
		var current, other bool
		var evaluated sql.NullBool
		err := r.db.QueryRowContext(ctx, `
			SELECT
				EXISTS (SELECT 1 FROM asset_software WHERE tenant_id = $1 AND asset_id = $2 AND product_id = $3
					AND software_version_id = $4 AND location = $5 AND superseded_at IS NULL AND last_seen_at >= $6),
				EXISTS (SELECT 1 FROM asset_software WHERE tenant_id = $1 AND asset_id = $2 AND product_id = $3
					AND software_version_id <> $4 AND location = $5 AND superseded_at IS NULL AND last_seen_at >= $6),
				(SELECT matched_at IS NOT NULL FROM software_versions WHERE id = $4 AND (tenant_id IS NULL OR tenant_id = $1))`,
			tenantID.String(), k.AssetID.String(), k.ProductID.String(), k.VersionID.String(), k.Location, currentSince).
			Scan(&current, &other, &evaluated)
		if err != nil {
			return nil, fmt.Errorf("link state: %w", err)
		}
		info := softwarematch.LinkInfo{State: softwarematch.LinkGone, VersionEvaluated: evaluated.Valid && evaluated.Bool}
		switch {
		case current:
			info.State = softwarematch.LinkCurrent
		case other:
			info.State = softwarematch.LinkUpgraded
		}
		out[k] = info
	}
	return out, nil
}

// CloseFindings (see softwarematch.Store). The status re-check in the
// UPDATE leaves alone a finding someone triaged, or a scanner reported,
// since it was read.
func (r *SoftwareMatchRepository) CloseFindings(ctx context.Context, tenantID shared.ID, ids []shared.ID, kind softwarematch.CloseKind) ([]shared.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var set, from string
	switch kind {
	case softwarematch.CloseVersionChanged:
		set, from = `status = 'resolved', resolution = 'auto_fixed', resolution_method = 'version_changed', resolved_at = NOW()`, autoResolveFromSQL
	case softwarematch.CloseNotObserved:
		set, from = `status = 'not_observed'`, staleFromSQL
	case softwarematch.CloseAdvisoryUpdated:
		set, from = `status = 'false_positive', resolution = 'advisory_updated', resolution_method = 'advisory_updated', resolved_at = NOW()`, vexFalsePositiveFromSQL
	default:
		return nil, fmt.Errorf("unknown close kind %q", kind)
	}
	if autoResolvePaused(ctx, r.db, tenantID.String()) {
		return nil, nil
	}
	return r.updateFindings(ctx, `
		UPDATE findings f SET `+set+`, updated_at = NOW()
		WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[]) AND `+matcherOwnedSQL+`
		  AND f.status IN `+from+`
		RETURNING f.id::text`, tenantID, ids)
}

// ReopenFindings (see softwarematch.Store): only findings the matcher itself
// closed (not observed, or resolved because the version changed).
func (r *SoftwareMatchRepository) ReopenFindings(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]shared.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return r.updateFindings(ctx, `
		UPDATE findings f SET status = 'confirmed', resolution = NULL, resolution_method = NULL,
			resolved_at = NULL, updated_at = NOW()
		WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[]) AND `+matcherOwnedSQL+`
		  AND f.status IN `+regressionReopenFromSQL+`
		  AND (f.status = 'not_observed' OR f.resolution_method = 'version_changed')
		RETURNING f.id::text`, tenantID, ids)
}

func (r *SoftwareMatchRepository) updateFindings(ctx context.Context, query string, tenantID shared.ID, ids []shared.ID) ([]shared.ID, error) {
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(strs))
	if err != nil {
		return nil, fmt.Errorf("matcher findings update: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("matcher findings update: %w", err)
		}
		out = append(out, shared.MustIDFromString(s))
	}
	return out, rows.Err()
}

// EnsureDefinitions (see softwarematch.Store): a CVE nobody reported yet
// gets its global catalog row from the corpus (origin nvd); an existing row
// is left as it is.
func (r *SoftwareMatchRepository) EnsureDefinitions(ctx context.Context, cves []softwarematch.CVEInfo) (map[string]shared.ID, error) {
	out := map[string]shared.ID{}
	if len(cves) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(cves))
	for _, c := range cves {
		ids = append(ids, c.ID)
	}
	if _, err := r.db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (cve_id, external_id, namespace, kind, title, description, severity,
			cvss_score, cvss_vector, cvss_version, published_at, modified_at, origin,
			epss_score, epss_percentile, cisa_kev_date_added, cisa_kev_due_date, exploit_available)
		SELECT c.cve_id, c.cve_id, 'CVE', 'vulnerability', LEFT(c.cve_id, 500), c.description,
			CASE WHEN c.severity IN ('critical', 'high', 'medium', 'low') THEN c.severity
			     WHEN c.severity = 'none' THEN 'info' ELSE 'unknown' END,
			c.cvss_score, c.cvss_vector, c.cvss_version, c.published_at, c.last_modified_at, 'nvd',
			e.epss_score, e.percentile, k.date_added::timestamptz, k.due_date::timestamptz, (k.cve_id IS NOT NULL)
		FROM cve_records c
		LEFT JOIN epss_scores e ON e.cve_id = c.cve_id
		LEFT JOIN kev_catalog k ON k.cve_id = c.cve_id
		WHERE c.cve_id = ANY($1)
		ON CONFLICT (cve_id) DO NOTHING`, pq.Array(ids)); err != nil {
		return nil, fmt.Errorf("ensure definitions: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, cve_id FROM vulnerabilities WHERE cve_id = ANY($1) AND tenant_id IS NULL`, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("ensure definitions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, cve string
		if err := rows.Scan(&id, &cve); err != nil {
			return nil, fmt.Errorf("ensure definitions: %w", err)
		}
		out[cve] = shared.MustIDFromString(id)
	}
	return out, rows.Err()
}
