package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// FindingRemediationKeyRepository owns the finding_remediation_keys side-table
// (RFC-015). It never reads or writes the findings table itself — group queries
// JOIN to findings read-only for status/severity/asset rollups.
type FindingRemediationKeyRepository struct {
	db *DB
}

// NewFindingRemediationKeyRepository constructs the repository.
func NewFindingRemediationKeyRepository(db *DB) *FindingRemediationKeyRepository {
	return &FindingRemediationKeyRepository{db: db}
}

var _ remediation.KeyRepository = (*FindingRemediationKeyRepository)(nil)

// Upsert records or refreshes a finding's remediation key (idempotent on finding_id).
func (r *FindingRemediationKeyRepository) Upsert(ctx context.Context, tenantID, findingID shared.ID, key, title string) error {
	const q = `
		INSERT INTO finding_remediation_keys (finding_id, tenant_id, remediation_key, title, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (finding_id)
		DO UPDATE SET remediation_key = EXCLUDED.remediation_key,
		              title = EXCLUDED.title,
		              updated_at = NOW()`
	if _, err := r.db.ExecContext(ctx, q, findingID.String(), tenantID.String(), key, title); err != nil {
		return fmt.Errorf("upsert remediation key: %w", err)
	}
	return nil
}

// Delete removes a finding's key.
func (r *FindingRemediationKeyRepository) Delete(ctx context.Context, tenantID, findingID shared.ID) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM finding_remediation_keys WHERE tenant_id = $1 AND finding_id = $2`,
		tenantID.String(), findingID.String()); err != nil {
		return fmt.Errorf("delete remediation key: %w", err)
	}
	return nil
}

// ListGroups rolls up the tenant's open, non-pentest findings by remediation
// key, over the findings in scope (nil = all).
func (r *FindingRemediationKeyRepository) ListGroups(ctx context.Context, tenantID shared.ID, excludeStatuses []string, scope *shared.DataScope) ([]remediation.Group, error) {
	scopeCond, args := dataScopeCond("f.asset_id", scope, []any{tenantID.String(), pq.Array(excludeStatuses)})
	q := `
		SELECT frk.remediation_key,
		       MAX(frk.title) AS title,
		       COUNT(*)::int AS finding_count,
		       COUNT(DISTINCT f.asset_id)::int AS asset_count,
		       COUNT(*) FILTER (WHERE f.severity = 'critical')::int AS crit,
		       COUNT(*) FILTER (WHERE f.severity = 'high')::int AS high,
		       COUNT(*) FILTER (WHERE f.severity = 'medium')::int AS medium,
		       COUNT(*) FILTER (WHERE f.severity = 'low')::int AS low,
		       COUNT(*) FILTER (WHERE f.severity IN ('info', 'none'))::int AS info
		FROM finding_remediation_keys frk
		JOIN findings f ON f.id = frk.finding_id AND f.tenant_id = frk.tenant_id
		WHERE frk.tenant_id = $1
		  AND f.source <> 'pentest'
		  AND f.status <> ALL($2::text[])
		  AND ` + scopeCond + `
		GROUP BY frk.remediation_key
		ORDER BY finding_count DESC`

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list remediation groups: %w", err)
	}
	defer func() { _ = rows.Close() }()

	groups := make([]remediation.Group, 0)
	for rows.Next() {
		var (
			g                          remediation.Group
			crit, high, med, low, info int
		)
		if err := rows.Scan(&g.Key, &g.Title, &g.FindingCount, &g.AssetCount, &crit, &high, &med, &low, &info); err != nil {
			return nil, err
		}
		g.SeverityCounts = map[string]int{
			"critical": crit, "high": high, "medium": med, "low": low, "info": info,
		}
		g.FixAvailable = true // a group is, by construction, an actionable fix
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// OpenFindingIDs returns the open, non-pentest finding IDs in a group that are
// in scope (nil = all).
func (r *FindingRemediationKeyRepository) OpenFindingIDs(ctx context.Context, tenantID shared.ID, key string, excludeStatuses []string, scope *shared.DataScope) ([]shared.ID, error) {
	scopeCond, args := dataScopeCond("f.asset_id", scope, []any{tenantID.String(), key, pq.Array(excludeStatuses)})
	q := `
		SELECT f.id
		FROM finding_remediation_keys frk
		JOIN findings f ON f.id = frk.finding_id AND f.tenant_id = frk.tenant_id
		WHERE frk.tenant_id = $1
		  AND frk.remediation_key = $2
		  AND f.source <> 'pentest'
		  AND f.status <> ALL($3::text[])
		  AND ` + scopeCond

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("open finding ids by key: %w", err)
	}
	defer func() { _ = rows.Close() }()

	ids := make([]shared.ID, 0)
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// CountByKey returns (total, resolved) non-pentest findings sharing the key —
// total across every status, resolved being those whose status is in
// closedStatuses. Single round trip via FILTER so a keyed campaign's progress
// stays a cheap side-table rollup.
func (r *FindingRemediationKeyRepository) CountByKey(ctx context.Context, tenantID shared.ID, key string, closedStatuses []string) (int64, int64, error) {
	return r.CountByKeyInScope(ctx, tenantID, key, closedStatuses, nil)
}

// CountByKeyInScope is CountByKey over the findings on the scope's assets
// only (a restricted reader's view of a keyed campaign); a nil scope counts
// every finding of the tenant.
func (r *FindingRemediationKeyRepository) CountByKeyInScope(ctx context.Context, tenantID shared.ID, key string, closedStatuses []string, scope *shared.DataScope) (int64, int64, error) {
	args := []any{tenantID.String(), key, pq.Array(closedStatuses)}
	inScope, args := dataScopeCond("f.asset_id", scope, args)
	q := `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE f.status = ANY($3::text[])) AS resolved
		FROM finding_remediation_keys frk
		JOIN findings f ON f.id = frk.finding_id AND f.tenant_id = frk.tenant_id
		WHERE frk.tenant_id = $1
		  AND frk.remediation_key = $2
		  AND f.source <> 'pentest'
		  AND ` + inScope

	var total, resolved int64
	if err := r.db.QueryRowContext(ctx, q, args...).Scan(&total, &resolved); err != nil {
		return 0, 0, fmt.Errorf("count findings by remediation key: %w", err)
	}
	return total, resolved, nil
}

// keySourceSelect reads what a key is derived from: the finding, its package
// version in the software catalog (a global row or this tenant's private one,
// never another tenant's), the global CVE catalog entry and the stored key.
const keySourceSelect = `
	SELECT f.id, f.source, COALESCE(f.finding_type, ''),
	       COALESCE(p.purl_type, ''), COALESCE(p.name, ''), COALESCE(sv.raw, ''),
	       COALESCE(f.metadata->'fixed_versions', '[]'::jsonb)::text,
	       COALESCE(v.fixed_versions, '{}'::text[]),
	       COALESCE(f.type_details->'secret'->>'fingerprint', ''),
	       COALESCE(f.secret_type, ''),
	       COALESCE(f.remediation->>'recommendation', ''),
	       COALESCE(frk.remediation_key, ''), COALESCE(frk.title, ''),
	       COALESCE(f.metadata->'version_match'->>'product', ''),
	       COALESCE(f.metadata->'version_match'->>'version', ''),
	       COALESCE(f.metadata->'version_match'->>'range', '')
	FROM findings f
	LEFT JOIN software_versions sv ON sv.id = f.component_id AND (sv.tenant_id IS NULL OR sv.tenant_id = f.tenant_id)
	LEFT JOIN software_products p ON p.id = sv.product_id AND p.purl_type IS NOT NULL
	          AND (p.tenant_id IS NULL OR p.tenant_id = f.tenant_id)
	LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
	LEFT JOIN finding_remediation_keys frk ON frk.finding_id = f.id AND frk.tenant_id = f.tenant_id
	WHERE f.tenant_id = $1`

// KeySources reads the key inputs of the tenant's findings with these ids.
func (r *FindingRemediationKeyRepository) KeySources(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) ([]remediation.KeySource, error) {
	if len(findingIDs) == 0 {
		return nil, nil
	}
	ids := make([]string, len(findingIDs))
	for i, id := range findingIDs {
		ids[i] = id.String()
	}
	return r.keySources(ctx, keySourceSelect+` AND f.id = ANY($2::uuid[])`, tenantID.String(), pq.Array(ids))
}

// KeySourcesByFingerprints reads the key inputs of the tenant's findings with
// these fingerprints.
func (r *FindingRemediationKeyRepository) KeySourcesByFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) ([]remediation.KeySource, error) {
	if len(fingerprints) == 0 {
		return nil, nil
	}
	return r.keySources(ctx, keySourceSelect+` AND f.fingerprint = ANY($2::text[])`, tenantID.String(), pq.Array(fingerprints))
}

func (r *FindingRemediationKeyRepository) keySources(ctx context.Context, q string, args ...any) ([]remediation.KeySource, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("read remediation key sources: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []remediation.KeySource
	for rows.Next() {
		var (
			id, metaFixed                 string
			vmProduct, vmVersion, vmRange string
			catalogFixed                  pq.StringArray
			ks                            remediation.KeySource
		)
		in := &ks.Input
		if err := rows.Scan(&id, &in.Source, &in.FindingType, &in.Ecosystem, &in.PackageName, &in.InstalledVersion,
			&metaFixed, &catalogFixed, &in.SecretFingerprint, &in.SecretType, &in.SolutionText,
			&ks.CurrentKey, &ks.CurrentTitle, &vmProduct, &vmVersion, &vmRange); err != nil {
			return nil, fmt.Errorf("scan remediation key source: %w", err)
		}
		if in.Ecosystem != "" {
			in.Ecosystem = software.EcosystemForType(in.Ecosystem)
		}
		fid, err := shared.IDFromString(id)
		if err != nil {
			return nil, fmt.Errorf("scan remediation key source: %w", err)
		}
		ks.FindingID = fid
		var fromFinding []string
		// A malformed metadata value is ignored: the catalog list still applies.
		_ = json.Unmarshal([]byte(metaFixed), &fromFinding)
		// A catalog entry may hold several release lines in one string
		// ("5.2.8, 4.2.30"), so it is split like a scanner's single value.
		in.FixedVersions = vulnerability.NormalizeFixedVersions(strings.Join(catalogFixed, ","), fromFinding)
		// A version-based match (no package record): the matched product and
		// version, and the fix the matching range names ("< 1.20.1").
		if in.PackageName == "" && vmProduct != "" {
			in.Ecosystem, in.PackageName, in.InstalledVersion = "cpe", vmProduct, vmVersion
			if fix := vulnmatch.FixedVersionFromDescription(vmRange); fix != "" {
				in.FixedVersions = vulnerability.NormalizeFixedVersions(fix, in.FixedVersions)
			}
		}
		out = append(out, ks)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read remediation key sources: %w", err)
	}
	return out, nil
}

// FindingIDsAfter pages through the tenant's finding ids in id order.
func (r *FindingRemediationKeyRepository) FindingIDsAfter(ctx context.Context, tenantID, after shared.ID, limit int) ([]shared.ID, error) {
	const q = `SELECT id FROM findings WHERE tenant_id = $1 AND id > $2 ORDER BY id LIMIT $3`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), after.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("page finding ids: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]shared.ID, 0, limit)
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("page finding ids: %w", err)
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, fmt.Errorf("page finding ids: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// TenantsWithFindings lists the tenants that have at least one finding.
func (r *FindingRemediationKeyRepository) TenantsWithFindings(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM findings ORDER BY tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("list tenants with findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("list tenants with findings: %w", err)
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, fmt.Errorf("list tenants with findings: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CampaignsTrackingKeys lists the tenant's campaigns that track one of keys.
func (r *FindingRemediationKeyRepository) CampaignsTrackingKeys(ctx context.Context, tenantID shared.ID, keys []string) ([]remediation.CampaignKeyRef, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	return r.campaignRefs(ctx, `
		SELECT id, name, finding_filter->>'remediation_key'
		FROM remediation_campaigns
		WHERE tenant_id = $1 AND finding_filter->>'remediation_key' = ANY($2::text[])
		ORDER BY id`, tenantID.String(), pq.Array(keys))
}

// CampaignsWithStaleKey lists the tenant's campaigns tracking a key no
// finding of the tenant has.
func (r *FindingRemediationKeyRepository) CampaignsWithStaleKey(ctx context.Context, tenantID shared.ID) ([]remediation.CampaignKeyRef, error) {
	return r.campaignRefs(ctx, `
		SELECT c.id, c.name, c.finding_filter->>'remediation_key'
		FROM remediation_campaigns c
		WHERE c.tenant_id = $1 AND COALESCE(c.finding_filter->>'remediation_key', '') <> ''
		  AND NOT EXISTS (SELECT 1 FROM finding_remediation_keys frk
		                  WHERE frk.tenant_id = c.tenant_id AND frk.remediation_key = c.finding_filter->>'remediation_key')
		ORDER BY c.id`, tenantID.String())
}

// RetargetCampaignKey moves a campaign of the tenant from oldKey to newKey,
// only while it still tracks oldKey.
func (r *FindingRemediationKeyRepository) RetargetCampaignKey(ctx context.Context, tenantID, campaignID shared.ID, oldKey, newKey string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE remediation_campaigns
		SET finding_filter = jsonb_set(finding_filter, '{remediation_key}', to_jsonb($4::text)), updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND finding_filter->>'remediation_key' = $3`,
		tenantID.String(), campaignID.String(), oldKey, newKey)
	if err != nil {
		return false, fmt.Errorf("retarget campaign key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("retarget campaign key: %w", err)
	}
	return n > 0, nil
}

func (r *FindingRemediationKeyRepository) campaignRefs(ctx context.Context, q string, args ...any) ([]remediation.CampaignKeyRef, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list campaigns by remediation key: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []remediation.CampaignKeyRef
	for rows.Next() {
		var id string
		var ref remediation.CampaignKeyRef
		if err := rows.Scan(&id, &ref.Name, &ref.Key); err != nil {
			return nil, fmt.Errorf("list campaigns by remediation key: %w", err)
		}
		if ref.ID, err = shared.IDFromString(id); err != nil {
			return nil, fmt.Errorf("list campaigns by remediation key: %w", err)
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}
