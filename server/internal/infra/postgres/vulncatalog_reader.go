package postgres

// The Postgres reader of the vulnerability catalog
// (docs/rfcs/RFC-143-vulnerability-catalog.md). It reads today's catalog
// tables in the tenant database; the intel database replaces them behind the
// same vulncatalog.Reader. The catalog is public data: every query reads
// global rows only (tenant_id IS NULL), never a tenant-private product or
// alias.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulncatalog"
	"github.com/openctemio/openctem/server/pkg/domain/vulnmatch"
)

// VulnCatalogReader is the vulncatalog.Reader over today's tables.
type VulnCatalogReader struct {
	db *DB
}

var _ vulncatalog.Reader = (*VulnCatalogReader)(nil)

// NewVulnCatalogReader creates the reader.
func NewVulnCatalogReader(db *DB) *VulnCatalogReader { return &VulnCatalogReader{db: db} }

// Mode reports ModeFull: the tables share the tenant database, so a read
// that fails here fails like any other tenant query.
func (r *VulnCatalogReader) Mode() vulncatalog.Mode { return vulncatalog.ModeFull }

// Version is the applied sequence of the vulnerability feed.
func (r *VulnCatalogReader) Version(ctx context.Context) (vulncatalog.Version, error) {
	var seq int64
	err := r.db.QueryRowContext(ctx,
		`SELECT applied_sequence FROM feed_checkpoints WHERE feed = $1`, FeedVulnFeed).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return vulncatalog.Version{}, nil
	}
	if err != nil {
		return vulncatalog.Version{}, fmt.Errorf("vulnerability catalog version: %w", err)
	}
	return vulncatalog.Version{Seq: seq}, nil
}

// ResolveAlias maps a global alias to its global product.
func (r *VulnCatalogReader) ResolveAlias(ctx context.Context, kind, value string) (shared.ID, error) {
	var id string
	err := r.db.QueryRowContext(ctx, `
		SELECT a.product_id FROM software_product_aliases a
		JOIN software_products p ON p.id = a.product_id AND p.tenant_id IS NULL
		WHERE a.tenant_id IS NULL AND a.kind = $1 AND a.value = $2`, kind, value).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return shared.ID{}, vulncatalog.ErrNotFound
	}
	if err != nil {
		return shared.ID{}, fmt.Errorf("vulnerability catalog alias: %w", err)
	}
	return shared.IDFromString(id)
}

// Product reads a global product.
func (r *VulnCatalogReader) Product(ctx context.Context, id shared.ID) (vulncatalog.Product, error) {
	p := vulncatalog.Product{ID: id}
	err := r.db.QueryRowContext(ctx, `
		SELECT part, vendor, name, COALESCE(cpe_vendor, ''), COALESCE(cpe_product, ''),
			COALESCE(purl_type, ''), COALESCE(purl_namespace, ''), COALESCE(purl_name, '')
		FROM software_products WHERE id = $1 AND tenant_id IS NULL`, id.String()).
		Scan(&p.Part, &p.Vendor, &p.Name, &p.CPEVendor, &p.CPEProduct, &p.PurlType, &p.PurlNamespace, &p.PurlName)
	if errors.Is(err, sql.ErrNoRows) {
		return vulncatalog.Product{}, vulncatalog.ErrNotFound
	}
	if err != nil {
		return vulncatalog.Product{}, fmt.Errorf("vulnerability catalog product: %w", err)
	}
	return p, nil
}

// Ranges returns a product's affected statements in id order.
func (r *VulnCatalogReader) Ranges(ctx context.Context, productID shared.ID) ([]vulncatalog.Affected, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, cve_id, scheme, COALESCE(exact_version, ''), COALESCE(v_start, ''), v_start_incl,
			COALESCE(v_end, ''), v_end_incl, edition, target, COALESCE(condition_product_id::text, '')
		FROM vulnerability_affected WHERE product_id = $1 ORDER BY id`, productID.String())
	if err != nil {
		return nil, fmt.Errorf("vulnerability catalog ranges: %w", err)
	}
	defer rows.Close()
	var out []vulncatalog.Affected
	for rows.Next() {
		var a vulncatalog.Affected
		var scheme string
		rg := &a.Range
		if err := rows.Scan(&a.LegacyID, &rg.VulnID, &scheme, &rg.Exact, &rg.Start, &rg.StartIncl,
			&rg.End, &rg.EndIncl, &rg.Edition, &rg.Target, &rg.Condition); err != nil {
			return nil, fmt.Errorf("vulnerability catalog ranges: %w", err)
		}
		rg.Scheme = vulnmatch.Scheme(scheme)
		rg.ID = fmt.Sprint(a.LegacyID)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vulnerability catalog ranges: %w", err)
	}
	return out, nil
}

const vulnCatalogFactColumns = `
	c.cve_id, COALESCE(c.status, ''), COALESCE(c.severity, ''), c.cvss_score::float8,
	COALESCE(c.cvss_version, ''), COALESCE(c.cvss_vector, ''), c.published_at, c.last_modified_at,
	COALESCE(c.cwes, '{}'),
	k.cve_id IS NOT NULL, COALESCE(k.vulnerability_name, ''), COALESCE(k.vendor_project, ''),
	COALESCE(k.product, ''), k.date_added::timestamptz, k.due_date::timestamptz,
	COALESCE(lower(k.known_ransomware_campaign_use) = 'known', false),
	e.epss_score::float8, ec.percentile::float8`

const vulnCatalogFactJoins = `
	FROM cve_records c
	LEFT JOIN kev_catalog k ON k.cve_id = c.cve_id
	LEFT JOIN epss_scores e ON e.cve_id = c.cve_id
	LEFT JOIN epss_percentile_curve ec ON ec.score = e.epss_score`

func scanVulnCatalogFact(sc interface{ Scan(...any) error }, extra ...any) (vulncatalog.Fact, error) {
	var f vulncatalog.Fact
	var cvss, epss, pct sql.NullFloat64
	var published, modified, added, due sql.NullTime
	var cwes []string
	var isKEV, ransomware bool
	var kev vulncatalog.KEV
	dest := make([]any, 0, 18+len(extra))
	dest = append(dest, &f.CVEID, &f.Status, &f.Severity, &cvss, &f.CVSSVersion, &f.CVSSVector, &published, &modified,
		pq.Array(&cwes), &isKEV, &kev.Name, &kev.VendorProject, &kev.Product, &added, &due, &ransomware, &epss, &pct)
	dest = append(dest, extra...)
	if err := sc.Scan(dest...); err != nil {
		return f, err
	}
	f.CVSSScore = nullFloatPtr(cvss)
	f.Published, f.Modified = nullTimeValue(published), nullTimeValue(modified)
	f.CWEs = cwes
	if isKEV {
		kev.CVEID, kev.DateAdded, kev.DueDate, kev.Ransomware = f.CVEID, nullTimeValue(added), nullTimeValue(due), ransomware
		f.KEV = &kev
	}
	if epss.Valid {
		f.EPSS = &vulncatalog.EPSS{CVEID: f.CVEID, Score: epss.Float64, Percentile: nullFloatPtr(pct)}
	}
	return f, nil
}

// Facts returns the facts of the CVEs the catalog has.
func (r *VulnCatalogReader) Facts(ctx context.Context, cveIDs []string) ([]vulncatalog.Fact, error) {
	ids, err := vulncatalog.NormalizeIDs(cveIDs)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+vulnCatalogFactColumns+vulnCatalogFactJoins+`
		WHERE c.cve_id = ANY($1) ORDER BY c.cve_id`, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("vulnerability catalog facts: %w", err)
	}
	defer rows.Close()
	out := make([]vulncatalog.Fact, 0, len(ids))
	for rows.Next() {
		f, err := scanVulnCatalogFact(rows)
		if err != nil {
			return nil, fmt.Errorf("vulnerability catalog facts: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vulnerability catalog facts: %w", err)
	}
	return out, nil
}

// CVE reads one full record.
func (r *VulnCatalogReader) CVE(ctx context.Context, id string) (vulncatalog.CVERecord, error) {
	var rec vulncatalog.CVERecord
	var desc sql.NullString
	row := r.db.QueryRowContext(ctx, `SELECT `+vulnCatalogFactColumns+`, c.description`+vulnCatalogFactJoins+`
		WHERE c.cve_id = $1`, normalizeVulnID(id))
	f, err := scanVulnCatalogFact(row, &desc)
	if errors.Is(err, sql.ErrNoRows) {
		return rec, vulncatalog.ErrNotFound
	}
	if err != nil {
		return rec, fmt.Errorf("vulnerability catalog record: %w", err)
	}
	rec.Fact, rec.Description = f, desc.String
	return rec, nil
}

// CanonicalVulnID resolves an alias to its CVE id; an id with no alias is
// its own canonical id.
func (r *VulnCatalogReader) CanonicalVulnID(ctx context.Context, id string) (string, error) {
	n := normalizeVulnID(id)
	if n == "" {
		return "", fmt.Errorf("%w: empty vulnerability id", shared.ErrValidation)
	}
	var cve string
	err := r.db.QueryRowContext(ctx, `SELECT cve_id FROM vuln_id_aliases WHERE alias_id = $1`, n).Scan(&cve)
	if errors.Is(err, sql.ErrNoRows) {
		return n, nil
	}
	if err != nil {
		return "", fmt.Errorf("vulnerability catalog alias id: %w", err)
	}
	return cve, nil
}

// KEVSet returns the whole known-exploited set.
func (r *VulnCatalogReader) KEVSet(ctx context.Context) (map[string]vulncatalog.KEV, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT cve_id, COALESCE(vulnerability_name, ''), COALESCE(vendor_project, ''), COALESCE(product, ''),
			date_added::timestamptz, due_date::timestamptz,
			COALESCE(lower(known_ransomware_campaign_use) = 'known', false)
		FROM kev_catalog`)
	if err != nil {
		return nil, fmt.Errorf("vulnerability catalog kev: %w", err)
	}
	defer rows.Close()
	out := map[string]vulncatalog.KEV{}
	for rows.Next() {
		var k vulncatalog.KEV
		var added, due sql.NullTime
		if err := rows.Scan(&k.CVEID, &k.Name, &k.VendorProject, &k.Product, &added, &due, &k.Ransomware); err != nil {
			return nil, fmt.Errorf("vulnerability catalog kev: %w", err)
		}
		k.DateAdded, k.DueDate = nullTimeValue(added), nullTimeValue(due)
		out[k.CVEID] = k
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vulnerability catalog kev: %w", err)
	}
	return out, nil
}

// EPSS returns the scores of the CVEs that have one.
func (r *VulnCatalogReader) EPSS(ctx context.Context, cveIDs []string) ([]vulncatalog.EPSS, error) {
	ids, err := vulncatalog.NormalizeIDs(cveIDs)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT e.cve_id, e.epss_score::float8, ec.percentile::float8
		FROM epss_scores e LEFT JOIN epss_percentile_curve ec ON ec.score = e.epss_score
		WHERE e.cve_id = ANY($1) ORDER BY e.cve_id`, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("vulnerability catalog epss: %w", err)
	}
	defer rows.Close()
	out := make([]vulncatalog.EPSS, 0, len(ids))
	for rows.Next() {
		var e vulncatalog.EPSS
		var pct sql.NullFloat64
		if err := rows.Scan(&e.CVEID, &e.Score, &pct); err != nil {
			return nil, fmt.Errorf("vulnerability catalog epss: %w", err)
		}
		e.Percentile = nullFloatPtr(pct)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vulnerability catalog epss: %w", err)
	}
	return out, nil
}

func normalizeVulnID(id string) string {
	ids, _ := vulncatalog.NormalizeIDs([]string{id})
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}
