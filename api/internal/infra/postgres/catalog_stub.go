package postgres

// Global CVE catalog content comes only from public feeds
// (docs/architecture/global-catalog-trust.md). A tenant report can create an
// identity stub (origin report: title = the id, no description, CVSS,
// references, versions or dates); the CVE corpus import fills it once the
// corpus holds the CVE, and the row then counts as feed-backed (origin nvd).

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
)

// corpusSeveritySQL maps a cve_records severity (alias c) to the catalog's
// severity vocabulary; no corpus row means unknown.
const corpusSeveritySQL = `CASE WHEN c.severity IN ('critical', 'high', 'medium', 'low') THEN c.severity
			     WHEN c.severity = 'none' THEN 'info' ELSE 'unknown' END`

// catalogStubRow selects the identity stubs of the CVE catalog (alias v).
const catalogStubRow = `v.tenant_id IS NULL AND v.cve_id IS NOT NULL AND v.origin = 'report'`

// fillCatalogStubsSQL replaces every shared content column of a stub with the
// corpus record of its CVE (and the CISA KEV name when KEV lists it). The
// columns that only a report could have set are cleared, so no reporter text
// survives the fill. The risk columns (EPSS, KEV dates, exploit flags) are
// already feed-only and are left to ThreatIntelRepository.
const fillCatalogStubsSQL = `
	UPDATE vulnerabilities v SET
		title = LEFT(COALESCE(NULLIF(k.vulnerability_name, ''), c.cve_id), 500),
		description = NULLIF(c.description, ''),
		severity = ` + corpusSeveritySQL + `,
		cvss_score = c.cvss_score, cvss_vector = c.cvss_vector, cvss_version = c.cvss_version,
		published_at = c.published_at, modified_at = c.last_modified_at,
		aliases = '{}', reference_urls = '[]', affected_versions = '[]', fixed_versions = '{}',
		remediation = NULL, origin = 'nvd', updated_at = NOW()
	FROM cve_records c
	LEFT JOIN kev_catalog k ON k.cve_id = c.cve_id
	WHERE v.cve_id = c.cve_id AND ` + catalogStubRow + ` AND c.cve_id = ANY($1)`

type stubExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// fillCatalogStubsFromCorpus fills the identity stubs of the given CVEs from
// the corpus. It runs inside the corpus import transaction, so a stub is
// filled in the same commit that brings its CVE into the corpus.
func fillCatalogStubsFromCorpus(ctx context.Context, db stubExecer, cveIDs []string) (int64, error) {
	if len(cveIDs) == 0 {
		return 0, nil
	}
	res, err := db.ExecContext(ctx, fillCatalogStubsSQL, pq.Array(cveIDs))
	if err != nil {
		return 0, fmt.Errorf("fill catalog stubs: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
