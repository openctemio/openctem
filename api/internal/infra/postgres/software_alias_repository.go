package postgres

// Feed product aliases and product merges. Design:
// docs/rfcs/RFC-066-inventory-vulnerability-matching.md (§5.5).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/software"
)

const (
	aliasSourceCurated = "curated"
	aliasSourceFeed    = "feed"
)

var _ software.AliasWriter = (*CVECorpusRepository)(nil)

// aliasLocks serializes every writer that can fold catalog products: the
// alias dictionary, the curated list and (through the vulnfeed checkpoint
// row, which every chunk transaction locks) the bundle importer of any
// replica. A fold that ran beside a chunk could delete a product the chunk
// is attaching new ranges to.
func aliasLocks(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('software:aliases', 66))`); err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT 1 FROM feed_checkpoints WHERE feed = $1 FOR UPDATE`, FeedVulnFeed); err != nil {
		return fmt.Errorf("lock feed checkpoint: %w", err)
	}
	return nil
}

// pendingMerge is a fold planned by the first pass.
type pendingMerge struct {
	from, into string
	reason     mergeReason
}

// mergeReason says which entry folded a product (for the journal).
type mergeReason struct{ kind, value, basis string }

// ApplyFeedAliases (see software.AliasWriter). Two passes in one
// transaction: the first writes the aliases and plans the folds (so a
// dictionary over the fold limit is refused before any tenant row is
// touched), the second folds. Tenant rows (links, findings, VEX) are
// therefore locked only for the folds at the end. It drops the importer's
// product cache (a folded product no longer exists).
func (r *CVECorpusRepository) ApplyFeedAliases(ctx context.Context, aliases []software.FeedAlias, maxMerges int) (software.AliasResult, error) {
	var res software.AliasResult
	if len(aliases) > software.MaxFeedAliases {
		return res, fmt.Errorf("%w: %d aliases, at most %d", software.ErrInvalidAlias, len(aliases), software.MaxFeedAliases)
	}
	if len(aliases) == 0 {
		// An empty dictionary would remove every feed alias.
		return res, fmt.Errorf("%w: empty dictionary", software.ErrInvalidAlias)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := aliasLocks(ctx, tx); err != nil {
		return res, err
	}
	var merges []pendingMerge
	keepKinds, keepValues := make([]string, 0, len(aliases)), make([]string, 0, len(aliases))
	for _, a := range aliases {
		if a.Validate() != nil {
			// A malformed entry is skipped, never fatal: the rest of the
			// dictionary still applies.
			res.Skipped++
			continue
		}
		keepKinds, keepValues = append(keepKinds, a.Kind), append(keepValues, a.Value)
		m, err := applyFeedAlias(ctx, tx, a, &res)
		if err != nil {
			return res, err
		}
		if m != nil {
			merges = append(merges, *m)
			if len(merges) > maxMerges {
				return res, fmt.Errorf("%w: more than %d", software.ErrMergeLimit, maxMerges)
			}
		}
	}
	removed, err := tx.ExecContext(ctx, `
		DELETE FROM software_product_aliases a
		WHERE a.tenant_id IS NULL AND a.source = 'feed'
		  AND NOT EXISTS (SELECT 1 FROM unnest($1::text[], $2::text[]) AS k(kind, value)
		                  WHERE k.kind = a.kind AND k.value = a.value)`, pq.Array(keepKinds), pq.Array(keepValues))
	if err != nil {
		return res, fmt.Errorf("remove feed aliases: %w", err)
	}
	if n, err := removed.RowsAffected(); err == nil {
		res.Removed = int(n)
	}
	requeue := map[string]bool{}
	folded := map[string]string{} // folded product → the product it went into
	for _, m := range merges {
		if _, done := folded[m.from]; done {
			continue
		}
		into := m.into
		for hops := 0; folded[into] != "" && hops < len(folded); hops++ {
			into = folded[into]
		}
		if into == m.from {
			continue
		}
		cves, err := mergeGlobalProduct(ctx, tx, m.from, into, m.reason)
		if err != nil {
			return res, err
		}
		folded[m.from] = into
		res.Merged++
		for _, c := range cves {
			requeue[c] = true
		}
	}
	if err := requeueCVEs(ctx, tx, requeue); err != nil {
		return res, err
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit: %w", err)
	}
	res.Requeued = len(requeue)
	r.resetProductCache()
	return res, nil
}

// resetProductCache drops the importer's product id cache.
func (r *CVECorpusRepository) resetProductCache() {
	r.mu.Lock()
	r.products = map[string]string{}
	r.mu.Unlock()
}

// applyFeedAlias writes one valid alias and returns the fold it calls for
// (nil: none).
func applyFeedAlias(ctx context.Context, tx *sql.Tx, a software.FeedAlias, res *software.AliasResult) (*pendingMerge, error) {
	target, _ := software.SplitCPEAlias(a.Target)
	var curSource, curProduct string
	err := tx.QueryRowContext(ctx, `SELECT source, product_id FROM software_product_aliases
		WHERE tenant_id IS NULL AND kind = $1 AND value = $2`, a.Kind, a.Value).Scan(&curSource, &curProduct)
	switch {
	case err == nil && curSource == aliasSourceCurated:
		res.Skipped++
		return nil, nil
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("alias %s: %w", a.Value, err)
	}
	// The product the value names today (kind cpe: a product with that CPE
	// identity; kind purl: a global product with that package identity).
	from, fromSource, err := productNamedBy(ctx, tx, a)
	if err != nil {
		return nil, err
	}
	if from != "" && fromSource == aliasSourceCurated {
		res.Skipped++
		return nil, nil
	}
	into, err := findCanonicalProduct(ctx, tx, target)
	if err != nil {
		return nil, err
	}
	if from != "" && from != into && !a.Reviewed() {
		// Folding is irreversible for tenant links and findings, and the
		// entry is only evidence. It may fold a product whose ranges all
		// come from CNA names (the feed re-ships those ranges under the
		// canonical product anyway); a product with data of its own
		// (NVD/OSV ranges, range conditions, no ranges at all) waits for a
		// reviewed entry, and its resolution stays as it is.
		ok, err := nameDerivedOnly(ctx, tx, from)
		if err != nil {
			return nil, err
		}
		if !ok {
			res.Held++
			if len(res.HeldValues) < software.MaxHeldValues {
				res.HeldValues = append(res.HeldValues, a.Value+" -> "+a.Target)
			}
			return nil, nil
		}
	}
	if into == "" {
		if into, err = canonicalProduct(ctx, tx, target); err != nil {
			return nil, err
		}
	}
	switch {
	case curProduct == "":
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO software_product_aliases (product_id, tenant_id, kind, value, source)
			VALUES ($1, NULL, $2, $3, 'feed')`, into, a.Kind, a.Value); err != nil {
			return nil, fmt.Errorf("alias %s: %w", a.Value, err)
		}
		res.Written++
	case curProduct != into:
		if _, err := tx.ExecContext(ctx, `UPDATE software_product_aliases SET product_id = $1
			WHERE tenant_id IS NULL AND kind = $2 AND value = $3 AND source = 'feed'`, into, a.Kind, a.Value); err != nil {
			return nil, fmt.Errorf("alias %s: %w", a.Value, err)
		}
		res.Repointed++
	default:
		res.Unchanged++
	}
	if from == "" || from == into {
		return nil, nil
	}
	return &pendingMerge{from: from, into: into, reason: mergeReason{kind: a.Kind, value: a.Value, basis: a.Basis}}, nil
}

// nameDerivedOnly reports whether every range that names the product
// (directly or as a condition) comes from a CNA name (source cve5), and
// it has at least one.
func nameDerivedOnly(ctx context.Context, tx *sql.Tx, product string) (bool, error) {
	var ok bool
	err := tx.QueryRowContext(ctx, `SELECT
		EXISTS (SELECT 1 FROM vulnerability_affected WHERE product_id = $1 AND source = 'cve5')
		AND NOT EXISTS (SELECT 1 FROM vulnerability_affected WHERE product_id = $1 AND source <> 'cve5')
		AND NOT EXISTS (SELECT 1 FROM vulnerability_affected WHERE condition_product_id = $1)`, product).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("product %s ranges: %w", product, err)
	}
	return ok, nil
}

// productNamedBy returns the global product whose own identity is the
// alias value, and its source.
func productNamedBy(ctx context.Context, tx *sql.Tx, a software.FeedAlias) (string, string, error) {
	var id, source string
	var err error
	switch a.Kind {
	case software.AliasKindCPE:
		k, _ := software.SplitCPEAlias(a.Value)
		err = tx.QueryRowContext(ctx, `SELECT id, source FROM software_products
			WHERE tenant_id IS NULL AND part = $1 AND cpe_vendor = $2 AND cpe_product = $3`,
			k.Part, k.Vendor, k.Product).Scan(&id, &source)
	default:
		err = tx.QueryRowContext(ctx, `SELECT id, source FROM software_products
			WHERE tenant_id IS NULL AND purl_type IS NOT NULL
			  AND lower('pkg:' || purl_type || '/' || CASE WHEN purl_namespace = '' THEN '' ELSE purl_namespace || '/' END || purl_name) = $1
			LIMIT 1`, a.Value).Scan(&id, &source)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("alias %s product: %w", a.Value, err)
	}
	return id, source, nil
}

// findCanonicalProduct resolves a CPE identity to its global product (a
// global CPE alias, then the product with that CPE) without creating one
// ("" when none exists).
func findCanonicalProduct(ctx context.Context, tx *sql.Tx, k software.CPEKey) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `
		SELECT id FROM (
			SELECT product_id AS id, 0 AS prio FROM software_product_aliases
			WHERE tenant_id IS NULL AND kind = 'cpe' AND value = $1
			UNION ALL
			SELECT id, 1 FROM software_products
			WHERE tenant_id IS NULL AND part = $2 AND cpe_vendor = $3 AND cpe_product = $4) c
		ORDER BY prio LIMIT 1`, k.String(), k.Part, k.Vendor, k.Product).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("product %s: %w", k, err)
	}
	return id, nil
}

// canonicalProduct resolves a CPE identity to its global product the way
// the importer does (a global CPE alias, then the product with that CPE),
// creating it (source nvd: the feed is a public source) when none exists.
func canonicalProduct(ctx context.Context, tx *sql.Tx, k software.CPEKey) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT product_id FROM software_product_aliases
		WHERE tenant_id IS NULL AND kind = 'cpe' AND value = $1`, k.String()).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, `
			INSERT INTO software_products (part, vendor, name, cpe_vendor, cpe_product, source)
			VALUES ($1, $2, $3, $2, $4, 'nvd')
			ON CONFLICT (part, cpe_vendor, cpe_product) WHERE tenant_id IS NULL AND cpe_vendor IS NOT NULL
			DO UPDATE SET updated_at = software_products.updated_at
			RETURNING id`, k.Part, k.Vendor, displayName(k.Product), k.Product).Scan(&id)
	}
	if err != nil {
		return "", fmt.Errorf("product %s: %w", k, err)
	}
	return id, nil
}

// mergeGlobalProduct folds the global, feed-created product from into the
// global product into: its versions move (or fold into the equal version
// of into), with the links and findings that name them; its ranges, VEX
// statements, bundle keys and aliases move; from is deleted. Versions are
// evaluated again and the tenants that run into are queued. Every fold is
// journaled in software_product_merges (the folded identity, the moved
// version ids and CVEs), so an operator can split a wrong fold. It returns
// the CVEs whose ranges moved. Every row it touches keeps its tenant: a
// link or finding is repointed between two global rows, never to another
// tenant (the catalog scope triggers enforce it as well).
func mergeGlobalProduct(ctx context.Context, tx *sql.Tx, from, into string, why mergeReason) ([]string, error) {
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT count(*) = 2 FROM software_products
		WHERE id IN ($1, $2) AND tenant_id IS NULL`, from, into).Scan(&ok); err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}
	if !ok {
		return nil, errors.New("merge: both products must be global")
	}
	moved, err := unmatchedVersions(ctx, tx, from, into)
	if err != nil {
		return nil, err
	}
	steps := []struct{ name, query string }{
		// Versions equal to one of into's (mergeVersionMap): links and
		// findings move to it.
		{"duplicate links", `DELETE FROM asset_software a USING ` + mergeVersionMap + ` m
			WHERE a.software_version_id = m.old_id AND EXISTS (SELECT 1 FROM asset_software b
			  WHERE b.tenant_id = a.tenant_id AND b.asset_id = a.asset_id AND b.location = a.location
			    AND b.software_version_id = m.new_id)`},
		{"links", `UPDATE asset_software a SET product_id = $2, software_version_id = m.new_id, updated_at = now()
			FROM ` + mergeVersionMap + ` m WHERE a.software_version_id = m.old_id`},
		{"findings", `UPDATE findings f SET component_id = m.new_id FROM ` + mergeVersionMap + ` m WHERE f.component_id = m.old_id`},
		{"versions", `DELETE FROM software_versions WHERE id IN (SELECT old_id FROM ` + mergeVersionMap + ` m)`},
		// The other versions move as they are.
		{"versions", `UPDATE software_versions SET product_id = $2, matched_at = NULL WHERE product_id = $1`},
		{"links", `UPDATE asset_software SET product_id = $2, updated_at = now() WHERE product_id = $1`},
		// into gains ranges: every version of it is evaluated again.
		{"versions", `UPDATE software_versions SET matched_at = NULL WHERE product_id = $2 AND matched_at IS NOT NULL`},
		{"version conditions", `UPDATE software_version_vulns SET condition_product_id = $2 WHERE condition_product_id = $1`},
		// A tenant's statement on into for the same subject wins over the
		// one on from (one statement per subject).
		{"duplicate vex statements", `DELETE FROM vex_statements v USING vex_statements w
			WHERE v.product_id = $1 AND w.product_id = $2 AND w.tenant_id = v.tenant_id AND w.vuln_id = v.vuln_id
			  AND COALESCE(w.asset_id, '00000000-0000-0000-0000-000000000000'::uuid) = COALESCE(v.asset_id, '00000000-0000-0000-0000-000000000000'::uuid)
			  AND w.versions = v.versions AND COALESCE(w.version_range, '') = COALESCE(v.version_range, '')`},
		{"vex statements", `UPDATE vex_statements SET product_id = $2, updated_at = now() WHERE product_id = $1`},
		{"bundle keys", `UPDATE cve_feed_products SET product_id = $2 WHERE product_id = $1`},
		{"aliases", `UPDATE software_product_aliases SET product_id = $2 WHERE product_id = $1 AND tenant_id IS NULL`},
		{"tenants", `INSERT INTO vuln_match_queue (tenant_id)
			SELECT DISTINCT tenant_id FROM asset_software WHERE product_id = $2
			ON CONFLICT (tenant_id) DO NOTHING`},
	}
	for _, s := range steps {
		q, args := mergeStep(s.query, from, into)
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return nil, fmt.Errorf("merge %s: %w", s.name, err)
		}
	}
	cves, err := moveRanges(ctx, tx, from, into)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO software_product_merges (from_product_id, into_product_id, from_identity, from_name, from_source,
			alias_kind, alias_value, basis, moved_version_ids, cve_ids)
		SELECT id, $2, COALESCE(part || ':' || cpe_vendor || ':' || cpe_product,
			'pkg:' || purl_type || '/' || CASE WHEN purl_namespace = '' THEN '' ELSE purl_namespace || '/' END || purl_name, ''),
			name, source, $3, $4, $5, $6, $7
		FROM software_products WHERE id = $1`,
		from, into, why.kind, why.value, why.basis, pq.Array(moved), pq.Array(append([]string{}, cves...))); err != nil {
		return nil, fmt.Errorf("merge journal: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM software_products WHERE id = $1 AND tenant_id IS NULL AND source <> 'curated'`, from); err != nil {
		return nil, fmt.Errorf("merge delete: %w", err)
	}
	return cves, nil
}

// unmatchedVersions returns the versions of from that have no equal
// version in into (they move as they are).
func unmatchedVersions(ctx context.Context, tx *sql.Tx, from, into string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM software_versions v WHERE v.product_id = $1
		AND NOT EXISTS (SELECT 1 FROM `+mergeVersionMap+` m WHERE m.old_id = v.id)`, from, into)
	if err != nil {
		return nil, fmt.Errorf("merge versions: %w", err)
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("merge versions: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("merge versions: %w", err)
	}
	return ids, nil
}

// requeueCVEs moves the feed cursor of the CVEs whose ranges moved, so the
// matcher evaluates the versions of their products again.
func requeueCVEs(ctx context.Context, tx *sql.Tx, set map[string]bool) error {
	if len(set) == 0 {
		return nil
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE cve_records SET synced_at = clock_timestamp() WHERE cve_id = ANY($1)`, pq.Array(ids)); err != nil {
		return fmt.Errorf("requeue cves: %w", err)
	}
	return nil
}

// mergeVersionMap pairs each version of from ($1) with the equal version of
// into ($2): same scheme, normalized (or raw) version, qualifier and
// edition.
const mergeVersionMap = `(SELECT v.id AS old_id, w.id AS new_id FROM software_versions v
	JOIN software_versions w ON w.product_id = $2 AND w.scheme = v.scheme
	 AND COALESCE(w.normalized, 'raw:' || w.raw) = COALESCE(v.normalized, 'raw:' || v.raw)
	 AND w.qualifier = v.qualifier AND w.edition = v.edition
	WHERE v.product_id = $1)`

// mergeStep returns a merge step with only the parameters it names ($1
// from, $2 into): PostgreSQL cannot type a parameter a statement does not
// use.
func mergeStep(query, from, into string) (string, []any) {
	hasFrom, hasInto := strings.Contains(query, "$1"), strings.Contains(query, "$2")
	switch {
	case hasFrom && hasInto:
		return query, []any{from, into}
	case hasInto:
		return strings.ReplaceAll(query, "$2", "$1"), []any{into}
	case hasFrom:
		return query, []any{from}
	}
	return query, nil
}

func setOf(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// moveRanges repoints the ranges (and range conditions) of from to into and
// returns the CVEs they belong to.
func moveRanges(ctx context.Context, tx *sql.Tx, from, into string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		WITH p AS (UPDATE vulnerability_affected SET product_id = $2 WHERE product_id = $1 RETURNING cve_id),
		     c AS (UPDATE vulnerability_affected SET condition_product_id = $2 WHERE condition_product_id = $1 RETURNING cve_id)
		SELECT cve_id FROM p UNION SELECT cve_id FROM c`, from, into)
	if err != nil {
		return nil, fmt.Errorf("merge ranges: %w", err)
	}
	defer rows.Close()
	var cves []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("merge ranges: %w", err)
		}
		cves = append(cves, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("merge ranges: %w", err)
	}
	return cves, nil
}
