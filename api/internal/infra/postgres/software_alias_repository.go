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

// ApplyFeedAliases (see software.AliasWriter). It runs in one transaction
// under the corpus lock, so it never interleaves with a bundle import of
// another replica, and it drops the importer's product cache (a merged
// product no longer exists).
func (r *CVECorpusRepository) ApplyFeedAliases(ctx context.Context, aliases []software.FeedAlias, maxMerges int) (software.AliasResult, error) {
	var res software.AliasResult
	if len(aliases) > software.MaxFeedAliases {
		return res, fmt.Errorf("%w: %d aliases, at most %d", software.ErrInvalidAlias, len(aliases), software.MaxFeedAliases)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('software:aliases', 66))`); err != nil {
		return res, fmt.Errorf("lock: %w", err)
	}
	requeue := map[string]bool{}
	for _, a := range aliases {
		if a.Validate() != nil {
			// A malformed entry is skipped, never fatal: the rest of the
			// dictionary still applies.
			res.Skipped++
			continue
		}
		if err := applyFeedAlias(ctx, tx, a, &res, requeue); err != nil {
			return res, err
		}
		if res.Merged > maxMerges {
			return res, fmt.Errorf("%w: more than %d", software.ErrMergeLimit, maxMerges)
		}
	}
	if err := requeueCVEs(ctx, tx, requeue); err != nil {
		return res, err
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit: %w", err)
	}
	res.Requeued = len(requeue)
	r.mu.Lock()
	r.products = map[string]string{}
	r.mu.Unlock()
	return res, nil
}

func applyFeedAlias(ctx context.Context, tx *sql.Tx, a software.FeedAlias, res *software.AliasResult, requeue map[string]bool) error {
	target, _ := software.SplitCPEAlias(a.Target)
	var curSource, curProduct string
	err := tx.QueryRowContext(ctx, `SELECT source, product_id FROM software_product_aliases
		WHERE tenant_id IS NULL AND kind = $1 AND value = $2`, a.Kind, a.Value).Scan(&curSource, &curProduct)
	switch {
	case err == nil && curSource == aliasSourceCurated:
		res.Skipped++
		return nil
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("alias %s: %w", a.Value, err)
	}
	// The product the value names today (kind cpe: a product with that CPE
	// identity; kind purl: a global product with that package identity).
	from, fromSource, err := productNamedBy(ctx, tx, a)
	if err != nil {
		return err
	}
	if from != "" && fromSource == aliasSourceCurated {
		res.Skipped++
		return nil
	}
	into, err := canonicalProduct(ctx, tx, target)
	if err != nil {
		return err
	}
	switch {
	case curProduct == "":
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO software_product_aliases (product_id, tenant_id, kind, value, source)
			VALUES ($1, NULL, $2, $3, 'feed')`, into, a.Kind, a.Value); err != nil {
			return fmt.Errorf("alias %s: %w", a.Value, err)
		}
		res.Written++
	case curProduct != into:
		if _, err := tx.ExecContext(ctx, `UPDATE software_product_aliases SET product_id = $1
			WHERE tenant_id IS NULL AND kind = $2 AND value = $3 AND source = 'feed'`, into, a.Kind, a.Value); err != nil {
			return fmt.Errorf("alias %s: %w", a.Value, err)
		}
		res.Repointed++
	default:
		res.Unchanged++
	}
	if from == "" || from == into {
		return nil
	}
	cves, err := mergeGlobalProduct(ctx, tx, from, into)
	if err != nil {
		return err
	}
	res.Merged++
	for _, c := range cves {
		requeue[c] = true
	}
	return nil
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
// evaluated again and the tenants that run into are queued. It returns the
// CVEs whose ranges moved. Every row it touches keeps its tenant: a link
// or finding is repointed between two global rows, never to another
// tenant.
func mergeGlobalProduct(ctx context.Context, tx *sql.Tx, from, into string) ([]string, error) {
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT count(*) = 2 FROM software_products
		WHERE id IN ($1, $2) AND tenant_id IS NULL`, from, into).Scan(&ok); err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}
	if !ok {
		return nil, errors.New("merge: both products must be global")
	}
	for _, q := range []string{
		`CREATE TEMP TABLE IF NOT EXISTS software_merge_map (old_id UUID PRIMARY KEY, new_id UUID NOT NULL) ON COMMIT DROP`,
		`TRUNCATE software_merge_map`,
	} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return nil, fmt.Errorf("merge map: %w", err)
		}
	}
	steps := []struct{ name, query string }{
		// Versions equal to one of into's: links and findings move to it.
		{"equal versions", `INSERT INTO software_merge_map (old_id, new_id)
			SELECT v.id, w.id FROM software_versions v
			JOIN software_versions w ON w.product_id = $2 AND w.scheme = v.scheme
			 AND COALESCE(w.normalized, 'raw:' || w.raw) = COALESCE(v.normalized, 'raw:' || v.raw)
			 AND w.qualifier = v.qualifier AND w.edition = v.edition
			WHERE v.product_id = $1`},
		{"duplicate links", `DELETE FROM asset_software a USING software_merge_map m
			WHERE a.software_version_id = m.old_id AND EXISTS (SELECT 1 FROM asset_software b
			  WHERE b.tenant_id = a.tenant_id AND b.asset_id = a.asset_id AND b.location = a.location
			    AND b.software_version_id = m.new_id)`},
		{"links", `UPDATE asset_software a SET product_id = $2, software_version_id = m.new_id, updated_at = now()
			FROM software_merge_map m WHERE a.software_version_id = m.old_id`},
		{"findings", `UPDATE findings f SET component_id = m.new_id FROM software_merge_map m WHERE f.component_id = m.old_id`},
		{"versions", `DELETE FROM software_versions WHERE id IN (SELECT old_id FROM software_merge_map)`},
		// The other versions move as they are.
		{"versions", `UPDATE software_versions SET product_id = $2, matched_at = NULL WHERE product_id = $1`},
		{"links", `UPDATE asset_software SET product_id = $2, updated_at = now() WHERE product_id = $1`},
		// into gains ranges: every version of it is evaluated again.
		{"versions", `UPDATE software_versions SET matched_at = NULL WHERE product_id = $2 AND matched_at IS NOT NULL`},
		{"version conditions", `UPDATE software_version_vulns SET condition_product_id = $2 WHERE condition_product_id = $1`},
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
	if _, err := tx.ExecContext(ctx, `DELETE FROM software_products WHERE id = $1 AND tenant_id IS NULL AND source <> 'curated'`, from); err != nil {
		return nil, fmt.Errorf("merge delete: %w", err)
	}
	return cves, nil
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
