package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// CVECorpusRepository writes the platform-wide CVE corpus (RFC-066 §5.3):
// cve_records, vulnerability_affected and the global catalog products the
// ranges name. It holds no tenant data and has no tenant-facing route.
type CVECorpusRepository struct {
	db *DB

	mu       sync.Mutex
	products map[string]string // "part:vendor:product" → global product id
}

// NewCVECorpusRepository creates a CVECorpusRepository.
func NewCVECorpusRepository(db *DB) *CVECorpusRepository {
	return &CVECorpusRepository{db: db, products: map[string]string{}}
}

var _ cvecorpus.Store = (*CVECorpusRepository)(nil)

// maxProductCache bounds the in-memory product id cache.
const maxProductCache = 200_000

// EmptiedRanges (see cvecorpus.Store).
func (r *CVECorpusRepository) EmptiedRanges(ctx context.Context, cves []cvecorpus.CVE) (int, error) {
	ids := make([]string, 0, len(cves))
	for _, c := range cves {
		if !c.Rejected && !c.TooManyRanges && len(c.Ranges) == 0 {
			ids = append(ids, c.ID)
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM vulnerability_affected WHERE cve_id = ANY($1)`,
		pq.Array(ids)).Scan(&n); err != nil {
		return 0, fmt.Errorf("count emptied ranges: %w", err)
	}
	return n, nil
}

// Counts (see cvecorpus.Store).
func (r *CVECorpusRepository) Counts(ctx context.Context) (records, ranges int, err error) {
	err = r.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM cve_records), (SELECT count(*) FROM vulnerability_affected)`).
		Scan(&records, &ranges)
	if err != nil {
		return 0, 0, fmt.Errorf("corpus counts: %w", err)
	}
	return records, ranges, nil
}

// ApplyPage (see cvecorpus.Store).
func (r *CVECorpusRepository) ApplyPage(ctx context.Context, cves []cvecorpus.CVE) (cvecorpus.PageResult, error) {
	var res cvecorpus.PageResult
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	created := map[string]string{}
	for _, c := range cves {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM cve_records WHERE cve_id = $1)`, c.ID).Scan(&exists); err != nil {
			return res, fmt.Errorf("cve %s: %w", c.ID, err)
		}
		if !exists && len(c.Ranges) == 0 {
			res.Skipped++
			continue
		}
		if err := upsertCVERecord(ctx, tx, c); err != nil {
			return res, err
		}
		res.Upserted++
		if c.TooManyRanges {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM vulnerability_affected WHERE cve_id = $1`, c.ID); err != nil {
			return res, fmt.Errorf("cve %s ranges: %w", c.ID, err)
		}
		if c.Rejected || len(c.Ranges) == 0 {
			continue
		}
		n, err := r.insertRanges(ctx, tx, c, created)
		if err != nil {
			return res, err
		}
		res.RangesWritten += n
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit: %w", err)
	}
	r.mu.Lock()
	if len(r.products)+len(created) > maxProductCache {
		r.products = map[string]string{}
	}
	for k, v := range created {
		r.products[k] = v
	}
	r.mu.Unlock()
	return res, nil
}

func upsertCVERecord(ctx context.Context, tx *sql.Tx, c cvecorpus.CVE) error {
	var score any
	if c.CVSSScore != nil {
		score = *c.CVSSScore
	}
	cwes := c.CWEs
	if cwes == nil {
		cwes = []string{}
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO cve_records (cve_id, status, published_at, last_modified_at, description,
			cvss_score, cvss_version, cvss_vector, severity, cwes, synced_at)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), $10, now())
		ON CONFLICT (cve_id) DO UPDATE SET
			status = EXCLUDED.status, published_at = EXCLUDED.published_at,
			last_modified_at = EXCLUDED.last_modified_at, description = EXCLUDED.description,
			cvss_score = EXCLUDED.cvss_score, cvss_version = EXCLUDED.cvss_version,
			cvss_vector = EXCLUDED.cvss_vector, severity = EXCLUDED.severity, cwes = EXCLUDED.cwes,
			synced_at = now()`,
		c.ID, c.Status, c.Published, c.LastModified, c.Description, score,
		c.CVSSVersion, c.CVSSVector, c.Severity, pq.Array(cwes))
	if err != nil {
		return fmt.Errorf("cve %s record: %w", c.ID, err)
	}
	return nil
}

func (r *CVECorpusRepository) insertRanges(ctx context.Context, tx *sql.Tx, c cvecorpus.CVE, created map[string]string) (int, error) {
	n := len(c.Ranges)
	products := make([]string, 0, n)
	conditions := make([]sql.NullString, 0, n)
	schemes := make([]string, 0, n)
	exact := make([]sql.NullString, 0, n)
	starts := make([]sql.NullString, 0, n)
	startIncl := make([]bool, 0, n)
	ends := make([]sql.NullString, 0, n)
	endIncl := make([]bool, 0, n)
	editions := make([]string, 0, n)
	targets := make([]string, 0, n)
	sources := make([]string, 0, n)
	for _, rg := range c.Ranges {
		pid, err := r.globalProduct(ctx, tx, rg.Product, created)
		if err != nil {
			return 0, err
		}
		var cond sql.NullString
		if rg.Condition != nil {
			cid, err := r.globalProduct(ctx, tx, *rg.Condition, created)
			if err != nil {
				return 0, err
			}
			cond = sql.NullString{String: cid, Valid: true}
		}
		products = append(products, pid)
		conditions = append(conditions, cond)
		scheme := string(rg.Range.Scheme)
		if scheme == "" {
			scheme = string(vulnmatch.SchemeGeneric)
		}
		schemes = append(schemes, scheme)
		exact = append(exact, nullStr(rg.Range.Exact))
		starts = append(starts, nullStr(rg.Range.Start))
		startIncl = append(startIncl, rg.Range.StartIncl)
		ends = append(ends, nullStr(rg.Range.End))
		endIncl = append(endIncl, rg.Range.EndIncl)
		editions = append(editions, rg.Range.Edition)
		targets = append(targets, rg.Range.Target)
		src := rg.Source
		if src == "" {
			src = "nvd"
		}
		sources = append(sources, src)
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO vulnerability_affected (cve_id, product_id, condition_product_id, scheme, exact_version,
			v_start, v_start_incl, v_end, v_end_incl, edition, target, source)
		SELECT $1, p, c, s, e, vs, vsi, ve, vei, ed, tg, src
		FROM unnest($2::uuid[], $3::uuid[], $4::text[], $5::text[], $6::text[], $7::bool[], $8::text[], $9::bool[], $10::text[], $11::text[], $12::text[])
			AS t(p, c, s, e, vs, vsi, ve, vei, ed, tg, src)`,
		c.ID, pq.Array(products), pq.Array(conditions), pq.Array(schemes), pq.Array(exact),
		pq.Array(starts), pq.Array(startIncl), pq.Array(ends), pq.Array(endIncl), pq.Array(editions), pq.Array(targets), pq.Array(sources))
	if err != nil {
		return 0, fmt.Errorf("cve %s ranges: %w", c.ID, err)
	}
	return n, nil
}

// globalProduct resolves a CPE to a global catalog product: a global CPE
// alias (curated alternate vendors), then a global product with that CPE,
// else a new global product (source nvd). The bundle is a public source,
// so creating a global row here is allowed.
func (r *CVECorpusRepository) globalProduct(ctx context.Context, tx *sql.Tx, c vulnmatch.CPE, created map[string]string) (string, error) {
	key := c.Part + ":" + c.Vendor + ":" + c.Product
	if id, ok := created[key]; ok {
		return id, nil
	}
	r.mu.Lock()
	id, ok := r.products[key]
	r.mu.Unlock()
	if ok {
		return id, nil
	}
	err := tx.QueryRowContext(ctx, `
		SELECT a.product_id FROM software_product_aliases a
		WHERE a.tenant_id IS NULL AND a.kind = 'cpe' AND a.value = $1`, key).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, `
			INSERT INTO software_products (part, vendor, name, cpe_vendor, cpe_product, source)
			VALUES ($1, $2, $3, $2, $4, 'nvd')
			ON CONFLICT (part, cpe_vendor, cpe_product) WHERE tenant_id IS NULL AND cpe_vendor IS NOT NULL
			DO UPDATE SET updated_at = software_products.updated_at
			RETURNING id`, c.Part, c.Vendor, displayName(c.Product), c.Product).Scan(&id)
	}
	if err != nil {
		return "", fmt.Errorf("product %s: %w", key, err)
	}
	created[key] = id
	return id, nil
}

func displayName(product string) string {
	return clipStr(strings.ReplaceAll(product, "_", " "), 200)
}

func nullStr(s string) sql.NullString {
	s = strings.TrimSpace(s)
	return sql.NullString{String: s, Valid: s != ""}
}
