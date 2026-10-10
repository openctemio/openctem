package postgres

// Chunked vulnerability bundles (docs/architecture/feed-transfer.md): every
// chunk upserts its records stamped with the bundle sequence, together with
// the checkpoint, in one transaction; finishing the bundle removes the rows
// of an older sequence the bundle replaced, behind the removal guard, in
// one transaction with the applied sequence. CVEs whose record or ranges
// changed get a new synced_at, which is what the matcher re-evaluates.
// Platform-wide corpus data: nothing here is tenant data.

import (
	"context"
	"database/sql"
	"fmt"
	"math"

	"github.com/lib/pq"
	"github.com/openctemio/sdk-go/pkg/transfer/bundle"

	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// FeedCheckpoint returns the checkpoint of the vulnerability feed.
func (r *CVECorpusRepository) FeedCheckpoint() bundle.Checkpoint { return r.feedCheckpoint() }

func (r *CVECorpusRepository) feedCheckpoint() *FeedCheckpoint {
	return &FeedCheckpoint{db: r.db, feed: FeedVulnFeed}
}

// ApplyFeedChunk applies one chunk and advances the checkpoint to next in
// the same transaction (a committed chunk is never applied twice, and two
// runs never both apply one). Records and ranges stored by a newer
// sequence are kept. A range must name a CVE and products the same bundle
// holds (written by its earlier chunks).
func (r *CVECorpusRepository) ApplyFeedChunk(ctx context.Context, c cvecorpus.Chunk, next bundle.State) (cvecorpus.PageResult, error) {
	var res cvecorpus.PageResult
	if c.Sequence == 0 || c.Sequence != next.InProgress || c.Sequence > math.MaxInt64 {
		return res, fmt.Errorf("chunk sequence %d is not the bundle in progress %d", c.Sequence, next.InProgress)
	}
	seq := int64(c.Sequence)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := r.feedCheckpoint().AdvanceTx(ctx, tx, next); err != nil {
		return res, err
	}
	created := map[string]string{}
	if err := r.upsertFeedProducts(ctx, tx, c.Products, seq, created); err != nil {
		return res, err
	}
	for _, cve := range c.CVEs {
		ok, err := upsertFeedCVE(ctx, tx, cve, seq)
		if err != nil {
			return res, err
		}
		if ok {
			res.Upserted++
		}
	}
	if res.RangesWritten, err = upsertFeedRanges(ctx, tx, c.Ranges, seq); err != nil {
		return res, err
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit: %w", err)
	}
	r.cacheProducts(created)
	return res, nil
}

func (r *CVECorpusRepository) cacheProducts(created map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.products)+len(created) > maxProductCache {
		r.products = map[string]string{}
	}
	for k, v := range created {
		r.products[k] = v
	}
}

// upsertFeedProducts resolves each listed product to a global catalog
// product and records the bundle key → product mapping for the ranges.
func (r *CVECorpusRepository) upsertFeedProducts(ctx context.Context, tx *sql.Tx, products []cvecorpus.Product, seq int64, created map[string]string) error {
	if len(products) == 0 {
		return nil
	}
	keys := make([]string, 0, len(products))
	ids := make([]string, 0, len(products))
	for _, p := range products {
		id, err := r.globalProduct(ctx, tx, p.CPE, created)
		if err != nil {
			return err
		}
		keys, ids = append(keys, p.Key), append(ids, id)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cve_feed_products (product_key, product_id, feed_sequence)
		SELECT k, p, $3 FROM unnest($1::text[], $2::uuid[]) AS t(k, p)
		ON CONFLICT (product_key) DO UPDATE SET product_id = EXCLUDED.product_id, feed_sequence = EXCLUDED.feed_sequence
		WHERE cve_feed_products.feed_sequence <= EXCLUDED.feed_sequence`,
		pq.Array(keys), pq.Array(ids), seq); err != nil {
		return fmt.Errorf("bundle products: %w", err)
	}
	return nil
}

// upsertFeedCVE writes one record unless a newer sequence stored it; its
// synced_at moves only when its content changed. It reports whether the
// row was written.
func upsertFeedCVE(ctx context.Context, tx *sql.Tx, c cvecorpus.CVE, seq int64) (bool, error) {
	var score any
	if c.CVSSScore != nil {
		score = *c.CVSSScore
	}
	cwes := c.CWEs
	if cwes == nil {
		cwes = []string{}
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO cve_records (cve_id, status, published_at, last_modified_at, description,
			cvss_score, cvss_version, cvss_vector, severity, cwes, feed_sequence, synced_at)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), $10, $11, now())
		ON CONFLICT (cve_id) DO UPDATE SET
			status = EXCLUDED.status, published_at = EXCLUDED.published_at,
			last_modified_at = EXCLUDED.last_modified_at, description = EXCLUDED.description,
			cvss_score = EXCLUDED.cvss_score, cvss_version = EXCLUDED.cvss_version,
			cvss_vector = EXCLUDED.cvss_vector, severity = EXCLUDED.severity, cwes = EXCLUDED.cwes,
			feed_sequence = EXCLUDED.feed_sequence,
			synced_at = CASE WHEN (cve_records.status, cve_records.published_at, cve_records.last_modified_at,
				cve_records.description, cve_records.cvss_score, cve_records.cvss_version, cve_records.cvss_vector,
				cve_records.severity, cve_records.cwes) IS DISTINCT FROM (EXCLUDED.status, EXCLUDED.published_at,
				EXCLUDED.last_modified_at, EXCLUDED.description, EXCLUDED.cvss_score, EXCLUDED.cvss_version,
				EXCLUDED.cvss_vector, EXCLUDED.severity, EXCLUDED.cwes)
				THEN now() ELSE cve_records.synced_at END
		WHERE cve_records.feed_sequence <= EXCLUDED.feed_sequence`,
		c.ID, c.Status, c.Published, c.LastModified, c.Description, score,
		c.CVSSVersion, c.CVSSVector, c.Severity, pq.Array(cwes), seq)
	if err != nil {
		return false, fmt.Errorf("cve %s record: %w", c.ID, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// feedRangeRows are the column arrays of a ranges upsert.
type feedRangeRows struct {
	keys, cves, products, schemes, editions, targets, sources []string
	conditions, exact, starts, ends                           []sql.NullString
	startIncl, endIncl                                        []bool
}

func (rows *feedRangeRows) add(kr cvecorpus.KeyedRange, cve, product string, cond sql.NullString) {
	rg := kr.Range.Range
	scheme := string(rg.Scheme)
	if scheme == "" {
		scheme = string(vulnmatch.SchemeGeneric)
	}
	src := kr.Range.Source
	if src == "" {
		src = "nvd"
	}
	rows.keys, rows.cves, rows.products = append(rows.keys, kr.Key), append(rows.cves, cve), append(rows.products, product)
	rows.conditions, rows.schemes = append(rows.conditions, cond), append(rows.schemes, scheme)
	rows.exact, rows.starts, rows.ends = append(rows.exact, nullStr(rg.Exact)), append(rows.starts, nullStr(rg.Start)), append(rows.ends, nullStr(rg.End))
	rows.startIncl, rows.endIncl = append(rows.startIncl, rg.StartIncl), append(rows.endIncl, rg.EndIncl)
	rows.editions, rows.targets, rows.sources = append(rows.editions, rg.Edition), append(rows.targets, rg.Target), append(rows.sources, src)
}

// upsertFeedRanges writes a chunk's ranges keyed by their record id. Each
// must name a CVE record and products of this bundle; ranges of a
// rejected CVE are not kept. A CVE that gains a range (or whose range now
// resolves to another product) gets a new synced_at.
//
//nolint:cyclop // one refusal per rule
func upsertFeedRanges(ctx context.Context, tx *sql.Tx, ranges []cvecorpus.KeyedRange, seq int64) (int, error) {
	if len(ranges) == 0 {
		return 0, nil
	}
	cveIDs, keys := map[string]bool{}, map[string]bool{}
	for _, kr := range ranges {
		cveIDs[kr.Range.Range.VulnID] = true
		keys[kr.ProductKey] = true
		if kr.ConditionKey != "" {
			keys[kr.ConditionKey] = true
		}
	}
	rejected, err := bundleCVEs(ctx, tx, setKeys(cveIDs), seq)
	if err != nil {
		return 0, err
	}
	products, err := bundleProducts(ctx, tx, setKeys(keys), seq)
	if err != nil {
		return 0, err
	}
	var rows feedRangeRows
	for _, kr := range ranges {
		vid := kr.Range.Range.VulnID
		rej, ok := rejected[vid]
		if !ok {
			return 0, fmt.Errorf("range of %s, which is not in the bundle", vid)
		}
		pid, ok := products[kr.ProductKey]
		if !ok {
			return 0, fmt.Errorf("range of %s: product %s is not in the bundle", vid, kr.ProductKey)
		}
		var cond sql.NullString
		if kr.ConditionKey != "" {
			cid, ok := products[kr.ConditionKey]
			if !ok {
				return 0, fmt.Errorf("range of %s: condition %s is not in the bundle", vid, kr.ConditionKey)
			}
			cond = sql.NullString{String: cid, Valid: true}
		}
		if rej {
			continue
		}
		rows.add(kr, vid, pid, cond)
	}
	if len(rows.keys) == 0 {
		return 0, nil
	}
	var written, changed int
	err = tx.QueryRowContext(ctx, `
		WITH t AS (
			SELECT * FROM unnest($1::text[], $2::text[], $3::uuid[], $4::uuid[], $5::text[], $6::text[], $7::text[],
				$8::bool[], $9::text[], $10::bool[], $11::text[], $12::text[], $13::text[])
				AS t(k, cve, p, c, s, e, vs, vsi, ve, vei, ed, tg, src)
		), old AS (
			SELECT a.range_key, a.product_id, a.condition_product_id
			FROM vulnerability_affected a JOIN t ON t.k = a.range_key
		), up AS (
			INSERT INTO vulnerability_affected (range_key, feed_sequence, cve_id, product_id, condition_product_id, scheme,
				exact_version, v_start, v_start_incl, v_end, v_end_incl, edition, target, source)
			SELECT k, $14, cve, p, c, s, e, vs, vsi, ve, vei, ed, tg, src FROM t
			ON CONFLICT (range_key) WHERE range_key IS NOT NULL DO UPDATE SET
				feed_sequence = EXCLUDED.feed_sequence, product_id = EXCLUDED.product_id,
				condition_product_id = EXCLUDED.condition_product_id
			WHERE vulnerability_affected.feed_sequence <= EXCLUDED.feed_sequence
			RETURNING range_key, cve_id, product_id, condition_product_id
		), ch AS (
			SELECT DISTINCT up.cve_id FROM up LEFT JOIN old ON old.range_key = up.range_key
			WHERE old.range_key IS NULL OR old.product_id <> up.product_id
			   OR old.condition_product_id IS DISTINCT FROM up.condition_product_id
		), touched AS (
			UPDATE cve_records SET synced_at = now() WHERE cve_id IN (SELECT cve_id FROM ch) RETURNING 1
		)
		SELECT (SELECT count(*) FROM up), (SELECT count(*) FROM touched)`,
		pq.Array(rows.keys), pq.Array(rows.cves), pq.Array(rows.products), pq.Array(rows.conditions), pq.Array(rows.schemes),
		pq.Array(rows.exact), pq.Array(rows.starts), pq.Array(rows.startIncl), pq.Array(rows.ends), pq.Array(rows.endIncl),
		pq.Array(rows.editions), pq.Array(rows.targets), pq.Array(rows.sources), seq).Scan(&written, &changed)
	if err != nil {
		return 0, fmt.Errorf("bundle ranges: %w", err)
	}
	return written, nil
}

func setKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// bundleCVEs maps each CVE this bundle wrote to whether it is rejected.
func bundleCVEs(ctx context.Context, tx *sql.Tx, ids []string, seq int64) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT cve_id, lower(status) = 'rejected' FROM cve_records WHERE cve_id = ANY($1) AND feed_sequence = $2`,
		pq.Array(ids), seq)
	if err != nil {
		return nil, fmt.Errorf("bundle cves: %w", err)
	}
	defer rows.Close()
	out := make(map[string]bool, len(ids))
	for rows.Next() {
		var id string
		var rej bool
		if err := rows.Scan(&id, &rej); err != nil {
			return nil, fmt.Errorf("bundle cves: %w", err)
		}
		out[id] = rej
	}
	return out, rows.Err()
}

// bundleProducts maps each product key this bundle listed to its global
// catalog product.
func bundleProducts(ctx context.Context, tx *sql.Tx, keys []string, seq int64) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT product_key, product_id FROM cve_feed_products WHERE product_key = ANY($1) AND feed_sequence = $2`,
		pq.Array(keys), seq)
	if err != nil {
		return nil, fmt.Errorf("bundle products: %w", err)
	}
	defer rows.Close()
	out := make(map[string]string, len(keys))
	for rows.Next() {
		var k, id string
		if err := rows.Scan(&k, &id); err != nil {
			return nil, fmt.Errorf("bundle products: %w", err)
		}
		out[k] = id
	}
	return out, rows.Err()
}

// FinishFeedBundle finishes a chunked bundle in one transaction with the
// applied sequence: it removes the ranges of an older sequence the bundle
// replaced (a snapshot: every range it does not hold, and it withdraws the
// CVEs it does not hold; a delta: the older ranges of the CVEs it holds),
// refusing when that would leave more ranges removed from non-rejected
// CVEs without any range than the guard allows. CVEs that lost a range or
// were withdrawn get a new synced_at. A sequence not newer than the
// applied one is refused.
func (r *CVECorpusRepository) FinishFeedBundle(ctx context.Context, f cvecorpus.Finish, done bundle.State) (cvecorpus.FinishResult, error) {
	var res cvecorpus.FinishResult
	if f.Sequence == 0 || f.Sequence != done.Applied || f.Sequence > math.MaxInt64 {
		return res, fmt.Errorf("finish sequence %d does not match the checkpoint %d", f.Sequence, done.Applied)
	}
	seq := int64(f.Sequence)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := r.feedCheckpoint().CompleteTx(ctx, tx, done); err != nil {
		return res, err
	}
	// Stale: rows of an older sequence, of every CVE (snapshot) or of the
	// CVEs this bundle wrote (delta).
	const stale = `a.feed_sequence < $1 AND ($2 OR a.cve_id IN (SELECT cve_id FROM cve_records WHERE feed_sequence = $1))`
	var total, emptied int
	if err := tx.QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM vulnerability_affected),
		       (SELECT count(*) FROM vulnerability_affected a JOIN cve_records rec ON rec.cve_id = a.cve_id
		        WHERE `+stale+` AND lower(rec.status) <> 'rejected'
		          AND NOT EXISTS (SELECT 1 FROM vulnerability_affected f WHERE f.cve_id = a.cve_id AND f.feed_sequence = $1))`,
		seq, f.Snapshot).Scan(&total, &emptied); err != nil {
		return res, fmt.Errorf("count removed ranges: %w", err)
	}
	limit := max(int(float64(total)*f.MaxEmptiedShare), f.MinEmptiedLimit)
	if emptied > limit {
		return res, fmt.Errorf("%w: %d ranges, over the limit of %d", cvecorpus.ErrRemovalLimit, emptied, limit)
	}
	if f.Snapshot {
		if err := tx.QueryRowContext(ctx, `
			WITH w AS (
				UPDATE cve_records SET status = 'Withdrawn', synced_at = now()
				WHERE feed_sequence < $1 AND status <> 'Withdrawn' RETURNING 1
			) SELECT count(*) FROM w`, seq).Scan(&res.Withdrawn); err != nil {
			return res, fmt.Errorf("withdraw cves: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM cve_feed_products WHERE feed_sequence < $1`, seq); err != nil {
			return res, fmt.Errorf("prune bundle products: %w", err)
		}
	}
	if err := tx.QueryRowContext(ctx, `
		WITH d AS (
			DELETE FROM vulnerability_affected a WHERE `+stale+` RETURNING a.cve_id
		), ch AS (
			UPDATE cve_records SET synced_at = now() WHERE cve_id IN (SELECT cve_id FROM d) RETURNING 1
		) SELECT (SELECT count(*) FROM d), (SELECT count(*) FROM ch)`,
		seq, f.Snapshot).Scan(&res.RangesRemoved, &res.Changed); err != nil {
		return res, fmt.Errorf("remove replaced ranges: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit: %w", err)
	}
	return res, nil
}
