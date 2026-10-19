package postgres

// The platform-wide log of material vulnerability changes
// (docs/rfcs/RFC-117-emerging-threat-alerts.md). Public facts only: the CVE
// corpus, the KEV catalog and EPSS scores. Nothing here is tenant data and
// no tenant-facing route writes it.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/vulnevent"
)

// VulnEventRepository persists vuln_events and the emitter's state.
type VulnEventRepository struct {
	db *DB
}

// NewVulnEventRepository creates a VulnEventRepository.
func NewVulnEventRepository(db *DB) *VulnEventRepository { return &VulnEventRepository{db: db} }

var _ vulnevent.Store = (*VulnEventRepository)(nil)

const (
	cursorCorpus = "corpus"
	cursorKEV    = "kev"
	cursorEPSS   = "epss"
)

// currentStateSQL is the state of each CVE record (alias r): its products
// and range count from vulnerability_affected.
const currentStateSQL = `
	SELECT r.cve_id, r.status, COALESCE(r.severity, ''), r.cvss_score, r.published_at, r.feed_sequence, r.synced_at,
		COALESCE((SELECT array_agg(DISTINCT a.product_id::text ORDER BY a.product_id::text)
			FROM vulnerability_affected a WHERE a.cve_id = r.cve_id), '{}'),
		(SELECT count(*) FROM vulnerability_affected a WHERE a.cve_id = r.cve_id)
	FROM cve_records r`

// BaselineCorpus (see vulnevent.Store).
func (r *VulnEventRepository) BaselineCorpus(ctx context.Context) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO vuln_event_state (vuln_id, status, severity, cvss_score, product_ids, range_count)
		SELECT r.cve_id, r.status, COALESCE(r.severity, ''), r.cvss_score,
			COALESCE(agg.products, '{}'), COALESCE(agg.ranges, 0)
		FROM cve_records r
		LEFT JOIN (
			SELECT cve_id, array_agg(DISTINCT product_id ORDER BY product_id) AS products, count(*) AS ranges
			FROM vulnerability_affected GROUP BY cve_id
		) agg ON agg.cve_id = r.cve_id
		ON CONFLICT (vuln_id) DO UPDATE SET status = EXCLUDED.status, severity = EXCLUDED.severity,
			cvss_score = EXCLUDED.cvss_score, product_ids = EXCLUDED.product_ids,
			range_count = EXCLUDED.range_count, updated_at = now()`)
	if err != nil {
		return 0, fmt.Errorf("baseline corpus: %w", err)
	}
	n, _ := res.RowsAffected()
	var at sql.NullTime
	var key sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT synced_at, cve_id FROM cve_records ORDER BY synced_at DESC, cve_id DESC LIMIT 1`).
		Scan(&at, &key); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("baseline cursor: %w", err)
	}
	if !at.Valid {
		at = sql.NullTime{Time: time.Unix(0, 0).UTC(), Valid: true}
	}
	if err := setCursor(ctx, tx, cursorCorpus, at.Time, key.String); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return int(n), nil
}

func setCursor(ctx context.Context, tx *sql.Tx, name string, at time.Time, key string) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO vuln_event_cursors (name, at, key) VALUES ($1, $2, $3)
		ON CONFLICT (name) DO UPDATE SET at = EXCLUDED.at, key = EXCLUDED.key, updated_at = now()`,
		name, at, key); err != nil {
		return fmt.Errorf("cursor %s: %w", name, err)
	}
	return nil
}

// CorpusCursor (see vulnevent.Store).
func (r *VulnEventRepository) CorpusCursor(ctx context.Context) (time.Time, string, bool, error) {
	var at sql.NullTime
	var key string
	err := r.db.QueryRowContext(ctx, `SELECT at, key FROM vuln_event_cursors WHERE name = $1`, cursorCorpus).Scan(&at, &key)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, "", false, nil
	}
	if err != nil {
		return time.Time{}, "", false, fmt.Errorf("corpus cursor: %w", err)
	}
	return at.Time, key, true, nil
}

// ChangedRecords (see vulnevent.Store).
func (r *VulnEventRepository) ChangedRecords(ctx context.Context, at time.Time, key string, limit int) ([]vulnevent.Change, error) {
	rows, err := r.db.QueryContext(ctx, `
		WITH cur AS (`+currentStateSQL+`
			WHERE (r.synced_at, r.cve_id) > ($1, $2)
			ORDER BY r.synced_at, r.cve_id
			LIMIT $3
		)
		SELECT cur.*, s.vuln_id IS NOT NULL, COALESCE(s.status, ''), COALESCE(s.severity, ''), s.cvss_score,
			COALESCE(s.product_ids::text[], '{}'), COALESCE(s.range_count, 0)
		FROM cur
		LEFT JOIN vuln_event_state s ON s.vuln_id = cur.cve_id
		ORDER BY cur.synced_at, cur.cve_id`, at, key, limit)
	if err != nil {
		return nil, fmt.Errorf("changed records: %w", err)
	}
	defer rows.Close()
	var out []vulnevent.Change
	for rows.Next() {
		var c vulnevent.Change
		var score, prevScore sql.NullFloat64
		var published sql.NullTime
		var products, prevProducts pq.StringArray
		var hasPrev bool
		var prev vulnevent.State
		if err := rows.Scan(&c.Cur.VulnID, &c.Cur.Status, &c.Cur.Severity, &score, &published, &c.Cur.FeedSequence,
			&c.SyncedAt, &products, &c.Cur.RangeCount,
			&hasPrev, &prev.Status, &prev.Severity, &prevScore, &prevProducts, &prev.RangeCount); err != nil {
			return nil, fmt.Errorf("changed records: %w", err)
		}
		if score.Valid {
			v := score.Float64
			c.Cur.CVSSScore = &v
		}
		if published.Valid {
			t := published.Time
			c.Cur.Published = &t
		}
		c.Cur.ProductIDs = []string(products)
		if hasPrev {
			prev.VulnID = c.Cur.VulnID
			if prevScore.Valid {
				v := prevScore.Float64
				prev.CVSSScore = &v
			}
			prev.ProductIDs = []string(prevProducts)
			c.Prev = &prev
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Record (see vulnevent.Store).
func (r *VulnEventRepository) Record(ctx context.Context, events []vulnevent.Event, states []vulnevent.State, at time.Time, key string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertVulnEvents(ctx, tx, events); err != nil {
		return err
	}
	if len(states) > 0 {
		ids := make([]string, 0, len(states))
		statuses := make([]string, 0, len(states))
		sevs := make([]string, 0, len(states))
		scores := make([]sql.NullFloat64, 0, len(states))
		products := make([]string, 0, len(states))
		counts := make([]int64, 0, len(states))
		for _, s := range states {
			ids, statuses, sevs = append(ids, s.VulnID), append(statuses, s.Status), append(sevs, s.Severity)
			var sc sql.NullFloat64
			if s.CVSSScore != nil {
				sc = sql.NullFloat64{Float64: *s.CVSSScore, Valid: true}
			}
			scores = append(scores, sc)
			// A uuid[] per row travels as its text form ({a,b}).
			products = append(products, uuidArrayLiteral(s.ProductIDs))
			counts = append(counts, int64(s.RangeCount))
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vuln_event_state (vuln_id, status, severity, cvss_score, product_ids, range_count)
			SELECT id, st, sev, sc, p::uuid[], n
			FROM unnest($1::text[], $2::text[], $3::text[], $4::numeric[], $5::text[], $6::int[]) AS t(id, st, sev, sc, p, n)
			ON CONFLICT (vuln_id) DO UPDATE SET status = EXCLUDED.status, severity = EXCLUDED.severity,
				cvss_score = EXCLUDED.cvss_score, product_ids = EXCLUDED.product_ids,
				range_count = EXCLUDED.range_count, updated_at = now()`,
			pq.Array(ids), pq.Array(statuses), pq.Array(sevs), pq.Array(scores), pq.Array(products), pq.Array(counts)); err != nil {
			return fmt.Errorf("event state: %w", err)
		}
	}
	if err := setCursor(ctx, tx, cursorCorpus, at, key); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func uuidArrayLiteral(ids []string) string {
	b := []byte{'{'}
	for i, id := range ids {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, id...)
	}
	return string(append(b, '}'))
}

func insertVulnEvents(ctx context.Context, tx *sql.Tx, events []vulnevent.Event) error {
	if len(events) == 0 {
		return nil
	}
	ids := make([]string, 0, len(events))
	kinds := make([]string, 0, len(events))
	ats := make([]time.Time, 0, len(events))
	sources := make([]sql.NullTime, 0, len(events))
	seqs := make([]sql.NullInt64, 0, len(events))
	details := make([]string, 0, len(events))
	for _, e := range events {
		ids, kinds, ats = append(ids, e.VulnID), append(kinds, string(e.Kind)), append(ats, e.At)
		var src sql.NullTime
		if e.SourceAt != nil {
			src = sql.NullTime{Time: *e.SourceAt, Valid: true}
		}
		sources = append(sources, src)
		var seq sql.NullInt64
		if e.FeedSequence != nil {
			seq = sql.NullInt64{Int64: *e.FeedSequence, Valid: true}
		}
		seqs = append(seqs, seq)
		d := e.Detail
		if d == nil {
			d = map[string]any{}
		}
		raw, err := json.Marshal(d)
		if err != nil || len(raw) > 2048 {
			raw = []byte("{}")
		}
		details = append(details, string(raw))
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO vuln_events (vuln_id, kind, at, source_at, feed_sequence, detail)
		SELECT id, k, a, s, q, d::jsonb
		FROM unnest($1::text[], $2::text[], $3::timestamptz[], $4::timestamptz[], $5::bigint[], $6::text[]) AS t(id, k, a, s, q, d)`,
		pq.Array(ids), pq.Array(kinds), pq.Array(ats), pq.Array(sources), pq.Array(seqs), pq.Array(details)); err != nil {
		return fmt.Errorf("insert vuln events: %w", err)
	}
	return nil
}

// cursorExists reports whether the named cursor was ever set (inside tx).
func cursorExists(ctx context.Context, tx *sql.Tx, name string) (bool, error) {
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM vuln_event_cursors WHERE name = $1)`, name).Scan(&ok); err != nil {
		return false, fmt.Errorf("cursor %s: %w", name, err)
	}
	return ok, nil
}

// SyncKEV (see vulnevent.Store). One transaction: the CVEs that entered
// the catalog get an event (unless this is the first call), every catalog
// CVE is marked in_kev, and CVEs that left it are unmarked.
func (r *VulnEventRepository) SyncKEV(ctx context.Context) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	seen, err := cursorExists(ctx, tx, cursorKEV)
	if err != nil {
		return 0, err
	}
	n := 0
	if seen {
		if err := tx.QueryRowContext(ctx, `
			WITH added AS (
				SELECT k.cve_id, k.date_added,
					COALESCE(k.known_ransomware_campaign_use, '') = 'Known' AS ransomware
				FROM kev_catalog k
				LEFT JOIN vuln_event_state s ON s.vuln_id = k.cve_id
				WHERE s.in_kev IS NOT TRUE
			), ins AS (
				INSERT INTO vuln_events (vuln_id, kind, source_at, detail)
				SELECT cve_id, 'kev_added', date_added::timestamptz,
					jsonb_build_object('ransomware', ransomware, 'date_added', to_char(date_added, 'YYYY-MM-DD'))
				FROM added RETURNING 1
			) SELECT count(*) FROM ins`).Scan(&n); err != nil {
			return 0, fmt.Errorf("kev events: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO vuln_event_state (vuln_id, in_kev)
		SELECT cve_id, true FROM kev_catalog
		ON CONFLICT (vuln_id) DO UPDATE SET in_kev = true, updated_at = now()
		WHERE vuln_event_state.in_kev IS NOT TRUE`); err != nil {
		return 0, fmt.Errorf("kev state: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE vuln_event_state s SET in_kev = false, updated_at = now()
		WHERE s.in_kev AND NOT EXISTS (SELECT 1 FROM kev_catalog k WHERE k.cve_id = s.vuln_id)`); err != nil {
		return 0, fmt.Errorf("kev removals: %w", err)
	}
	if err := setCursor(ctx, tx, cursorKEV, time.Now().UTC(), ""); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return n, nil
}

// epssBandSQL maps the score of epss_scores e to its band
// (vulnevent.EPSSBand).
const epssBandSQL = `(CASE WHEN e.epss_score >= 0.5 THEN 2 WHEN e.epss_score >= 0.1 THEN 1 ELSE 0 END)`

// SyncEPSS (see vulnevent.Store). Only CVEs the emitter tracks (records of
// the corpus, KEV entries) are compared: an EPSS move on a CVE nothing can
// match is not an event.
func (r *VulnEventRepository) SyncEPSS(ctx context.Context) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	seen, err := cursorExists(ctx, tx, cursorEPSS)
	if err != nil {
		return 0, err
	}
	n := 0
	if seen {
		if err := tx.QueryRowContext(ctx, `
			WITH up AS (
				SELECT s.vuln_id, s.epss_band AS from_band, `+epssBandSQL+` AS to_band, e.epss_score
				FROM vuln_event_state s JOIN epss_scores e ON e.cve_id = s.vuln_id
				WHERE `+epssBandSQL+` > s.epss_band
			), ins AS (
				INSERT INTO vuln_events (vuln_id, kind, detail)
				SELECT vuln_id, 'epss_crossed', jsonb_build_object('from_band', from_band, 'to_band', to_band,
					'epss', round(epss_score::numeric, 4), 'threshold', CASE WHEN to_band = 2 THEN 0.5 ELSE 0.1 END)
				FROM up RETURNING 1
			) SELECT count(*) FROM ins`).Scan(&n); err != nil {
			return 0, fmt.Errorf("epss events: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE vuln_event_state s SET epss_band = `+epssBandSQL+`, updated_at = now()
		FROM epss_scores e WHERE e.cve_id = s.vuln_id AND s.epss_band <> `+epssBandSQL); err != nil {
		return 0, fmt.Errorf("epss state: %w", err)
	}
	if err := setCursor(ctx, tx, cursorEPSS, time.Now().UTC(), ""); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return n, nil
}

// Prune (see vulnevent.Store).
func (r *VulnEventRepository) Prune(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM vuln_events WHERE at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("prune vuln events: %w", err)
	}
	return res.RowsAffected()
}
