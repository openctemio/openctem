// Package findingsourcebackfill is the finding-source-backfill command: it
// gives findings stored before per-source records existed one record each
// (docs/architecture/finding-source-records.md).
//
// The record holds the values on the finding row (title, text, severity,
// type details, native identity, scores, vulnerability ids, unmapped
// fields), attributed to the finding's most recent sighting
// (finding_sightings: its channel, sensor, sender and tool) and marked
// backfilled, because those values may mix earlier sources. A finding with
// no sighting (entered by a person) gets none; a finding that already has a
// record is left alone, so the command can be re-run at any time.
//
//	DATABASE_URL  postgres connection string; when unset it is built from the
//	              server's DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME and
//	              DB_SSLMODE, so it runs as-is inside the API container
//
// Usage:
//
//	finding-source-backfill                  dry run, every tenant (read-only)
//	finding-source-backfill -tenant <id>     one tenant
//	finding-source-backfill -apply           write, in batches (one short transaction each)
//	finding-source-backfill -batch 500       findings per batch
//	finding-source-backfill -json            the report as JSON
//
// Exit status: 0 success, 1 the run failed, 2 usage or connection error.
package findingsourcebackfill

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// DefaultBatch is the findings per apply batch.
const DefaultBatch = 500

// Report is what a run found (and, with Apply, wrote).
type Report struct {
	Apply bool `json:"apply"`
	// Findings without a record.
	Missing int `json:"findings_without_records"`
	// WithSighting would get (Apply: got) a record; NoSighting would not.
	WithSighting int `json:"with_sighting"`
	NoSighting   int `json:"without_sighting"`
	Written      int `json:"written"`
	// ByChannel counts the findings with a sighting by its channel.
	ByChannel map[string]int `json:"by_channel"`
	ByTenant  map[string]int `json:"by_tenant"`
	Batches   int            `json:"batches"`
}

// Options of a run.
type Options struct {
	Tenant *shared.ID
	Apply  bool
	Batch  int
}

// missingSQL counts the findings without a record, per tenant and the
// channel of their most recent sighting (” without one).
const missingSQL = `
	SELECT f.tenant_id::text, COALESCE(s.channel, ''), count(*)
	FROM findings f
	LEFT JOIN LATERAL (
		SELECT x.channel FROM finding_sightings x
		WHERE x.tenant_id = f.tenant_id AND x.finding_id = f.id
		ORDER BY x.last_seen_at DESC, x.channel, x.tool, x.sender LIMIT 1
	) s ON true
	WHERE ($1::uuid IS NULL OR f.tenant_id = $1::uuid)
	  AND NOT EXISTS (SELECT 1 FROM finding_source_records r WHERE r.tenant_id = f.tenant_id AND r.finding_id = f.id)
	GROUP BY 1, 2`

// backfillBatchSQL writes the records of the next batch of findings after
// the cursor ($2) and returns the batch's last id and the rows written.
// Values are capped like the writer's (vulnerability.MaxSource*); a JSON
// document over its cap is left out and the record marked clipped.
var backfillBatchSQL = fmt.Sprintf(`
	WITH cand AS (
		SELECT f.id, f.tenant_id FROM findings f
		WHERE ($1::uuid IS NULL OR f.tenant_id = $1::uuid) AND f.id > $2::uuid
		  AND NOT EXISTS (SELECT 1 FROM finding_source_records r WHERE r.tenant_id = f.tenant_id AND r.finding_id = f.id)
		ORDER BY f.id LIMIT $3
	), ins AS (
		INSERT INTO finding_source_records (tenant_id, finding_id, channel, sensor_id, sender, tool, tool_version,
			first_seen_at, last_seen_at, title, description, snippet, recommendation, message, severity,
			cvss_score, cvss_vector, type_details, native_vuln_id, native_scheme, source_meta, scores,
			vulnerability_ids, source_extra, location_key, clipped, backfilled)
		SELECT f.tenant_id, f.id, s.channel, s.sensor_id, s.sender, s.tool, COALESCE(s.tool_version, f.tool_version),
			s.first_seen_at, s.last_seen_at,
			NULLIF(left(f.title, %[1]d), ''), NULLIF(left(f.description, %[2]d), ''), NULLIF(left(f.snippet, %[3]d), ''),
			NULLIF(left(f.remediation->>'recommendation', %[4]d), ''), NULLIF(left(f.message, %[5]d), ''),
			COALESCE(NULLIF(f.source_severity, ''), f.severity),
			CASE WHEN f.cvss_score BETWEEN 0 AND 10 THEN f.cvss_score END, left(f.cvss_vector, 255),
			CASE WHEN octet_length(f.type_details::text) <= %[6]d THEN f.type_details END,
			left(f.native_vuln_id, 256), left(f.native_scheme, 64),
			CASE WHEN octet_length(f.source_meta::text) <= %[7]d THEN f.source_meta END,
			CASE WHEN octet_length(f.scores::text) <= %[7]d THEN f.scores END,
			CASE WHEN octet_length(f.vulnerability_ids::text) <= %[7]d THEN f.vulnerability_ids END,
			CASE WHEN octet_length(f.source_extra::text) <= %[7]d THEN f.source_extra END,
			left(f.location_key, 512),
			(char_length(f.title) > %[1]d OR char_length(f.description) > %[2]d OR char_length(f.snippet) > %[3]d
				OR char_length(f.remediation->>'recommendation') > %[4]d OR char_length(f.message) > %[5]d
				OR octet_length(f.type_details::text) > %[6]d OR octet_length(f.source_meta::text) > %[7]d
				OR octet_length(f.scores::text) > %[7]d OR octet_length(f.vulnerability_ids::text) > %[7]d
				OR octet_length(f.source_extra::text) > %[7]d) IS TRUE,
			true
		FROM cand c
		JOIN findings f ON f.tenant_id = c.tenant_id AND f.id = c.id
		JOIN LATERAL (
			SELECT x.channel, x.sensor_id, x.sender, x.tool, x.tool_version, x.first_seen_at, x.last_seen_at
			FROM finding_sightings x
			WHERE x.tenant_id = c.tenant_id AND x.finding_id = c.id
			ORDER BY x.last_seen_at DESC, x.channel, x.tool, x.sender LIMIT 1
		) s ON true
		ORDER BY c.id
		ON CONFLICT DO NOTHING
		RETURNING 1
	)
	SELECT (SELECT max(id::text) FROM cand), (SELECT count(*) FROM ins)`,
	vulnerability.MaxSourceTitle, vulnerability.MaxSourceDescription, vulnerability.MaxSourceSnippet,
	vulnerability.MaxSourceRecommendation, vulnerability.MaxSourceMessage, vulnerability.MaxSourceTypeDetails,
	maxJSON)

// maxJSON is the cap of the interop JSON documents (the column CHECK).
const maxJSON = 131072

// Run counts the findings without a record and, with Apply, writes their
// records in batches.
func Run(ctx context.Context, db *sql.DB, opts Options) (*Report, error) {
	rep := &Report{Apply: opts.Apply, ByChannel: map[string]int{}, ByTenant: map[string]int{}}
	var tenant any
	if opts.Tenant != nil {
		tenant = opts.Tenant.String()
	}
	if err := countMissing(ctx, db, tenant, rep); err != nil {
		return nil, err
	}
	if !opts.Apply {
		return rep, nil
	}
	batch := opts.Batch
	if batch <= 0 {
		batch = DefaultBatch
	}
	cursor := "00000000-0000-0000-0000-000000000000"
	for {
		var last sql.NullString
		var written int
		if err := db.QueryRowContext(ctx, backfillBatchSQL, tenant, cursor, batch).Scan(&last, &written); err != nil {
			return rep, fmt.Errorf("backfill batch after %s: %w", cursor, err)
		}
		if !last.Valid {
			return rep, nil
		}
		rep.Batches++
		rep.Written += written
		cursor = last.String
	}
}

// countMissing fills the counts of the findings without a record.
func countMissing(ctx context.Context, db *sql.DB, tenant any, rep *Report) error {
	rows, err := db.QueryContext(ctx, missingSQL, tenant)
	if err != nil {
		return fmt.Errorf("count findings without records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var t, channel string
		var n int
		if err := rows.Scan(&t, &channel, &n); err != nil {
			return fmt.Errorf("count findings without records: %w", err)
		}
		rep.Missing += n
		if channel == "" {
			rep.NoSighting += n
			continue
		}
		rep.WithSighting += n
		rep.ByChannel[channel] += n
		rep.ByTenant[t] += n
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("count findings without records: %w", err)
	}
	return nil
}

// Main runs the command with os.Args (see cmd/server/tools.go for why it
// parses its flags on a fresh flag set).
func Main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	tenantFlag := flag.String("tenant", "", "tenant id (default: every tenant)")
	apply := flag.Bool("apply", false, "write the records (default: a dry run that changes nothing)")
	batch := flag.Int("batch", DefaultBatch, "findings per batch")
	asJSON := flag.Bool("json", false, "print the report as JSON")
	timeout := flag.Duration("timeout", time.Hour, "overall time limit")
	flag.Parse()

	opts := Options{Apply: *apply, Batch: *batch}
	if *tenantFlag != "" {
		id, err := shared.IDFromString(*tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		opts.Tenant = &id
	}
	if *batch < 1 || *batch > 10000 {
		fail(2, "-batch: between 1 and 10000")
	}
	dbURL := databaseURL()
	if dbURL == "" {
		fail(2, "DATABASE_URL (or DB_HOST/DB_*) must be set in the environment")
	}
	if !*apply {
		dbURL = readOnlyURL(dbURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fail(2, "open database: "+err.Error())
	}
	defer func() { _ = db.Close() }()
	if err := db.PingContext(ctx); err != nil {
		fail(2, "connect database: "+err.Error())
	}
	rep, err := Run(ctx, db, opts)
	if rep != nil {
		if *asJSON {
			b, _ := json.MarshalIndent(rep, "", "  ")
			fmt.Println(string(b))
		} else {
			fmt.Print(render(rep))
		}
	}
	if err != nil {
		fail(1, err.Error())
	}
}

func render(r *Report) string {
	var b strings.Builder
	mode := "dry run, nothing written"
	if r.Apply {
		mode = "apply"
	}
	fmt.Fprintf(&b, "finding-source-backfill (%s)\n", mode)
	fmt.Fprintf(&b, "findings without records:   %d\n", r.Missing)
	fmt.Fprintf(&b, "  with a sighting:          %d\n", r.WithSighting)
	fmt.Fprintf(&b, "  without (entered by hand): %d\n", r.NoSighting)
	channels := make([]string, 0, len(r.ByChannel))
	for c := range r.ByChannel {
		channels = append(channels, c)
	}
	sort.Strings(channels)
	for _, c := range channels {
		fmt.Fprintf(&b, "  channel %-18s %d\n", c+":", r.ByChannel[c])
	}
	fmt.Fprintf(&b, "tenants: %d\n", len(r.ByTenant))
	if r.Apply {
		fmt.Fprintf(&b, "written: %d in %d batches\n", r.Written, r.Batches)
	} else {
		b.WriteString("re-run with -apply to write\n")
	}
	return b.String()
}

func databaseURL() string {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	host := os.Getenv("DB_HOST")
	if host == "" {
		return ""
	}
	get := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(get("DB_USER", "openctem"), os.Getenv("DB_PASSWORD")),
		Host:     host + ":" + get("DB_PORT", "5432"),
		Path:     "/" + get("DB_NAME", "openctem"),
		RawQuery: "sslmode=" + url.QueryEscape(get("DB_SSLMODE", "disable")),
	}
	return u.String()
}

// readOnlyURL makes every transaction of the connection read-only: the
// server refuses any write, so a dry run cannot change anything.
func readOnlyURL(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		q := u.Query()
		q.Set("default_transaction_read_only", "on")
		u.RawQuery = q.Encode()
		return u.String()
	}
	return dsn + " default_transaction_read_only=on"
}

func fail(code int, msg string) {
	fmt.Fprintln(os.Stderr, "finding-source-backfill: "+msg)
	os.Exit(code)
}
