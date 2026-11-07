// Package findingpractice is the finding-practice command: it sets the
// practice of findings stored before practices existed, and re-derives the
// practice of open findings whose inputs changed
// (docs/architecture/finding-practices.md).
//
// It uses the same function as the write path (vulnerability.DerivePractice);
// the rules have no SQL copy. A row is considered when its practice was never
// derived (practice_reason IS NULL, any status) or when it is open; a closed
// finding that has a practice keeps it (forward only, so closed-period
// figures never move).
//
// A dry run (the default) opens a read-only connection and prints only
// aggregates per tenant: findings per practice before and after, the moves
// between practices (open and closed counts) and how many rows would change.
// It prints no finding id, title or other row content. -apply writes the
// changes in keyset pages, one transaction per page, only where the stored
// value differs (a rerun is a no-op), and queues a dashboard fact refresh for
// the assets whose findings moved. An update bumps the row's updated_at and
// row_version, as every write does.
//
//	DATABASE_URL  postgres connection string; when unset it is built from the
//	              server's DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME and
//	              DB_SSLMODE, so it runs as-is inside the API container
//
// Usage:
//
//	finding-practice                  dry run, every tenant (changes nothing)
//	finding-practice -tenant <id>     one tenant
//	finding-practice -apply           make the changes
//	finding-practice -json            the report as JSON
//
// Exit status: 0 success, 1 the run failed, 2 usage or connection error.
package findingpractice

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

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// DefaultBatchSize is the keyset page size.
const DefaultBatchSize = 2000

// Options select what a run does.
type Options struct {
	Tenant    *shared.ID // nil: every tenant
	Apply     bool
	BatchSize int
}

// Move counts the findings that move from one practice to another.
type Move struct {
	Open   int `json:"open"`
	Closed int `json:"closed"`
}

// TenantReport is one tenant's aggregates. It holds counts only.
type TenantReport struct {
	TenantID string `json:"tenant_id"`
	// Findings is every finding of the tenant.
	Findings int `json:"findings"`
	// Scanned is the rows considered (never derived, or open).
	Scanned int `json:"scanned"`
	// Changed is the rows whose practice or reason differs from the derived one.
	Changed int `json:"changed"`
	// Applied is the rows written (with -apply).
	Applied int `json:"applied"`
	// Before and After are findings per practice, now and after the run.
	Before map[string]int `json:"before"`
	After  map[string]int `json:"after"`
	// Moves is keyed "from>to" (only practice changes, not reason-only ones).
	Moves map[string]Move `json:"moves"`
	// Reasons counts the derivation reason of the changed rows.
	Reasons map[string]int `json:"reasons"`
}

// Report is what a run found and, with Apply, did.
type Report struct {
	Apply   bool           `json:"apply"`
	Tenants []TenantReport `json:"tenants"`
}

// Main runs the command with os.Args (see cmd/server/tools.go for why it
// parses its flags on a fresh flag set).
func Main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	tenantFlag := flag.String("tenant", "", "tenant id (default: every tenant)")
	apply := flag.Bool("apply", false, "make the changes (default: a dry run)")
	asJSON := flag.Bool("json", false, "print the report as JSON")
	batch := flag.Int("batch", DefaultBatchSize, "rows per page")
	timeout := flag.Duration("timeout", 2*time.Hour, "overall time limit")
	flag.Parse()

	opts := Options{Apply: *apply, BatchSize: *batch}
	if *tenantFlag != "" {
		id, err := shared.IDFromString(*tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		opts.Tenant = &id
	}
	dbURL := databaseURL()
	if dbURL == "" {
		fail(2, "DATABASE_URL (or DB_HOST/DB_*) must be set in the environment")
	}
	if !opts.Apply {
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
		fail(2, "connect: "+err.Error())
	}
	rep, err := Run(ctx, db, opts)
	if err != nil {
		fail(1, err.Error())
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	}
	fmt.Print(Render(rep))
}

// Run derives the practice of every considered finding of the selected
// tenants and, with Apply, writes the differences.
func Run(ctx context.Context, db *sql.DB, opts Options) (*Report, error) {
	if opts.BatchSize <= 0 {
		opts.BatchSize = DefaultBatchSize
	}
	tenants, err := listTenants(ctx, db, opts.Tenant)
	if err != nil {
		return nil, err
	}
	rep := &Report{Apply: opts.Apply, Tenants: make([]TenantReport, 0, len(tenants))}
	for _, tid := range tenants {
		tr, err := runTenant(ctx, db, tid, opts)
		if err != nil {
			return nil, fmt.Errorf("tenant %s: %w", tid, err)
		}
		rep.Tenants = append(rep.Tenants, *tr)
	}
	return rep, nil
}

func listTenants(ctx context.Context, db *sql.DB, only *shared.ID) ([]string, error) {
	if only != nil {
		var id string
		if err := db.QueryRowContext(ctx, `SELECT id FROM tenants WHERE id = $1`, only.String()).Scan(&id); err != nil {
			return nil, fmt.Errorf("tenant: %w", err)
		}
		return []string{id}, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM findings ORDER BY tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// pageSQL reads one keyset page of considered findings with the facts of
// their asset, pinned to the tenant on both tables.
const pageSQL = `
	SELECT f.id, f.asset_id, f.finding_type, f.source, f.tool_name, f.pentest_campaign_id IS NOT NULL,
	       is_open_finding_status(f.status), f.practice, f.practice_reason,
	       COALESCE(a.asset_type, ''),
	       COALESCE(a.is_internet_accessible, false) OR COALESCE(a.exposure, '') = 'public'
	FROM findings f
	LEFT JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
	WHERE f.tenant_id = $1 AND f.id > $2
	  AND (f.practice_reason IS NULL OR is_open_finding_status(f.status))
	ORDER BY f.id
	LIMIT $3`

type change struct {
	id, asset, practice, reason string
}

func runTenant(ctx context.Context, db *sql.DB, tid string, opts Options) (*TenantReport, error) {
	tr := &TenantReport{TenantID: tid, Before: map[string]int{}, After: map[string]int{}, Moves: map[string]Move{}, Reasons: map[string]int{}}
	rows, err := db.QueryContext(ctx, `SELECT practice, count(*) FROM findings WHERE tenant_id = $1 GROUP BY practice`, tid)
	if err != nil {
		return nil, fmt.Errorf("count practices: %w", err)
	}
	for rows.Next() {
		var p string
		var n int
		if err := rows.Scan(&p, &n); err != nil {
			_ = rows.Close()
			return nil, err
		}
		tr.Before[p] = n
		tr.After[p] = n
		tr.Findings += n
	}
	_ = rows.Close()

	after := "00000000-0000-0000-0000-000000000000"
	for {
		changes, last, n, err := scanPage(ctx, db, tid, after, opts.BatchSize, tr)
		if err != nil {
			return nil, err
		}
		if opts.Apply && len(changes) > 0 {
			written, err := applyPage(ctx, db, tid, changes)
			if err != nil {
				return nil, err
			}
			tr.Applied += written
		}
		if n < opts.BatchSize {
			break
		}
		after = last
	}
	for p, n := range tr.After {
		if n == 0 {
			delete(tr.After, p)
		}
	}
	return tr, nil
}

func scanPage(ctx context.Context, db *sql.DB, tid, after string, limit int, tr *TenantReport) ([]change, string, int, error) {
	rows, err := db.QueryContext(ctx, pageSQL, tid, after, limit)
	if err != nil {
		return nil, "", 0, fmt.Errorf("read findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var (
		changes []change
		last    string
		n       int
	)
	for rows.Next() {
		var (
			id, ftype, source, tool, stored, assetType string
			asset, reason                              sql.NullString
			inCampaign, open, facing                   bool
		)
		if err := rows.Scan(&id, &asset, &ftype, &source, &tool, &inCampaign, &open, &stored, &reason, &assetType, &facing); err != nil {
			return nil, "", 0, fmt.Errorf("scan finding: %w", err)
		}
		n++
		last = id
		p, why := vulnerability.DerivePractice(vulnerability.PracticeInput{
			FindingType: vulnerability.FindingType(ftype), Source: vulnerability.FindingSource(source), ToolName: tool,
			InPentestCampaign: inCampaign, AssetType: assetType, AssetInternetFacing: facing,
		})
		if string(p) == stored && reason.Valid && reason.String == why {
			continue
		}
		changes = append(changes, change{id: id, asset: asset.String, practice: string(p), reason: why})
		tr.Changed++
		tr.Reasons[why]++
		if string(p) != stored {
			k := stored + ">" + string(p)
			m := tr.Moves[k]
			if open {
				m.Open++
			} else {
				m.Closed++
			}
			tr.Moves[k] = m
			tr.After[stored]--
			tr.After[string(p)]++
		}
	}
	tr.Scanned += n
	return changes, last, n, rows.Err()
}

// applySQL writes one page. The guard repeats the selection (never derived,
// or open) and writes only a differing value, so a finding closed or changed
// since the read is left as it is.
const applySQL = `
	UPDATE findings f SET practice = v.p, practice_reason = v.r
	FROM unnest($2::uuid[], $3::text[], $4::text[]) AS v(id, p, r)
	WHERE f.tenant_id = $1 AND f.id = v.id
	  AND (f.practice_reason IS NULL OR is_open_finding_status(f.status))
	  AND (f.practice <> v.p OR f.practice_reason IS DISTINCT FROM v.r)`

// markDirtySQL queues a dashboard fact refresh for the tenant's assets whose
// findings moved (reason bit 1, as the findings triggers use).
const markDirtySQL = `
	INSERT INTO dash_dirty_assets (tenant_id, asset_id, reasons)
	SELECT DISTINCT $1::uuid, a, 1::smallint FROM unnest($2::uuid[]) AS a`

func applyPage(ctx context.Context, db *sql.DB, tid string, changes []change) (int, error) {
	ids := make([]string, len(changes))
	ps := make([]string, len(changes))
	rs := make([]string, len(changes))
	assets := map[string]bool{}
	for i, c := range changes {
		ids[i], ps[i], rs[i] = c.id, c.practice, c.reason
		if c.asset == "" {
			assets["00000000-0000-0000-0000-000000000000"] = true
		} else {
			assets[c.asset] = true
		}
	}
	assetIDs := make([]string, 0, len(assets))
	for a := range assets {
		assetIDs = append(assetIDs, a)
	}
	sort.Strings(assetIDs)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, applySQL, tid, pq.Array(ids), pq.Array(ps), pq.Array(rs))
	if err != nil {
		return 0, fmt.Errorf("write practices: %w", err)
	}
	n, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, markDirtySQL, tid, pq.Array(assetIDs)); err != nil {
		return 0, fmt.Errorf("queue dashboard refresh: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(n), nil
}

// Render prints the report for a person.
func Render(r *Report) string {
	var b strings.Builder
	mode := "dry run (nothing changed; -apply to write)"
	if r.Apply {
		mode = "applied"
	}
	fmt.Fprintf(&b, "finding-practice: %s, %d tenant(s)\n", mode, len(r.Tenants))
	for _, t := range r.Tenants {
		fmt.Fprintf(&b, "\ntenant %s: %d findings, %d considered, %d to change, %d written\n", t.TenantID, t.Findings, t.Scanned, t.Changed, t.Applied)
		fmt.Fprintf(&b, "  %-12s %8s %8s\n", "practice", "before", "after")
		for _, p := range vulnerability.AllPractices() {
			k := p.String()
			if t.Before[k] == 0 && t.After[k] == 0 {
				continue
			}
			fmt.Fprintf(&b, "  %-12s %8d %8d\n", k, t.Before[k], t.After[k])
		}
		keys := make([]string, 0, len(t.Moves))
		for k := range t.Moves {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			m := t.Moves[k]
			fmt.Fprintf(&b, "  move %-24s open %d, closed %d\n", strings.Replace(k, ">", " -> ", 1), m.Open, m.Closed)
		}
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
	fmt.Fprintln(os.Stderr, "finding-practice: "+msg)
	os.Exit(code)
}
