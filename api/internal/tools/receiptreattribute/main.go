// Package receiptreattribute is the receipt-reattribute command: a one-off
// repair for the receipts the results quarantine's release wrote before a
// released item kept its original sender.
//
// A held sensor report that the platform later released (the tool's signed
// descriptor now declares what it carries) was re-ingested server-side, and
// its receipt was filed under source kind "connector" with a connector named
// after the tool, so the dashboard showed a sensor's results as a connector's.
// This command moves each such receipt back to the sensor that sent it: source
// kind "sensor", the sensor as the sender of its tool rows, and the
// "released from quarantine" marker.
//
// A receipt is repaired only when the release itself left evidence of it: the
// quarantine item that was auto-released (its stored result says
// auto_accepted), whose report id is the connector receipt's reference, with
// the same tenant and tool, and a receipt created within minutes of the
// item's review. Nothing is guessed: a receipt without such an item is left
// alone, and so is one whose sensor receipt already exists (a conflict is
// reported, not merged). Only the receipt rows and the daily intake facts
// move; findings, their ingest actions and every binding stay as they were.
// An item purged after its retention left no evidence, so its receipt is
// not found.
//
//	DATABASE_URL  postgres connection string; when unset it is built from the
//	              server's DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME and
//	              DB_SSLMODE, so it runs as-is inside the API container
//
// Usage:
//
//	receipt-reattribute                  dry run, every tenant (changes nothing)
//	receipt-reattribute -tenant <id>     one tenant
//	receipt-reattribute -apply           make the changes (one transaction each)
//	receipt-reattribute -json            the report as JSON
//
// Exit status: 0 success, 1 the run failed, 2 usage or connection error.
package receiptreattribute

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// reviewWindow is how far from the item's review a receipt may have been
// created: the apply writes the receipt, then marks the item reviewed.
const (
	windowBefore = 10 * time.Minute
	windowAfter  = time.Minute
)

// Candidate is one receipt to move.
type Candidate struct {
	TenantID  string `json:"tenant_id"`
	ReceiptID string `json:"receipt_id"`
	Tool      string `json:"tool"`
	SensorID  string `json:"sensor_id"`
	Received  int    `json:"received"`
	// Conflict: a sensor receipt for the same report already exists; the
	// receipt is left as it is.
	Conflict bool `json:"conflict,omitempty"`

	sensorName string
	ref        string
	newRef     string
	day        time.Time
}

// Report is what a run found (and, with Apply, did).
type Report struct {
	Apply     bool           `json:"apply"`
	Receipts  int            `json:"receipts"`
	Received  int            `json:"findings_received"`
	Conflicts int            `json:"conflicts"`
	Moved     int            `json:"moved"`
	ByTenant  map[string]int `json:"receipts_by_tenant"`
	Items     []Candidate    `json:"items"`
}

// Main runs the command with os.Args (see internal/server/tools.go for why it
// parses its flags on a fresh flag set).
func Main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	tenantFlag := flag.String("tenant", "", "tenant id (default: every tenant)")
	apply := flag.Bool("apply", false, "make the changes (default: a dry run)")
	asJSON := flag.Bool("json", false, "print the report as JSON")
	timeout := flag.Duration("timeout", 10*time.Minute, "overall time limit")
	flag.Parse()

	var tenant *shared.ID
	if *tenantFlag != "" {
		id, err := shared.IDFromString(*tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		tenant = &id
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
		fail(2, "connect: "+err.Error())
	}
	rep, err := Run(ctx, db, tenant, *apply)
	if err != nil {
		fail(1, err.Error())
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	}
	fmt.Print(render(rep))
}

// Run finds the receipts to move and, with apply, moves them.
func Run(ctx context.Context, db *sql.DB, tenant *shared.ID, apply bool) (*Report, error) {
	cands, err := find(ctx, db, tenant)
	if err != nil {
		return nil, err
	}
	rep := &Report{Apply: apply, ByTenant: map[string]int{}, Items: cands}
	for i := range cands {
		c := &cands[i]
		if c.Conflict {
			rep.Conflicts++
			continue
		}
		rep.Receipts++
		rep.Received += c.Received
		rep.ByTenant[c.TenantID]++
		if !apply {
			continue
		}
		if err := move(ctx, db, c); err != nil {
			return rep, fmt.Errorf("receipt %s: %w", c.ReceiptID, err)
		}
		rep.Moved++
	}
	return rep, nil
}

// find lists the connector receipts that an auto-released quarantine item
// wrote.
func find(ctx context.Context, db *sql.DB, tenant *shared.ID) ([]Candidate, error) {
	var tid any
	if tenant != nil {
		tid = tenant.String()
	}
	rows, err := db.QueryContext(ctx, `
		SELECT r.tenant_id::text, r.id::text, r.source_ref, COALESCE(r.tool_name, ''), r.findings_received, r.created_at,
			q.sensor_id::text, q.report_id, COALESCE(s.name, '')
		FROM sensor_result_quarantine q
		JOIN ingest_receipts r ON r.tenant_id = q.tenant_id AND r.source_kind = 'connector'
			AND COALESCE(r.tool_name, '') = q.tool_name
			AND r.source_ref = q.report_id
			AND r.created_at BETWEEN q.reviewed_at - $2::interval AND q.reviewed_at + $3::interval
		LEFT JOIN sensors s ON s.tenant_id = q.tenant_id AND s.id = q.sensor_id
		WHERE q.status = 'accepted' AND q.result->>'auto_accepted' = 'true'
			AND ($1::uuid IS NULL OR q.tenant_id = $1::uuid)
		ORDER BY r.tenant_id, r.created_at, r.id`,
		tid, fmt.Sprintf("%d seconds", int(windowBefore.Seconds())), fmt.Sprintf("%d seconds", int(windowAfter.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("find released receipts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Candidate
	seen := map[string]bool{}
	for rows.Next() {
		var c Candidate
		var reportID string
		if err := rows.Scan(&c.TenantID, &c.ReceiptID, &c.ref, &c.Tool, &c.Received, &c.day, &c.SensorID, &reportID, &c.sensorName); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		if seen[c.ReceiptID] {
			continue // two items of one report id: the receipt is moved once
		}
		seen[c.ReceiptID] = true
		sid, err := shared.IDFromString(c.SensorID)
		if err != nil {
			continue
		}
		c.newRef = ingestreceipt.ReportRef(sid, reportID)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		var one int
		err := db.QueryRowContext(ctx, `SELECT 1 FROM ingest_receipts WHERE tenant_id = $1 AND source_kind = 'sensor' AND source_ref = $2`,
			out[i].TenantID, out[i].newRef).Scan(&one)
		switch {
		case err == nil:
			out[i].Conflict = true
		case !errors.Is(err, sql.ErrNoRows):
			return nil, fmt.Errorf("check conflict: %w", err)
		}
	}
	return out, nil
}

// move re-attributes one receipt in one transaction: the receipt, its tool
// rows, and the daily intake fact of its day.
func move(ctx context.Context, db *sql.DB, c *Candidate) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	// The receipt, only while it is still the connector receipt we found.
	res, err := tx.ExecContext(ctx, `
		UPDATE ingest_receipts SET source_kind = 'sensor', source_ref = $3, released_from_quarantine = true
		WHERE tenant_id = $1 AND id = $2 AND source_kind = 'connector'`, c.TenantID, c.ReceiptID, c.newRef)
	if err != nil {
		return fmt.Errorf("update receipt: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errors.New("the receipt changed meanwhile")
	}
	name := c.sensorName
	if len([]rune(name)) > 255 {
		name = string([]rune(name)[:255])
	}
	if _, err = tx.ExecContext(ctx, `
		UPDATE ingest_receipt_tools SET instance_kind = 'sensor', instance_id = $3, instance_name = $4, released_reports = reports
		WHERE tenant_id = $1 AND receipt_id = $2 AND instance_kind = 'connector'`, c.TenantID, c.ReceiptID, c.SensorID, name); err != nil {
		return fmt.Errorf("update tool rows: %w", err)
	}
	// The daily fact: take the receipt's counts off the connector row of its
	// day and add them to the sensor row.
	var d struct{ reports, received, created, still, reopened, closed, skipped, failed, suppressed int }
	if err = tx.QueryRowContext(ctx, `
		SELECT reports, findings_received, findings_created, findings_updated, findings_reopened, findings_closed,
			skipped, findings_failed, findings_suppressed
		FROM ingest_receipts WHERE tenant_id = $1 AND id = $2`, c.TenantID, c.ReceiptID).Scan(
		&d.reports, &d.received, &d.created, &d.still, &d.reopened, &d.closed, &d.skipped, &d.failed, &d.suppressed); err != nil {
		return fmt.Errorf("read receipt counts: %w", err)
	}
	tool := c.Tool
	if tool == "" {
		tool = ingestreceipt.UnknownTool
	}
	if _, err = tx.ExecContext(ctx, `
		UPDATE dash_ingest_day SET reports = GREATEST(reports - $4, 0), received = GREATEST(received - $5, 0),
			created = GREATEST(created - $6, 0), still_detected = GREATEST(still_detected - $7, 0),
			reopened = GREATEST(reopened - $8, 0), closed = GREATEST(closed - $9, 0), skipped = GREATEST(skipped - $10, 0),
			failed = GREATEST(failed - $11, 0), suppressed = GREATEST(suppressed - $12, 0)
		WHERE tenant_id = $1 AND day = ($2::timestamptz AT TIME ZONE 'UTC')::date AND source_kind = 'connector' AND tool = $3`,
		c.TenantID, c.day, tool, d.reports, d.received, d.created, d.still, d.reopened, d.closed, d.skipped, d.failed, d.suppressed); err != nil {
		return fmt.Errorf("take off connector fact: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO dash_ingest_day (tenant_id, day, source_kind, tool, reports, received, created, still_detected, reopened,
			closed, skipped, failed, suppressed)
		VALUES ($1, ($2::timestamptz AT TIME ZONE 'UTC')::date, 'sensor', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (tenant_id, day, source_kind, tool) DO UPDATE SET
			reports = dash_ingest_day.reports + EXCLUDED.reports, received = dash_ingest_day.received + EXCLUDED.received,
			created = dash_ingest_day.created + EXCLUDED.created, still_detected = dash_ingest_day.still_detected + EXCLUDED.still_detected,
			reopened = dash_ingest_day.reopened + EXCLUDED.reopened, closed = dash_ingest_day.closed + EXCLUDED.closed,
			skipped = dash_ingest_day.skipped + EXCLUDED.skipped, failed = dash_ingest_day.failed + EXCLUDED.failed,
			suppressed = dash_ingest_day.suppressed + EXCLUDED.suppressed`,
		c.TenantID, c.day, tool, d.reports, d.received, d.created, d.still, d.reopened, d.closed, d.skipped, d.failed, d.suppressed); err != nil {
		return fmt.Errorf("add sensor fact: %w", err)
	}
	return tx.Commit()
}

func render(r *Report) string {
	var b strings.Builder
	mode := "dry run, nothing changed"
	if r.Apply {
		mode = "applied"
	}
	fmt.Fprintf(&b, "receipt-reattribute (%s)\n", mode)
	for t, n := range r.ByTenant {
		fmt.Fprintf(&b, "  tenant %s: %d receipts\n", t, n)
	}
	fmt.Fprintf(&b, "receipts to move: %d, findings received on them: %d\n", r.Receipts, r.Received)
	fmt.Fprintf(&b, "left alone (a sensor receipt for the report already exists): %d\n", r.Conflicts)
	if r.Apply {
		fmt.Fprintf(&b, "moved: %d\n", r.Moved)
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
	fmt.Fprintln(os.Stderr, "receipt-reattribute: "+msg)
	os.Exit(code)
}
