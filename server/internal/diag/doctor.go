// Package diag is the operator's self-service diagnosis of an installation:
// `server doctor` checks it and says what is wrong and how to fix it, and
// `server support-bundle` writes an archive that is safe to hand to someone
// who has no access to the installation's data
// (docs/operations/diagnose-and-get-support.md).
//
// Nothing here changes anything: every SQL statement runs in a read-only
// transaction with a statement timeout, and no check writes a file, a key or
// a setting. No result carries row data: counts, sizes, ages, versions and
// schema names only.
package diag

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/openctemio/openctem/server/internal/app/systemstatus"
	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/diag/redact"
	"github.com/openctemio/openctem/server/pkg/version"
)

// Status of one check.
type Status string

const (
	// StatusPass: the check found nothing wrong.
	StatusPass Status = "pass"
	// StatusWarn: works, but the operator should act.
	StatusWarn Status = "warn"
	// StatusFail: broken, or about to be.
	StatusFail Status = "fail"
	// StatusInfo: a fact reported without a judgement, or a check that
	// could not run.
	StatusInfo Status = "info"
)

// Check is one row of the doctor's table.
type Check struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status Status `json:"status"`
	// Summary is one sentence built from fixed words and numbers.
	Summary string `json:"summary"`
	// Fix says what to do; empty when there is nothing to do.
	Fix string `json:"fix,omitempty"`
	// Detail is the underlying error text. It may name a host or a role,
	// so a support bundle carries it masked (Report.Redacted).
	Detail string `json:"detail,omitempty"`
}

// Report is the doctor's result.
type Report struct {
	CheckedAt time.Time    `json:"checked_at"`
	Build     version.Info `json:"build"`
	Checks    []Check      `json:"checks"`
	Passed    int          `json:"passed"`
	Warnings  int          `json:"warnings"`
	Failed    int          `json:"failed"`
}

// ExitCode is 0 when no check failed, 1 otherwise.
func (r Report) ExitCode() int {
	if r.Failed > 0 {
		return 1
	}
	return 0
}

// Redacted returns the report with every detail masked, for a bundle.
func (r Report) Redacted(red *redact.Redactor) Report {
	out := r
	out.Checks = make([]Check, len(r.Checks))
	for i, c := range r.Checks {
		c.Detail = red.Message(c.Detail)
		out.Checks[i] = c
	}
	return out
}

// WriteJSON writes the report as indented JSON.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// WriteTable writes the report as a table, each row followed by its detail
// and its fix.
func (r Report) WriteTable(w io.Writer) {
	_, _ = fmt.Fprintf(w, "openctem-server %s\n\n", r.Build)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "STATUS\tCHECK\tRESULT")
	for _, c := range r.Checks {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", strings.ToUpper(string(c.Status)), c.Name, c.Summary)
		if c.Detail != "" {
			_, _ = fmt.Fprintf(tw, "\t\t  detail: %s\n", c.Detail)
		}
		if c.Fix != "" {
			_, _ = fmt.Fprintf(tw, "\t\t  fix: %s\n", c.Fix)
		}
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintf(w, "\n%d passed, %d warnings, %d failed\n", r.Passed, r.Warnings, r.Failed)
}

// Querier is what a check reads through: a read-only transaction.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Deps are the doctor's inputs. The server wires them from the loaded
// configuration; tests pass their own.
type Deps struct {
	// Config is the loaded configuration, nil when ConfigErr is set.
	Config    *config.Config
	ConfigErr error
	// Getenv reads the process environment (key presence and shape only;
	// no value is ever reported).
	Getenv func(string) (string, bool)

	// DB is the API's own connection, nil when DBErr is set.
	DB    *sql.DB
	DBErr error
	// OwnsAuditTables reports whether the connected role owns the audit
	// tables (the server's startup preflight).
	OwnsAuditTables func(ctx context.Context, q Querier) (bool, error)

	// PingRedis is nil when RedisErr is set.
	PingRedis func(ctx context.Context) error
	RedisErr  error

	// System collects the Health page's file and probe checks (free space,
	// backup status, certificate files, the web and gateway probes). Its
	// database reads are not used.
	System func(ctx context.Context) systemstatus.Snapshot

	MigrationsDir string
	// SensorLatest and SensorMin are the sensor release line this build
	// documents (the versions manifest).
	SensorLatest, SensorMin string

	// CertExpiry returns the expiry of the certificate the public URL
	// serves; nil skips the probe (--offline).
	CertExpiry func(ctx context.Context, hostPort string) (time.Time, error)

	// StatementTimeout bounds every SQL statement (default 5s).
	StatementTimeout time.Duration
	Now              func() time.Time
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d Deps) statementTimeout() time.Duration {
	if d.StatementTimeout > 0 {
		return d.StatementTimeout
	}
	return 5 * time.Second
}

// ReadOnly runs fn in a read-only transaction whose statements are cut at
// timeout. The transaction cannot be made read-write and is always rolled
// back.
func ReadOnly(ctx context.Context, db *sql.DB, timeout time.Duration, fn func(q Querier) error) error {
	if db == nil {
		return errNoDatabase
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	ms := timeout.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	// The values are integers this function formats itself.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", ms)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL lock_timeout = %d", ms)); err != nil {
		return err
	}
	// The first query fixes the transaction's mode: after it PostgreSQL
	// refuses a switch to read-write for the rest of the transaction.
	var one int
	if err := tx.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		return err
	}
	return fn(tx)
}

var errNoDatabase = fmt.Errorf("no database connection")

func (d Deps) readOnly(ctx context.Context, fn func(q Querier) error) error {
	return ReadOnly(ctx, d.DB, d.statementTimeout(), fn)
}

// Run runs every check, in a fixed order.
func Run(ctx context.Context, d Deps) Report {
	r := Report{CheckedAt: d.now().UTC(), Build: version.Get()}
	add := func(cs ...Check) { r.Checks = append(r.Checks, cs...) }

	add(d.checkBuild())
	add(d.checkConfig())
	add(d.checkBaseURL())
	add(d.checkKeys()...)

	dbUp := d.checkDatabase(ctx)
	add(dbUp)
	if dbUp.Status == StatusPass {
		add(d.checkRole(ctx), d.checkMigrations(ctx), d.checkClock(ctx))
	}
	add(d.checkRedis(ctx))

	var snap *systemstatus.Snapshot
	if d.System != nil {
		s := d.System(ctx)
		snap = &s
	}
	add(d.checkCertificates(ctx, snap)...)
	add(d.checkStorage(snap), d.checkBackup(snap))
	add(d.checkServices(snap)...)

	if dbUp.Status == StatusPass {
		add(d.checkQueue(ctx)...)
		add(d.checkSensors(ctx)...)
		add(d.checkAuditChain(ctx))
	}

	for _, c := range r.Checks {
		switch c.Status {
		case StatusPass:
			r.Passed++
		case StatusWarn:
			r.Warnings++
		case StatusFail:
			r.Failed++
		case StatusInfo:
		}
	}
	return r
}

func (d Deps) checkBuild() Check {
	b := version.Get()
	exts := "no extensions"
	if len(b.Extensions) > 0 {
		names := make([]string, 0, len(b.Extensions))
		for _, e := range b.Extensions {
			names = append(names, strings.TrimSpace(e.Name+" "+e.Version))
		}
		exts = fmt.Sprintf("%d extensions loaded (%s)", len(names), strings.Join(names, ", "))
	}
	built := ""
	if b.BuildTime != "" {
		built = ", built " + b.BuildTime
	}
	return Check{ID: "build", Name: "Build", Status: StatusInfo,
		Summary: fmt.Sprintf("Version %s, commit %s%s, channel %s, %s.", b.Version, b.Commit, built, b.Channel, exts)}
}
