// Package provideraddrcmd is the provider-addresses command: the one-time
// move of provider shared addresses (docs/architecture/provider-address-move.md,
// runbook docs/operations/provider-address-move.md). See
// internal/app/provideraddr.
//
//	DATABASE_URL  postgres connection string; when unset it is built from the
//	              server's DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME and
//	              DB_SSLMODE, so it runs as-is inside the API container
//
// Usage:
//
//	provider-addresses                     dry run for every organization:
//	                                       reads everything, changes nothing,
//	                                       writes one dry-run row per
//	                                       organization with the counts, and
//	                                       prints a plain-text report
//	provider-addresses -tenant <id>        dry run for one organization
//	provider-addresses -tenant <id> -apply apply for one organization:
//	                                       batched, resumable (run it again
//	                                       to continue), idempotent (a second
//	                                       apply changes nothing); one audit
//	                                       entry, one dashboard refresh and a
//	                                       one-time notice per organization
//	provider-addresses -tenant <id> -restore
//	                                       put back what applies changed for
//	                                       the organization, except addresses
//	                                       changed since (listed as changed)
//	provider-addresses -json               reports as JSON
//	provider-addresses -progress           one line per batch on stderr
//
// -apply and -restore always take one -tenant: a change is made one
// organization at a time. The command never runs by itself; nothing in the
// server starts it.
//
// Exit status: 0 success, 1 a run failed, 2 usage or connection error.
package provideraddrcmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/app/provideraddr"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/tools/toolaudit"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	pa "github.com/openctemio/openctem/server/pkg/domain/provideraddr"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

var _ provideraddr.Store = (*postgres.ProviderAddressMoveRepository)(nil)

const actor = "provider-addresses"

// Main runs the command with os.Args. It parses its flags on a fresh flag
// set: the server binary that dispatches to it (internal/server/tools.go)
// registers its own flags on flag.CommandLine at init.
func Main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	apply := flag.Bool("apply", false, "make the changes for one organization (default is a dry run)")
	restore := flag.Bool("restore", false, "put back what applies changed for one organization")
	tenantFlag := flag.String("tenant", "", "organization id (a dry run without it covers every organization)")
	batch := flag.Int("batch", provideraddr.DefaultBatchSize, "address assets read per batch")
	batchShared := flag.Int("batch-shared", provideraddr.DefaultMaxShared, "provider addresses changed per batch at most")
	maxBatches := flag.Int("max-batches", 0, "stop after this many batches (0 = until done; an apply or restore resumes later)")
	asJSON := flag.Bool("json", false, "print reports as JSON")
	progress := flag.Bool("progress", false, "print one line per batch (number, address assets read, time) to stderr")
	timeout := flag.Duration("timeout", 2*time.Hour, "overall time limit")
	flag.Parse()

	if *batch <= 0 || *batch > 5000 {
		fail(2, "-batch must be between 1 and 5000")
	}
	if *batchShared <= 0 || *batchShared > *batch {
		fail(2, "-batch-shared must be between 1 and -batch")
	}
	if *apply && *restore {
		fail(2, "-apply and -restore exclude each other")
	}
	mode := pa.ModeDryRun
	switch {
	case *apply:
		mode = pa.ModeApply
	case *restore:
		mode = pa.ModeRestore
	}
	if mode != pa.ModeDryRun && *tenantFlag == "" {
		fail(2, "-apply and -restore need -tenant <id>: changes are made one organization at a time")
	}
	dbURL := databaseURL()
	if dbURL == "" {
		fail(2, "DATABASE_URL (or DB_HOST/DB_*) must be set in the environment")
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
	os.Exit(run(ctx, db, *tenantFlag, mode, batchSize{read: *batch, shared: *batchShared}, *maxBatches, *asJSON, *progress))
}

// run runs the command against db; it returns the exit status.
// batchSize is how many address assets a batch reads and how many provider
// addresses it changes at most.
type batchSize struct{ read, shared int }

func run(ctx context.Context, db *sql.DB, tenantArg string, mode pa.Mode, batch batchSize, maxBatches int, asJSON, progress bool) int {
	pdb := &postgres.DB{DB: db}
	repo := postgres.NewProviderAddressMoveRepository(pdb)
	auditRepo := postgres.NewAuditRepository(pdb)
	runID := toolaudit.NewRunID()
	auditor := func(ctx context.Context, tenantID shared.ID, action audit.Action, counts map[string]int) error {
		return toolaudit.Record(ctx, auditRepo, toolaudit.Event{TenantID: tenantID, Action: action,
			ResourceType: audit.ResourceTypeAsset, Actor: actor, RunID: runID, Counts: counts})
	}
	svc := provideraddr.NewService(repo, auditor, postgres.NewDashboardFactsRepository(pdb))

	var tenants []shared.ID
	if tenantArg != "" {
		id, err := shared.IDFromString(tenantArg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "provider-addresses: -tenant is not an id")
			return 2
		}
		tenants = []shared.ID{id}
	} else {
		var err error
		if tenants, err = repo.ListTenants(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "provider-addresses: "+err.Error())
			return 1
		}
	}
	opts := provideraddr.Options{Mode: mode, BatchSize: batch.read, MaxShared: batch.shared, MaxBatches: maxBatches,
		Classifier: edgeaddr.Default(), Actor: actor}
	if progress {
		opts.Progress = func(n, read int, took time.Duration) {
			fmt.Fprintf(os.Stderr, "batch %d: %d rows, %d ms\n", n, read, took.Milliseconds())
		}
	}
	code := 0
	var reports []*provideraddr.Report
	for _, t := range tenants {
		rep, err := svc.Run(ctx, t, opts)
		if rep != nil {
			reports = append(reports, rep)
			if !asJSON {
				fmt.Println(provideraddr.Format(rep))
			}
		}
		if err != nil {
			code = 1
			msg := err.Error()
			if errors.Is(err, pa.ErrBusy) {
				msg = "another run holds this organization; try again when it ends"
			}
			fmt.Fprintf(os.Stderr, "provider-addresses: organization %s: %s\n", t, msg)
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			return 1
		}
	}
	return code
}

func fail(code int, msg string) {
	fmt.Fprintln(os.Stderr, "provider-addresses: "+msg)
	os.Exit(code)
}

// databaseURL returns DATABASE_URL, or builds it from the server's DB_*
// variables.
func databaseURL() string {
	if u := os.Getenv("DATABASE_URL"); u != "" {
		return u
	}
	host := os.Getenv("DB_HOST")
	if host == "" {
		return ""
	}
	port := os.Getenv("DB_PORT")
	if port == "" {
		port = "5432"
	}
	ssl := os.Getenv("DB_SSLMODE")
	if ssl == "" {
		ssl = "disable"
	}
	u := url.URL{Scheme: "postgres", User: url.UserPassword(os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD")),
		Host: host + ":" + port, Path: "/" + os.Getenv("DB_NAME"), RawQuery: "sslmode=" + url.QueryEscape(ssl)}
	return u.String()
}
