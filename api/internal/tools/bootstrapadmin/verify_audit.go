package bootstrapadmin

// `bootstrap-admin verify-audit` checks the administrators' audit log: the
// append-only, hash-chained admin_audit_logs table (migration 002545). It
// recomputes every online row with the database's own hash function and
// checks the links from the newest retention anchor to the tail. Exit 0 when
// every row verifies, 1 when one does not, 2 on a usage or connection error.
//
//	docker compose run --rm admin-cli verify-audit
//	DATABASE_URL=... ./bootstrap-admin verify-audit [-json]
//
// The database URL comes from the environment (DATABASE_URL or DB_*). The -db
// flag is for tests only: a password on the command line shows in ps.

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

func runVerifyAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbURL := fs.String("db", "", "Database URL. Testing only: the password then shows in ps; use DATABASE_URL or DB_* env")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	url := firstNonEmpty(*dbURL, os.Getenv("DATABASE_URL"), databaseURLFromParts())
	if url == "" {
		fmt.Fprintln(stderr, "verify-audit: database URL required (DATABASE_URL or DB_HOST/DB_USER/DB_PASSWORD/DB_NAME)")
		return 2
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		fmt.Fprintln(stderr, "verify-audit: open database:", err)
		return 2
	}
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	report, err := postgres.NewAuditLogRepository(&postgres.DB{DB: db}).VerifyChain(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "verify-audit:", err)
		return 2
	}
	printAuditReport(stdout, report, *asJSON)
	if !report.OK() {
		return 1
	}
	return 0
}

func printAuditReport(w io.Writer, r *admin.AuditChainReport, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		return
	}
	fmt.Fprintf(w, "administrators' audit chain: %d rows online (positions %d-%d)", r.Entries, r.FirstPosition, r.LastPosition)
	if r.AnchorPosition > 0 {
		fmt.Fprintf(w, ", pruned up to %d", r.AnchorPosition)
	}
	fmt.Fprintln(w)
	if r.OK() {
		fmt.Fprintln(w, "OK: every row verifies")
		return
	}
	fmt.Fprintf(w, "BROKEN: %d rows do not verify", len(r.Breaks))
	if r.Truncated {
		fmt.Fprint(w, " (more not listed)")
	}
	fmt.Fprintln(w)
	for _, b := range r.Breaks {
		fmt.Fprintf(w, "  position %d  row %s  %s\n", b.Position, b.ID, b.Reason)
	}
}
