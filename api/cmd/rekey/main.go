// Command rekey re-encrypts every value stored under APP_ENCRYPTION_KEY with a
// new key, in one database transaction. See internal/app/rekey for the list of
// locations and docs/operations/encryption-key-rotation.md for the runbook.
//
// The keys are read from the environment only, never from flags, so they do
// not appear in shell history or the process list, and they are never printed:
//
//	DATABASE_URL     postgres connection string; when unset it is built from
//	                 the server's DB_HOST, DB_PORT, DB_USER, DB_PASSWORD,
//	                 DB_NAME and DB_SSLMODE, so it runs as-is inside the API
//	                 container
//	REKEY_OLD_KEY    the key the values are encrypted with now
//	REKEY_NEW_KEY    the key to re-encrypt them with
//	REKEY_OLD_KEY_FORMAT / REKEY_NEW_KEY_FORMAT  optional: hex|base64|raw
//	                 (default: detected from the length, like the server)
//
// Usage:
//
//	rekey            dry run: re-encrypt inside a transaction, report, roll back
//	rekey -apply     the same, then commit
//
// Exit status: 0 success, 1 a value neither key opens (or OLD-key ciphertext
// outside the known locations; nothing committed), 2 usage or connection error.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/rekey"
)

func main() {
	apply := flag.Bool("apply", false, "commit the re-encryption (default is a dry run that rolls back)")
	dryRun := flag.Bool("dry-run", false, "report only and roll back (the default; cannot be combined with -apply)")
	sweep := flag.Bool("sweep", true, "also scan every text/bytea/jsonb column for OLD-key ciphertext outside the known locations")
	timeout := flag.Duration("timeout", 10*time.Minute, "overall time limit")
	flag.Parse()

	if *apply && *dryRun {
		fail(2, "-apply and -dry-run are mutually exclusive")
	}
	dbURL := databaseURL()
	keys := rekey.Keys{
		Old: os.Getenv("REKEY_OLD_KEY"), OldFormat: os.Getenv("REKEY_OLD_KEY_FORMAT"),
		New: os.Getenv("REKEY_NEW_KEY"), NewFormat: os.Getenv("REKEY_NEW_KEY_FORMAT"),
	}
	if dbURL == "" || keys.Old == "" || keys.New == "" {
		fail(2, "DATABASE_URL (or DB_HOST/DB_*), REKEY_OLD_KEY and REKEY_NEW_KEY must be set in the environment")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fail(2, "open database: "+err.Error())
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		fail(2, "connect database: "+err.Error())
	}

	mode := "DRY RUN (rolled back)"
	if *apply {
		mode = "APPLY"
	}
	fmt.Printf("rekey: %s\n\n", mode)

	rep, err := rekey.Run(ctx, db, keys, rekey.Options{Apply: *apply, Sweep: *sweep})
	if rep != nil {
		printReport(rep)
	}
	switch {
	case errors.Is(err, rekey.ErrFailures):
		fail(1, err.Error())
	case err != nil:
		fail(2, err.Error())
	}
	if rep.Committed {
		fmt.Println("\ncommitted. Set APP_ENCRYPTION_KEY to the new key; keep the old one in APP_ENCRYPTION_KEY_PREVIOUS until the API keys, SCIM tokens and sensor keys issued under it are rotated.")
	} else {
		fmt.Println("\nnothing written (dry run). Re-run with -apply to commit.")
	}
}

func printReport(rep *rekey.Report) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "LOCATION\tRE-ENCRYPTED\tALREADY NEW\tNOT CIPHERTEXT\tFAILED")
	for _, c := range rep.Counts {
		if c.Absent {
			_, _ = fmt.Fprintf(w, "%s\t-\t-\t-\t-\t(not in this schema)\n", c.Location)
			continue
		}
		_, _ = fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\n", c.Location, c.Rekeyed, c.Already, c.NotCipher, c.Failed)
	}
	r, a, f := rep.Total()
	_, _ = fmt.Fprintf(w, "TOTAL\t%d\t%d\t%d\t%d\n", r, a, len(rep.NotCipher), f)
	_ = w.Flush()
	for _, f := range rep.Failures {
		fmt.Printf("FAILED   %s row %s: %s\n", f.Location, f.Key, f.Reason)
	}
	for _, f := range rep.NotCipher {
		fmt.Printf("SKIPPED  %s row %s: %s\n", f.Location, f.Key, f.Reason)
	}
	for _, f := range rep.Unlisted {
		fmt.Printf("UNLISTED %s (%s): %s\n", f.Location, f.Key, f.Reason)
	}
}

// databaseURL returns DATABASE_URL, else a URL built from the server's DB_*
// variables (the password is escaped and never printed).
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

func fail(code int, msg string) {
	if !strings.HasPrefix(msg, "rekey:") {
		msg = "rekey: " + msg
	}
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(code)
}
