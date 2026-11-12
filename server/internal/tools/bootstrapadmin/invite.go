package bootstrapadmin

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/openctemio/openctem/api/internal/adminbootstrap"
	"github.com/openctemio/openctem/api/pkg/brand"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// runInvite is `bootstrap-admin invite`: it adds an administrator by
// invitation from the host, for an install whose console cannot send e-mail
// (a new super admin is refused there while approvals are on). The link is
// printed once, so stdout must be a terminal unless -print-secrets is given.
func runInvite(args []string, getEnv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bootstrap-admin invite", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbURL := fs.String("db", "", "Database URL. Testing only: the password then shows in ps; use DATABASE_URL or DB_* env")
	email := fs.String("email", "", "Email of the new administrator")
	name := fs.String("name", "", "Display name (defaults to the email prefix)")
	role := fs.String("role", "ops_admin", "Role: super_admin, ops_admin, readonly")
	printSecrets := fs.Bool("print-secrets", false, "Print the link even when stdout is not a terminal")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "Error: "+format+"\n", a...)
		return 1
	}
	if !*printSecrets && !isTerminal(stdout) {
		return fail("stdout is not a terminal, and this command prints a one-time link. Run it attached to a terminal, or pass -print-secrets. Nothing was changed")
	}
	databaseURL := firstNonEmpty(*dbURL, getEnv("DATABASE_URL"), databaseURLFrom(getEnv))
	if databaseURL == "" {
		return fail("Database URL required: set DATABASE_URL, or DB_HOST/DB_USER/DB_PASSWORD/DB_NAME env vars")
	}
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return fail("Error connecting to database: %v", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return fail("Error pinging database: %v", err)
	}
	log := logger.New(logger.Config{Level: "warn", Format: "text", Output: stderr})
	o := adminbootstrap.InviteOptions{
		Email: *email, Name: *name, Role: *role,
		Actor:     commandActor(getEnv),
		UIBaseURL: firstNonEmpty(getEnv("SMTP_BASE_URL"), getEnv("APP_URL")),
		Logger:    log,
	}
	if mailer, merr := setupMailer(ctx, db, getEnv, stdout, log); merr == nil && mailer != nil {
		o.Notifier = rosterMailer{email: mailer, appName: firstNonEmpty(getEnv("BRAND_NAME"), brand.DefaultName)}
	}
	if err := adminbootstrap.Invite(ctx, db, o, stdout); err != nil {
		return fail("%v", err)
	}
	return 0
}
