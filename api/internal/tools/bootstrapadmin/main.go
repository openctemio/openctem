// Package bootstrapadmin is the bootstrap-admin command: a CLI tool to create the first platform administrators.
// This is used during initial deployment to bootstrap the admin system.
//
// A platform administrator (RFC-022) is a normal sign-in account (users table)
// that belongs to no organization, linked to an admin_users row that holds the
// role and the authenticator. The administrator signs in on the console's own
// site (ADMIN_PUBLIC_URL) with a TOTP code. Administrators have no API
// keys. This tool creates both: a new admin row and a new sign-in account with
// a temporary password, printed once. An email that already has an account is
// refused (see createAccount).
//
// It creates two administrators in one run (RFC-022 revision 4): the primary
// one and a backup break-glass super admin. The backup is local (never bound to
// an identity provider), exempt from "require IdP", and every sign-in with it
// is alerted, so the console stays reachable when the IdP is down. Both must
// change their temporary password and enroll an authenticator on first use.
//
// With -org-name and -org-owner-email it also creates the first organization
// (organizations are created by the platform administrator,
// SIGNUP_MODE=disabled by default). It
// goes through the same services as the admin console's Organizations ->
// Create: audited tenant.created and user.created, the owner's membership and
// role, and a one-time set-password link for a new owner, emailed when SMTP is
// configured (SMTP_*), otherwise printed once here. A failed send prints it
// once too, with a warning (never to a log).
//
// The run is idempotent: an administrator that already exists is reported and
// left alone, so re-running with -backup-email adds a backup to an existing
// installation; an organization whose slug exists is reported and left alone.
//
// Accountability: every administrator it creates, replaces (-force) or links
// (-link) is written in one transaction with an entry in the administrators'
// hash-chained audit log (admin.created, admin.replaced, admin.relinked; actor
// bootstrap-admin, with the OS user and host), and the other active
// administrators are emailed when the platform e-mail is configured (a
// warning is printed when it is not). -force replaces only the -email
// administrator and keeps its role unless -role is given; it refuses to bring
// back an inactive administrator without -role, and to leave the platform with
// no active super admin. -force-backup replaces the break-glass backup. Each
// replacement is confirmed by typing the email back on a terminal, or with
// -yes.
//
// Secrets: the temporary passwords and the set-password link are printed once
// to stdout. When stdout is not a terminal the command refuses to run unless
// -print-secrets is given. The database credentials come from the
// environment, never from argv: -db exists for tests only, because a password
// on the command line shows in ps and the shell history.
//
// Usage (DATABASE_URL, or DB_HOST/DB_USER/DB_PASSWORD/DB_NAME with
// DB_MIGRATE_USER/DB_MIGRATE_PASSWORD, in the environment):
//
//	# Create the first administrator and its break-glass backup
//	./bootstrap-admin -email=admin@example.com -backup-email=breakglass@example.com
//
//	# ...and the first organization, owned by a new account
//	./bootstrap-admin -email=admin@example.com -backup-email=breakglass@example.com \
//	    -org-name="Acme Security" -org-owner-email=owner@example.com
//
//	# Only the primary (not recommended; prints a warning)
//	./bootstrap-admin -email=admin@example.com -no-backup
//
//	# Replace a lost primary administrator (asks to type the email back)
//	./bootstrap-admin -email=admin@example.com -backup-email=breakglass@example.com -force
//
//	# Link an existing administrator (created before sign-in accounts were
//	# linked) to a sign-in account, keeping its role and authenticator
//	./bootstrap-admin -email=admin@example.com -link
//
//	# A single-use enrollment token for the bundled shared sensor (sensor_token.go)
//	./bootstrap-admin sensor-token -from-env SENSOR_INSTANCE_ENROLLMENT_TOKEN
//
//	# Copy the server file storage between local and S3 (storage_migrate.go)
//	./bootstrap-admin storage migrate -from local -to s3 -local-path /app/data/attachments -dry-run
//
//	# In Compose: a one-shot container attached to the terminal
//	docker compose run --rm bootstrap-admin -email=admin@example.com -backup-email=bg@example.com
package bootstrapadmin

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/adminbootstrap"
	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/platformemail"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/brand"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Main runs the command with os.Args. It parses its flags on a fresh flag
// set: the server binary that dispatches to it (see cmd/server/tools.go)
// registers its own flags on flag.CommandLine at init.
func Main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	// `bootstrap-admin storage migrate ...`: copy the server file storage
	// between local and S3 (storage_migrate.go).
	if len(os.Args) > 1 && os.Args[1] == "storage" {
		os.Exit(runStorage(os.Args[2:]))
	}
	// `bootstrap-admin sensor-token ...`: a single-use enrollment token for
	// the install's bundled shared sensor (sensor_token.go).
	if len(os.Args) > 1 && os.Args[1] == "sensor-token" {
		os.Exit(runSensorToken(os.Args[2:]))
	}
	// `bootstrap-admin verify-audit`: check the administrators' audit chain
	// (verify_audit.go).
	if len(os.Args) > 1 && os.Args[1] == "verify-audit" {
		os.Exit(runVerifyAudit(os.Args[2:], os.Stdout, os.Stderr))
	}
	os.Exit(runBootstrap(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}

// runBootstrap is the admin-creating command (everything but the
// subcommands). It returns the exit code.
func runBootstrap(args []string, getEnv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbURL := fs.String("db", "", "Database URL. Testing only: the password then shows in ps and the shell history; use DATABASE_URL or DB_* env")
	email := fs.String("email", "", "Admin email (or set ADMIN_EMAIL env)")
	name := fs.String("name", "", "Admin name (defaults to email prefix)")
	role := fs.String("role", "", "Admin role: super_admin, ops_admin, readonly. A new admin defaults to super_admin; with -force the existing role is kept unless -role is given")
	backupEmail := fs.String("backup-email", "", "Break-glass backup admin email (or set ADMIN_BACKUP_EMAIL env)")
	backupName := fs.String("backup-name", "", "Break-glass backup admin name (defaults to email prefix)")
	noBackup := fs.Bool("no-backup", false, "Do not create a break-glass backup admin (not recommended)")
	force := fs.Bool("force", false, "Delete and re-create the existing -email admin (new account and temporary password; keeps its role unless -role is given; never touches the backup)")
	forceBackup := fs.Bool("force-backup", false, "Delete and re-create the existing break-glass backup admin (-backup-email)")
	yes := fs.Bool("yes", false, "Confirm -force/-force-backup without typing the email back (needed without a terminal)")
	printSecrets := fs.Bool("print-secrets", false, "Print the temporary passwords and set-password link even when stdout is not a terminal (they then reach whatever stdout is: a file, a pipe, a log)")
	linkOnly := fs.Bool("link", false, "Only link the existing admin with this email (one from v0.8 or older) to a new sign-in account and reactivate it (keeps role and authenticator)")
	orgName := fs.String("org-name", "", "Create the first organization with this name (or set ORG_NAME env); needs -org-owner-email")
	orgSlug := fs.String("org-slug", "", "URL slug of the first organization (or set ORG_SLUG env; derived from -org-name when empty)")
	orgOwnerEmail := fs.String("org-owner-email", "", "Owner of the first organization (or set ORG_OWNER_EMAIL env); a new account gets a one-time set-password link")
	orgOwnerName := fs.String("org-owner-name", "", "Owner's display name for a new account (or set ORG_OWNER_NAME env)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		msg := fmt.Sprintf(format, a...)
		if !strings.HasSuffix(msg, "\n") {
			msg += "\n"
		}
		fmt.Fprint(stderr, "Error: "+msg)
		return 1
	}

	// The temporary passwords and the set-password link are printed once.
	// Without a terminal they would land in a container log, a CI log or a
	// file, so the run is refused before anything is created.
	if !*printSecrets && !isTerminal(stdout) {
		return fail("stdout is not a terminal, and this command prints one-time credentials. " +
			"Run it attached to a terminal (docker compose run --rm bootstrap-admin ...), " +
			"or pass -print-secrets if the output is meant to be captured. Nothing was changed")
	}

	log := logger.New(logger.Config{Level: "warn", Format: "text", Output: stderr})

	opts := adminbootstrap.Options{
		Email:       firstNonEmpty(*email, getEnv("ADMIN_EMAIL")),
		Name:        firstNonEmpty(*name, getEnv("ADMIN_NAME")),
		Role:        *role,
		BackupEmail: firstNonEmpty(*backupEmail, getEnv("ADMIN_BACKUP_EMAIL")),
		BackupName:  firstNonEmpty(*backupName, getEnv("ADMIN_BACKUP_NAME")),
		NoBackup:    *noBackup,
		Force:       *force,
		ForceBackup: *forceBackup,
		Yes:         *yes,
		LinkOnly:    *linkOnly,
		Actor:       commandActor(getEnv),

		OrgName:       firstNonEmpty(*orgName, getEnv("ORG_NAME")),
		OrgSlug:       firstNonEmpty(*orgSlug, getEnv("ORG_SLUG")),
		OrgOwnerEmail: firstNonEmpty(*orgOwnerEmail, getEnv("ORG_OWNER_EMAIL")),
		OrgOwnerName:  firstNonEmpty(*orgOwnerName, getEnv("ORG_OWNER_NAME")),
		// The printed link uses the UI origin the server would put in the
		// email; without one it prints a <ui-url> placeholder.
		UIBaseURL: firstNonEmpty(getEnv("SMTP_BASE_URL"), getEnv("APP_URL")),
		// The console has its own site; its origin is printed when known.
		AdminPublicURL: getEnv("ADMIN_PUBLIC_URL"),
		Logger:         log,
	}
	if isTerminal(stdin) {
		opts.Confirm = typedConfirmation(stdin, stderr)
	}
	if err := opts.Normalize(); err != nil {
		return fail("%v", err)
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
	pingCtx, cancelPing := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelPing()
	if err := db.PingContext(pingCtx); err != nil {
		return fail("Error pinging database: %v", err)
	}

	// Long enough for the operator to type a confirmation.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	mailer, err := setupMailer(ctx, db, getEnv, stdout, log)
	if err != nil {
		return fail("%v", err)
	}
	if mailer != nil {
		opts.OrgSetupMailer = mailer
		opts.Notifier = rosterMailer{email: mailer, appName: firstNonEmpty(getEnv("BRAND_NAME"), brand.DefaultName)}
	}

	if err := adminbootstrap.Run(ctx, db, opts, stdout); err != nil {
		return fail("%v", err)
	}
	return 0
}

// isTerminal reports whether f is a character device (a terminal). Anything
// that is not an *os.File (a buffer in tests) is not one.
func isTerminal(f any) bool {
	file, ok := f.(*os.File)
	if !ok {
		return false
	}
	st, err := file.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// typedConfirmation asks for the email of an administrator about to be
// replaced to be typed back.
func typedConfirmation(stdin io.Reader, prompt io.Writer) func(string) bool {
	in := bufio.NewReader(stdin)
	return func(email string) bool {
		fmt.Fprintf(prompt, "Type %s to confirm replacing it: ", email)
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return false
		}
		return strings.EqualFold(strings.TrimSpace(line), email)
	}
}

// commandActor names who ran the command for the audit entry: the account
// that invoked sudo, else the login user, else the process's own user; and
// the host (in a container, its host name).
func commandActor(getEnv func(string) string) adminbootstrap.Actor {
	who := firstNonEmpty(getEnv("SUDO_USER"), getEnv("USER"), getEnv("LOGNAME"))
	if who == "" {
		if u, err := user.Current(); err == nil {
			who = u.Username
		} else {
			who = "uid " + strconv.Itoa(os.Getuid())
		}
	}
	host, _ := os.Hostname()
	return adminbootstrap.Actor{OSUser: who, Hostname: host}
}

// rosterMailer sends the roster-change notice to the other administrators
// synchronously (the command exits right after), with the same subject and
// body as the console's notice.
type rosterMailer struct {
	email   *authapp.EmailService
	appName string
}

func (m rosterMailer) NotifyRosterChange(ctx context.Context, c adminconsole.RosterChange) error {
	subject, body := adminconsole.RosterChangeEmail(m.appName, c)
	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return m.email.SendReport(sendCtx, "", c.Recipients, subject, body)
}

// setupMailer returns the platform e-mail sender: it emails the first
// organization owner's set-password link and tells the other administrators
// what the run changed (admin console, Settings > E-mail). For a headless
// install, BOOTSTRAP_SMTP_HOST (with _PORT, _USER, _PASSWORD, _FROM,
// _FROM_NAME, _STARTTLS) stores those settings first, when none are stored,
// encrypted with APP_ENCRYPTION_KEY. Without e-mail it returns nil, and the
// link is printed instead.
func setupMailer(ctx context.Context, db *sql.DB, getEnv func(string) string, out io.Writer, log *logger.Logger) (*authapp.EmailService, error) {
	key := getEnv("APP_ENCRYPTION_KEY")
	if key == "" {
		return nil, nil
	}
	enc, err := crypto.NewCipherFromKey(key, getEnv("APP_ENCRYPTION_KEY_FORMAT"))
	if err != nil {
		return nil, errors.New("APP_ENCRYPTION_KEY is not a valid key")
	}
	svc := platformemail.NewService(postgres.NewPlatformSettingRepository(&postgres.DB{DB: db}), enc, nil, log)
	if host := getEnv("BOOTSTRAP_SMTP_HOST"); host != "" {
		port, err := strconv.Atoi(firstNonEmpty(getEnv("BOOTSTRAP_SMTP_PORT"), "587"))
		if err != nil {
			return nil, errors.New("BOOTSTRAP_SMTP_PORT is not a number")
		}
		var password *string
		if p, ok := os.LookupEnv("BOOTSTRAP_SMTP_PASSWORD"); ok {
			password = &p
		}
		startTLS := getEnv("BOOTSTRAP_SMTP_STARTTLS") != "false"
		created, err := svc.Seed(ctx, platformemail.Input{
			Host: host, Port: port, Username: getEnv("BOOTSTRAP_SMTP_USER"), Password: password,
			From: getEnv("BOOTSTRAP_SMTP_FROM"), FromName: firstNonEmpty(getEnv("BOOTSTRAP_SMTP_FROM_NAME"), getEnv("BRAND_NAME"), brand.DefaultName), StartTLS: startTLS,
		})
		if err != nil {
			return nil, fmt.Errorf("BOOTSTRAP_SMTP_*: %w", err)
		}
		if created {
			fmt.Fprintln(out, "Platform e-mail settings stored from BOOTSTRAP_SMTP_* (change them in the admin console, Settings > E-mail).")
		} else {
			fmt.Fprintln(out, "Platform e-mail settings already stored; BOOTSTRAP_SMTP_* ignored.")
		}
	}
	mailer := authapp.NewEmailService(svc.Sender(), config.SMTPFromEnv(), firstNonEmpty(getEnv("BRAND_NAME"), brand.DefaultName), log)
	if !mailer.IsConfigured() {
		return nil, nil
	}
	return mailer, nil
}

// databaseURLFromParts builds a URL from DB_* variables (containers that use
// separate DB_* vars). net/url escapes each part, so a password with @ : / ? #
// or % in it reaches the server as written.
func databaseURLFromParts() string { return databaseURLFrom(os.Getenv) }

func databaseURLFrom(getEnv func(string) string) string {
	dbHost := getEnv("DB_HOST")
	dbUser := getEnv("DB_USER")
	dbPassword := getEnv("DB_PASSWORD")
	// With a separate console role the app role cannot write admin_users, and
	// the console role itself cannot create or delete the sign-in account in
	// users, so the CLI connects as the schema owner (DB_MIGRATE_USER).
	if u := getEnv("DB_MIGRATE_USER"); u != "" {
		dbUser, dbPassword = u, getEnv("DB_MIGRATE_PASSWORD")
	}
	dbName := getEnv("DB_NAME")
	if dbHost == "" || dbUser == "" || dbPassword == "" || dbName == "" {
		return ""
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(dbUser, dbPassword),
		Host:     net.JoinHostPort(dbHost, firstNonEmpty(getEnv("DB_PORT"), "5432")),
		Path:     "/" + dbName,
		RawQuery: url.Values{"sslmode": {firstNonEmpty(getEnv("DB_SSLMODE"), "disable")}}.Encode(),
	}
	return u.String()
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
