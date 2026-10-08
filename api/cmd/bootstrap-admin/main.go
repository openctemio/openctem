// Package main provides a CLI tool to create the first platform administrators.
// This is used during initial deployment to bootstrap the admin system.
//
// A platform administrator (RFC-022) is a normal sign-in account (users table)
// that belongs to no organization, linked to an admin_users row that holds the
// role and the authenticator. The administrator signs in on the normal /login
// page and opens the admin console with a TOTP code. Administrators have no API
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
// TENANT_CREATION_MODE=admin_only by default). It
// goes through the same services as the admin console's Organizations ->
// Create: audited tenant.created and user.created, the owner's membership and
// role, and a one-time set-password link for a new owner, emailed when SMTP is
// configured (SMTP_*), otherwise printed once here.
//
// The run is idempotent: an administrator that already exists is reported and
// left alone, so re-running with -backup-email adds a backup to an existing
// installation; an organization whose slug exists is reported and left alone.
//
// Usage:
//
//	# Create the first administrator and its break-glass backup
//	./bootstrap-admin -db=$DATABASE_URL -email=admin@example.com -backup-email=breakglass@example.com
//
//	# ...and the first organization, owned by a new account
//	./bootstrap-admin -db=$DATABASE_URL -email=admin@example.com -backup-email=breakglass@example.com \
//	    -org-name="Acme Security" -org-owner-email=owner@example.com
//
//	# Only the primary (not recommended; prints a warning)
//	./bootstrap-admin -db=$DATABASE_URL -email=admin@example.com -no-backup
//
//	# Link an existing administrator (created before sign-in accounts were
//	# linked) to a sign-in account, keeping its role and authenticator
//	./bootstrap-admin -db=$DATABASE_URL -email=admin@example.com -link
//
//	# Or via environment variables
//	DATABASE_URL=postgres://... ADMIN_EMAIL=admin@example.com ADMIN_BACKUP_EMAIL=bg@example.com \
//	    ORG_NAME="Acme Security" ORG_OWNER_EMAIL=owner@example.com ./bootstrap-admin
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/adminbootstrap"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/email"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func main() {
	dbURL := flag.String("db", "", "Database URL (or set DATABASE_URL env)")
	email := flag.String("email", "", "Admin email (or set ADMIN_EMAIL env)")
	name := flag.String("name", "", "Admin name (defaults to email prefix)")
	role := flag.String("role", "super_admin", "Admin role: super_admin, ops_admin, readonly")
	backupEmail := flag.String("backup-email", "", "Break-glass backup admin email (or set ADMIN_BACKUP_EMAIL env)")
	backupName := flag.String("backup-name", "", "Break-glass backup admin name (defaults to email prefix)")
	noBackup := flag.Bool("no-backup", false, "Do not create a break-glass backup admin (not recommended)")
	force := flag.Bool("force", false, "Delete and re-create an existing admin with the same email")
	linkOnly := flag.Bool("link", false, "Only link the existing admin with this email (one from v0.8 or older) to a new sign-in account and reactivate it (keeps role and authenticator)")
	orgName := flag.String("org-name", "", "Create the first organization with this name (or set ORG_NAME env); needs -org-owner-email")
	orgSlug := flag.String("org-slug", "", "URL slug of the first organization (or set ORG_SLUG env; derived from -org-name when empty)")
	orgOwnerEmail := flag.String("org-owner-email", "", "Owner of the first organization (or set ORG_OWNER_EMAIL env); a new account gets a one-time set-password link")
	orgOwnerName := flag.String("org-owner-name", "", "Owner's display name for a new account (or set ORG_OWNER_NAME env)")
	flag.Parse()

	log := logger.New(logger.Config{Level: "warn", Format: "text", Output: os.Stderr})

	opts := adminbootstrap.Options{
		Email:       firstNonEmpty(*email, os.Getenv("ADMIN_EMAIL")),
		Name:        firstNonEmpty(*name, os.Getenv("ADMIN_NAME")),
		Role:        *role,
		BackupEmail: firstNonEmpty(*backupEmail, os.Getenv("ADMIN_BACKUP_EMAIL")),
		BackupName:  firstNonEmpty(*backupName, os.Getenv("ADMIN_BACKUP_NAME")),
		NoBackup:    *noBackup,
		Force:       *force,
		LinkOnly:    *linkOnly,

		OrgName:       firstNonEmpty(*orgName, os.Getenv("ORG_NAME")),
		OrgSlug:       firstNonEmpty(*orgSlug, os.Getenv("ORG_SLUG")),
		OrgOwnerEmail: firstNonEmpty(*orgOwnerEmail, os.Getenv("ORG_OWNER_EMAIL")),
		OrgOwnerName:  firstNonEmpty(*orgOwnerName, os.Getenv("ORG_OWNER_NAME")),
		// The printed link uses the UI origin the server would put in the
		// email; without one it prints a <ui-url> placeholder.
		UIBaseURL: firstNonEmpty(os.Getenv("SMTP_BASE_URL"), os.Getenv("APP_URL")),
		Logger:    log,
	}
	if err := opts.Normalize(); err != nil {
		fatal("%v", err)
	}
	opts.OrgSetupMailer = setupMailer(log)

	databaseURL := firstNonEmpty(*dbURL, os.Getenv("DATABASE_URL"), databaseURLFromParts())
	if databaseURL == "" {
		fatal("Database URL required. Use -db flag, set DATABASE_URL, or set DB_HOST/DB_USER/DB_PASSWORD/DB_NAME env vars")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		fatal("Error connecting to database: %v", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		fatal("Error pinging database: %v", err)
	}

	if err := adminbootstrap.Run(ctx, db, opts, os.Stdout); err != nil {
		fatal("%v", err)
	}
}

// setupMailer emails the first organization owner's set-password link through
// the system SMTP (SMTP_* env, the same settings the server uses). Without
// SMTP it returns nil (an untyped nil interface, never a nil *EmailService)
// and the link is printed instead.
func setupMailer(log *logger.Logger) tenantapp.AccountSetupMailer {
	smtp := config.SMTPFromEnv()
	if !smtp.IsConfigured() {
		return nil
	}
	sender := email.NewSMTPSender(email.Config{
		Host:       smtp.Host,
		Port:       smtp.Port,
		User:       smtp.User,
		Password:   smtp.Password,
		From:       smtp.From,
		FromName:   smtp.FromName,
		TLS:        smtp.TLS,
		SkipVerify: smtp.SkipVerify,
		Timeout:    smtp.Timeout,
	})
	return authapp.NewEmailService(sender, smtp, firstNonEmpty(os.Getenv("APP_NAME"), "openctem"), log)
}

// databaseURLFromParts builds a URL from DB_* variables (containers that use
// separate DB_* vars).
func databaseURLFromParts() string {
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	if dbHost == "" || dbUser == "" || dbPassword == "" || dbName == "" {
		return ""
	}
	dbPort := firstNonEmpty(os.Getenv("DB_PORT"), "5432")
	dbSSLMode := firstNonEmpty(os.Getenv("DB_SSLMODE"), "disable")
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", dbUser, dbPassword, dbHost, dbPort, dbName, dbSSLMode)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprint(os.Stderr, "Error: "+msg)
	os.Exit(1)
}
