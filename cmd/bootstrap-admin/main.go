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
// The run is idempotent: an administrator that already exists is reported and
// left alone, so re-running with -backup-email adds a backup to an existing
// installation.
//
// Usage:
//
//	# Create the first administrator and its break-glass backup
//	./bootstrap-admin -db=$DATABASE_URL -email=admin@example.com -backup-email=breakglass@example.com
//
//	# Only the primary (not recommended; prints a warning)
//	./bootstrap-admin -db=$DATABASE_URL -email=admin@example.com -no-backup
//
//	# Link an existing administrator (created before sign-in accounts were
//	# linked) to a sign-in account, keeping its role and authenticator
//	./bootstrap-admin -db=$DATABASE_URL -email=admin@example.com -link
//
//	# Or via environment variables
//	DATABASE_URL=postgres://... ADMIN_EMAIL=admin@example.com ADMIN_BACKUP_EMAIL=bg@example.com ./bootstrap-admin
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

	"github.com/openctemio/api/internal/adminbootstrap"
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
	linkOnly := flag.Bool("link", false, "Only link the existing admin with this email to a sign-in account (keeps role and authenticator)")
	flag.Parse()

	opts := adminbootstrap.Options{
		Email:       firstNonEmpty(*email, os.Getenv("ADMIN_EMAIL")),
		Name:        firstNonEmpty(*name, os.Getenv("ADMIN_NAME")),
		Role:        *role,
		BackupEmail: firstNonEmpty(*backupEmail, os.Getenv("ADMIN_BACKUP_EMAIL")),
		BackupName:  firstNonEmpty(*backupName, os.Getenv("ADMIN_BACKUP_NAME")),
		NoBackup:    *noBackup,
		Force:       *force,
		LinkOnly:    *linkOnly,
	}
	if err := opts.Normalize(); err != nil {
		fatal("%v", err)
	}

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
