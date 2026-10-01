// Package adminbootstrap creates the first platform administrators and their
// break-glass backup (the bootstrap-admin command, RFC-022 revision 4).
package adminbootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/api/pkg/password"
)

// Options are the command-line inputs; call Normalize before Run.
type Options struct {
	Email       string
	Name        string
	Role        string
	BackupEmail string
	BackupName  string
	NoBackup    bool
	Force       bool
	LinkOnly    bool
}

// Normalize validates the inputs and fills defaults.
func (o *Options) Normalize() error {
	o.Email = strings.ToLower(strings.TrimSpace(o.Email))
	o.BackupEmail = strings.ToLower(strings.TrimSpace(o.BackupEmail))
	if o.Email == "" {
		return errors.New("admin email required. Use -email flag or set ADMIN_EMAIL env")
	}
	if !strings.Contains(o.Email, "@") {
		return errors.New("invalid admin email")
	}
	if o.Role == "viewer" { // accepted for older scripts; the role is readonly
		o.Role = "readonly"
	}
	if o.Role == "" {
		o.Role = "super_admin"
	}
	if o.Role != "super_admin" && o.Role != "ops_admin" && o.Role != "readonly" {
		return errors.New("invalid role. Must be one of: super_admin, ops_admin, readonly")
	}
	if o.Name == "" {
		o.Name = strings.Split(o.Email, "@")[0]
	}
	if o.LinkOnly {
		return nil
	}
	switch {
	case o.NoBackup && o.BackupEmail != "":
		return errors.New("-no-backup and -backup-email are mutually exclusive")
	case o.NoBackup:
	case o.BackupEmail == "":
		return errors.New("a break-glass backup administrator is required: pass -backup-email (or ADMIN_BACKUP_EMAIL), or -no-backup to skip it (not recommended)")
	case !strings.Contains(o.BackupEmail, "@"):
		return errors.New("invalid backup email")
	case o.BackupEmail == o.Email:
		return errors.New("the backup administrator needs a different email from the primary one")
	}
	if o.BackupName == "" && o.BackupEmail != "" {
		o.BackupName = strings.Split(o.BackupEmail, "@")[0]
	}
	return nil
}

// adminSpec is one administrator to create.
type adminSpec struct {
	Email      string
	Name       string
	Role       string
	BreakGlass bool
}

// Run performs the bootstrap against db, writing the report to out.
func Run(ctx context.Context, db *sql.DB, o Options, out io.Writer) error {
	if err := CheckSchema(ctx, db); err != nil {
		return err
	}
	if o.LinkOnly {
		return link(ctx, db, o, out)
	}

	specs := []adminSpec{{Email: o.Email, Name: o.Name, Role: o.Role}}
	if !o.NoBackup {
		// The backup must be able to fix anything, so it is a super admin.
		specs = append(specs, adminSpec{Email: o.BackupEmail, Name: o.BackupName, Role: "super_admin", BreakGlass: true})
	}
	for _, s := range specs {
		if err := ensureAdmin(ctx, db, s, o.Force, out); err != nil {
			return err
		}
	}
	if o.NoBackup {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "WARNING: no break-glass backup administrator was created. Keep at least two")
		fmt.Fprintln(out, "administrators, one of them a local break-glass account (re-run with -backup-email).")
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Admin console (browser): sign in at <ui-url>/login with the email and temporary")
	fmt.Fprintln(out, "password, then open the console: change the password and enroll an authenticator app.")
	if !o.NoBackup {
		fmt.Fprintln(out, "Store the break-glass credentials offline (e.g. a sealed envelope or a vault).")
		fmt.Fprintln(out, "Every break-glass sign-in is audited with high severity and alerted to the other administrators.")
	}
	return nil
}

// CheckSchema refuses to run against a database missing the migrations this
// tool writes to.
func CheckSchema(ctx context.Context, db *sql.DB) error {
	var tableExists bool
	if err := db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'admin_users')
	`).Scan(&tableExists); err != nil {
		return fmt.Errorf("checking schema: %w", err)
	}
	if !tableExists {
		return errors.New("admin_users table does not exist. Run migrations first")
	}
	for _, c := range []struct{ column, migration string }{
		{"user_id", "000226"},
		{"is_break_glass", "000229"},
	} {
		var ok bool
		if err := db.QueryRowContext(ctx, `
			SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_name = 'admin_users' AND column_name = $1)`, c.column).Scan(&ok); err != nil {
			return fmt.Errorf("checking schema: %w", err)
		}
		if !ok {
			return fmt.Errorf("admin_users.%s is missing. Run migrations first (%s)", c.column, c.migration)
		}
	}
	// Before 000227 every admin row needed an API key.
	var keyRequired bool
	if err := db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'admin_users' AND column_name = 'api_key_hash' AND is_nullable = 'NO')
	`).Scan(&keyRequired); err != nil {
		return fmt.Errorf("checking schema: %w", err)
	}
	if keyRequired {
		return errors.New("admin_users still requires an API key. Run migrations first (000227)")
	}
	return nil
}

// ensureAdmin creates one administrator unless it exists (idempotent). With
// force, an existing one is deleted and re-created.
func ensureAdmin(ctx context.Context, db *sql.DB, s adminSpec, force bool, out io.Writer) error {
	label := "Administrator"
	if s.BreakGlass {
		label = "Break-glass administrator"
	}
	var existingID string
	var existingBreakGlass, existingLinked bool
	err := db.QueryRowContext(ctx, `
		SELECT id, is_break_glass, user_id IS NOT NULL FROM admin_users WHERE lower(email) = $1`, s.Email).
		Scan(&existingID, &existingBreakGlass, &existingLinked)
	switch {
	case err == nil && !force && !existingLinked:
		// An administrator from before sign-in accounts (v0.8 and older: an API
		// key only). Migration 000227 revoked its key and deactivated it, so
		// reporting it as existing would leave the operator with no usable
		// administrator and no hint why.
		return fmt.Errorf("%s %s exists from before v0.9.0 with no sign-in account; migration 000227 revoked its API key "+
			"and deactivated it. Run bootstrap-admin -email=%s -link to give it a sign-in account and reactivate it, "+
			"or -force to replace it", strings.ToLower(label[:1])+label[1:], s.Email, s.Email)
	case err == nil && !force:
		fmt.Fprintf(out, "%s %s already exists (ID: %s), left unchanged.\n", label, s.Email, existingID)
		if s.BreakGlass && !existingBreakGlass {
			fmt.Fprintf(out, "  NOTE: %s is not marked break-glass. Mark it in the console (Administrators) if it is the backup.\n", s.Email)
		}
		return nil
	case err == nil && force:
		// The linked sign-in account goes too (it belongs to no organization and
		// exists only for this administrator); the admin row cascades with it.
		if _, err := db.ExecContext(ctx, `
			DELETE FROM users WHERE id = (SELECT user_id FROM admin_users WHERE id = $1)`, existingID); err != nil {
			return fmt.Errorf("deleting existing admin account: %w", err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM admin_users WHERE id = $1`, existingID); err != nil {
			return fmt.Errorf("deleting existing admin: %w", err)
		}
		fmt.Fprintf(out, "Deleted existing admin: %s\n", existingID)
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("checking existing admin: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// The sign-in account first, so a refused email leaves no admin row behind.
	userID, temp, err := createAccount(ctx, tx, s.Email, s.Name)
	if err != nil {
		return err
	}
	adminID := uuid.New().String()
	now := time.Now()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO admin_users (id, email, name, role, is_active, user_id, is_break_glass,
		                         password_change_required, created_at, updated_at)
		VALUES ($1, $2, $3, $4, TRUE, $5, $6, TRUE, $7, $7)
	`, adminID, s.Email, s.Name, s.Role, userID, s.BreakGlass, now); err != nil {
		return fmt.Errorf("creating admin: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("creating admin: %w", err)
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "=== %s created ===\n", label)
	fmt.Fprintf(out, "  ID:       %s\n", adminID)
	fmt.Fprintf(out, "  Name:     %s\n", s.Name)
	fmt.Fprintf(out, "  Email:    %s\n", s.Email)
	fmt.Fprintf(out, "  Role:     %s\n", s.Role)
	if s.BreakGlass {
		fmt.Fprintln(out, "  Type:     break-glass (local emergency access; never bound to an identity provider)")
	}
	fmt.Fprintf(out, "  Password: %s   (temporary, shown once; must be changed at first sign-in)\n", temp)
	return nil
}

// link links an administrator created before revision 2 (every v0.8 and older
// administrator: an API key only) to a new sign-in account, and reactivates it:
// migration 000227 deactivated such rows when admin API keys were removed.
func link(ctx context.Context, db *sql.DB, o Options, out io.Writer) error {
	var adminID string
	var linked, active bool
	if err := db.QueryRowContext(ctx, `
		SELECT id, user_id IS NOT NULL, is_active FROM admin_users WHERE lower(email) = $1`, o.Email).
		Scan(&adminID, &linked, &active); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no admin with email %s. Run without -link to create one", o.Email)
		}
		return fmt.Errorf("looking up admin: %w", err)
	}
	if linked {
		return fmt.Errorf("admin %s already has a sign-in account; nothing to link", o.Email)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	userID, temp, err := createAccount(ctx, tx, o.Email, o.Name)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE admin_users
		   SET user_id = $2, password_change_required = TRUE, is_active = TRUE, updated_at = NOW()
		 WHERE id = $1`,
		adminID, userID); err != nil {
		return fmt.Errorf("linking the account: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("linking the account: %w", err)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "=== Administrator linked to a sign-in account ===")
	fmt.Fprintf(out, "  Admin ID: %s\n", adminID)
	fmt.Fprintf(out, "  Email:    %s\n", o.Email)
	if !active {
		// Migration 000227 deactivated every administrator without a sign-in
		// account; linking is the operator's explicit request to use it again.
		fmt.Fprintln(out, "  Status:   reactivated (it had been deactivated when admin API keys were removed)")
	}
	fmt.Fprintf(out, "  Password: %s   (temporary, shown once; must be changed at first sign-in)\n", temp)
	return nil
}

// createAccount creates the administrator's sign-in account: a new local
// account with a temporary password (returned, shown once). An email that
// already has an account is refused, never reused: with self-registration
// anyone could have registered it first and would then own the
// administrator's password.
func createAccount(ctx context.Context, tx *sql.Tx, email, name string) (userID, temp string, err error) {
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE lower(email) = $1`, email).Scan(&existing)
	switch {
	case err == nil:
		return "", "", fmt.Errorf("an account with email %s already exists. A platform administrator gets a new, dedicated account: use another email", email)
	case !errors.Is(err, sql.ErrNoRows):
		return "", "", fmt.Errorf("looking up sign-in account: %w", err)
	}
	temp, err = temporaryPassword()
	if err != nil {
		return "", "", err
	}
	hash, err := password.New().Hash(temp)
	if err != nil {
		return "", "", fmt.Errorf("hashing password: %w", err)
	}
	userID = uuid.New().String()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users (id, email, name, password_hash, auth_provider, status, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'local', 'active', true, NOW(), NOW())
	`, userID, email, name, hash); err != nil {
		return "", "", fmt.Errorf("creating sign-in account: %w", err)
	}
	return userID, temp, nil
}

// temporaryPassword returns a random password meeting the default policy.
func temporaryPassword() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating password: %w", err)
	}
	out := make([]byte, len(buf))
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return "Oc" + string(out) + "7!", nil
}
