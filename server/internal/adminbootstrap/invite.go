package adminbootstrap

// `bootstrap-admin invite`: the host path for adding an administrator when the
// console cannot (no platform e-mail while four-eyes approvals are on). It
// creates the account with no password, prints the single-use set-password
// link once on the host terminal, and records the invitation in the
// administrators' audit log as the host actor. It needs no console approval:
// whoever can run it already holds the database credentials and the
// encryption key, which is the root of trust the platform accepts. Every other
// administrator is told, like for any roster change.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/password"
)

// AuditActionAdminInvited is the audit action of an invitation made on the host.
const AuditActionAdminInvited = "admin.invited"

// InviteOptions describes the administrator to invite.
type InviteOptions struct {
	Email string
	Name  string
	Role  string
	Actor Actor
	// UIBaseURL is the web UI origin of the printed set-password link.
	UIBaseURL string
	Notifier  adminconsole.RosterChangeNotifier
	Logger    *logger.Logger
}

// Invite creates the invited administrator and prints the link once.
func Invite(ctx context.Context, db *sql.DB, o InviteOptions, out io.Writer) error {
	o.Email = strings.ToLower(strings.TrimSpace(o.Email))
	if o.Email == "" || !strings.Contains(o.Email, "@") {
		return errors.New("a valid -email is required")
	}
	if o.Role == "" {
		o.Role = "ops_admin"
	}
	if o.Role != "super_admin" && o.Role != "ops_admin" && o.Role != "readonly" {
		return errors.New("invalid role. Must be one of: super_admin, ops_admin, readonly")
	}
	if strings.TrimSpace(o.Name) == "" {
		o.Name = strings.Split(o.Email, "@")[0]
	}
	if err := CheckSchema(ctx, db); err != nil {
		return err
	}

	token, err := password.GenerateResetToken()
	if err != nil {
		return fmt.Errorf("generating the link: %w", err)
	}
	expires := time.Now().Add(adminconsole.AdminInvitationTTL)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = $1)
	                                     OR EXISTS (SELECT 1 FROM admin_users WHERE lower(email) = $1)`, o.Email).Scan(&exists); err != nil {
		return fmt.Errorf("looking up %s: %w", o.Email, err)
	}
	if exists {
		return fmt.Errorf("an account or administrator with email %s already exists. A platform administrator gets a new, dedicated account: use another email", o.Email)
	}
	userID := uuid.New().String()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users (id, email, name, password_hash, auth_provider, status, email_verified,
		                   password_reset_token, password_reset_expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, NULL, 'local', 'active', true, $4, $5, NOW(), NOW())
	`, userID, o.Email, o.Name, crypto.HashToken(token), expires); err != nil {
		return fmt.Errorf("creating the sign-in account: %w", err)
	}
	adminID := uuid.New().String()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO admin_users (id, email, name, role, is_active, user_id, is_break_glass,
		                         password_change_required, created_at, updated_at)
		VALUES ($1, $2, $3, $4, TRUE, $5, FALSE, FALSE, NOW(), NOW())
	`, adminID, o.Email, o.Name, o.Role, userID); err != nil {
		return fmt.Errorf("creating the administrator: %w", err)
	}
	c := adminChange{Action: AuditActionAdminInvited, Spec: adminSpec{Email: o.Email, Name: o.Name, Role: o.Role}, ID: adminID, ActiveAfter: true}
	if err := writeAudit(ctx, tx, o.Actor.normalized(), c); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("inviting the administrator: %w", err)
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "=== Administrator invited ===")
	fmt.Fprintf(out, "  Email: %s\n", o.Email)
	fmt.Fprintf(out, "  Role:  %s\n", o.Role)
	fmt.Fprintf(out, "  Link:  %s\n", setupLinkURL(o.UIBaseURL, token))
	fmt.Fprintf(out, "  Shown once, valid %d hours, single use. Hand it only to %s.\n", int(adminconsole.AdminInvitationTTL.Hours()), o.Email)
	fmt.Fprintln(out, "  After choosing a password they sign in on the console and set up their second factor.")
	notifyAdmins(ctx, db, Options{Actor: o.Actor, Notifier: o.Notifier, Logger: o.Logger}, []adminChange{c}, out)
	return nil
}
