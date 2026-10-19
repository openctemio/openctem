package adminbootstrap

// What makes the command's own use visible: an entry in the administrators'
// hash-chained audit log for every administrator it creates, replaces or
// links, written in the same transaction as the change, and a notice to the
// other active administrators afterwards (the same notice the console sends
// when an administrator changes the roster).

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Audit actions of this command (admin_audit_logs.action).
const (
	AuditActionAdminCreated  = "admin.created"
	AuditActionAdminReplaced = "admin.replaced"
	AuditActionAdminRelinked = "admin.relinked"
)

// Actor identifies who ran the command: the OS account ($SUDO_USER, else
// $USER) and the host. Both are what the operator's environment says; they
// name the run for the audit review, they do not authenticate it.
type Actor struct {
	OSUser   string
	Hostname string
}

func (a Actor) normalized() Actor {
	return Actor{OSUser: cleanActorField(a.OSUser), Hostname: cleanActorField(a.Hostname)}
}

// cleanActorField keeps the value printable, on one line and short.
func cleanActorField(v string) string {
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(v))
	if len(v) > 128 {
		v = v[:128]
	}
	if v == "" {
		return "unknown"
	}
	return v
}

// writeAudit records one change in the administrators' audit log, inside tx.
// The database links the row into the hash chain (migration 002545), so
// verify-audit keeps verifying.
func writeAudit(ctx context.Context, tx *sql.Tx, actor Actor, c adminChange) error {
	adminID, err := shared.IDFromString(c.ID)
	if err != nil {
		return fmt.Errorf("audit entry: %w", err)
	}
	meta := map[string]any{
		"actor":        AuditActor,
		"os_user":      actor.OSUser,
		"hostname":     actor.Hostname,
		"role_after":   c.Spec.Role,
		"status_after": statusLabel(c.ActiveAfter),
		"break_glass":  c.Spec.BreakGlass,
	}
	if c.Before != nil {
		meta["role_before"] = c.Before.Role
		meta["status_before"] = statusLabel(c.Before.Active)
		if c.Before.ID != c.ID {
			meta["replaced_admin_id"] = c.Before.ID
		}
	}
	entry := &admin.AuditLog{
		ID:           shared.NewID(),
		AdminEmail:   AuditActor,
		Action:       c.Action,
		ResourceType: "admin_user",
		ResourceID:   &adminID,
		ResourceName: c.Spec.Email,
		RequestBody:  meta,
		UserAgent:    AuditActor,
		Success:      true,
		Severity:     "high",
		CreatedAt:    time.Now(),
	}
	if err := postgres.CreateAdminAuditLogTx(ctx, tx, entry); err != nil {
		return fmt.Errorf("writing the admin audit entry: %w", err)
	}
	return nil
}

// notifyAdmins tells every other active administrator what this run changed.
// It never fails the run: the change is committed and audited already, and
// the WARN line (alert=admin_roster_change, on stderr) is written either way.
func notifyAdmins(ctx context.Context, db *sql.DB, o Options, changes []adminChange, out io.Writer) {
	if len(changes) == 0 {
		return
	}
	actor := o.Actor.normalized()
	ids := make([]string, 0, len(changes))
	parts := make([]string, 0, len(changes))
	for _, c := range changes {
		ids = append(ids, c.ID)
		parts = append(parts, changeSummary(c))
	}
	recipients, err := otherActiveAdmins(ctx, db, ids)
	if err != nil {
		fmt.Fprintf(out, "WARNING: could not list the other administrators to notify them: %v\n", err)
		return
	}
	if o.Logger != nil {
		o.Logger.Warn("platform administrator roster changed by bootstrap-admin",
			"alert", adminconsole.AlertRosterChange,
			"actor", AuditActor,
			"os_user", actor.OSUser,
			"hostname", actor.Hostname,
			"notified", len(recipients),
		)
	}
	if len(recipients) == 0 {
		return
	}
	if o.Notifier == nil {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "WARNING: platform e-mail is not configured, so the %d other active administrator(s) were not emailed.\n", len(recipients))
		fmt.Fprintln(out, "The change is in the admin audit log (console: Audit log; bootstrap-admin verify-audit).")
		return
	}
	err = o.Notifier.NotifyRosterChange(ctx, adminconsole.RosterChange{
		Kind:       adminconsole.RosterAdminAdded,
		Summary:    strings.Join(parts, "; "),
		ActorEmail: AuditActor + " (OS user " + actor.OSUser + ")",
		IP:         "command line on " + actor.Hostname,
		At:         time.Now(),
		Recipients: recipients,
		Via:        "with the bootstrap-admin command on host " + actor.Hostname,
	})
	if err != nil {
		fmt.Fprintf(out, "WARNING: the other administrators could not be emailed (%v). The change is in the admin audit log.\n", err)
		return
	}
	fmt.Fprintf(out, "The other %d active administrator(s) were emailed about this change.\n", len(recipients))
}

// otherActiveAdmins lists the active administrators' emails, leaving out the
// ones this run created or changed.
func otherActiveAdmins(ctx context.Context, db *sql.DB, exclude []string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT email FROM admin_users
		 WHERE is_active AND NOT (id::text = ANY($1))
		 ORDER BY created_at LIMIT 500`, pq.StringArray(exclude))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// changeSummary is one English clause for the notice; never a secret.
func changeSummary(c adminChange) string {
	kind := "administrator"
	if c.Spec.BreakGlass {
		kind = "break-glass administrator"
	}
	after := c.Spec.Role + ", " + statusLabel(c.ActiveAfter)
	switch c.Action {
	case AuditActionAdminReplaced:
		return fmt.Sprintf("replaced %s %s (%s, %s -> %s; new password, authenticator removed)",
			kind, c.Spec.Email, c.Before.Role, statusLabel(c.Before.Active), after)
	case AuditActionAdminRelinked:
		return fmt.Sprintf("linked %s %s to a new sign-in account (%s, %s -> %s)",
			kind, c.Spec.Email, c.Before.Role, statusLabel(c.Before.Active), after)
	default:
		return fmt.Sprintf("added %s %s (%s)", kind, c.Spec.Email, after)
	}
}
