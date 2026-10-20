// Package adminbootstrap creates the first platform administrators and their
// break-glass backup (the bootstrap-admin command, RFC-022 revision 4), and
// optionally the first organization with its owner (see organization.go).
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

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/password"
)

// Options are the command-line inputs; call Normalize before Run.
type Options struct {
	Email       string
	Name        string
	Role        string
	BackupEmail string
	BackupName  string
	NoBackup    bool
	// Force deletes and re-creates the -email administrator when it exists.
	// It never touches the backup: ForceBackup does that.
	Force       bool
	ForceBackup bool
	LinkOnly    bool
	// RoleExplicit is set by Normalize when Role was given. Without it a
	// replaced administrator keeps its role, and an inactive one is refused.
	RoleExplicit bool
	// Yes confirms replacements without the typed-back email (scripts).
	Yes bool
	// Confirm asks the operator to type the email of an administrator about
	// to be replaced and reports whether it matched; nil when there is no
	// terminal, and then a replacement needs Yes.
	Confirm func(email string) bool
	// Actor is who ran the command, recorded in the audit entries.
	Actor Actor
	// Notifier tells the other active administrators what this run changed
	// (nil: no platform e-mail, a warning is printed instead).
	Notifier adminconsole.RosterChangeNotifier

	// The first organization (optional). OrgName and OrgOwnerEmail go
	// together; OrgSlug is derived from OrgName when empty.
	OrgName       string
	OrgSlug       string
	OrgOwnerEmail string
	OrgOwnerName  string
	// OrgSetupMailer emails the owner's one-time set-password link; nil (or
	// no SMTP) prints the link instead.
	OrgSetupMailer tenantapp.AccountSetupMailer
	// UIBaseURL is the web UI origin used to print the set-password link.
	UIBaseURL string
	// AdminPublicURL is the platform console's own origin (ADMIN_PUBLIC_URL);
	// when empty the closing text names the default address pattern.
	AdminPublicURL string
	// Logger receives service warnings (nil: discarded).
	Logger *logger.Logger
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
	} else {
		o.RoleExplicit = true
	}
	if o.Role != "super_admin" && o.Role != "ops_admin" && o.Role != "readonly" {
		return errors.New("invalid role. Must be one of: super_admin, ops_admin, readonly")
	}
	if o.Name == "" {
		o.Name = strings.Split(o.Email, "@")[0]
	}
	if o.LinkOnly {
		if o.hasOrg() {
			return errors.New("-org-* flags cannot be combined with -link: run them without -link")
		}
		if o.Force || o.ForceBackup {
			return errors.New("-force and -force-backup cannot be combined with -link")
		}
		return nil
	}
	switch {
	case o.ForceBackup && o.NoBackup:
		return errors.New("-force-backup and -no-backup are mutually exclusive")
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
	return o.normalizeOrg()
}

// adminSpec is one administrator to create.
type adminSpec struct {
	Email      string
	Name       string
	Role       string
	BreakGlass bool
}

// Run performs the bootstrap against db, writing the report to out.
//
// Every administrator it creates, replaces or links is written in one
// transaction together with one entry per change in the administrators'
// hash-chained audit log (actor bootstrap-admin, with the OS user and host in
// the entry), and the other active administrators are told afterwards (see
// accountability.go). Whoever holds the schema owner's credentials can always
// write these tables directly; what this command guarantees is that its own
// use is never silent.
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
	plan, err := planAdmins(ctx, db, o, specs)
	if err != nil {
		return err
	}
	if err := confirmReplacements(o, plan, out); err != nil {
		return err
	}
	changes, err := applyAdmins(ctx, db, o, plan)
	if err != nil {
		return err
	}
	for _, st := range plan {
		if st.action == actionKeep {
			reportKept(out, o, st)
		}
	}
	for _, c := range changes {
		reportChange(out, c)
	}
	notifyAdmins(ctx, db, o, changes, out)

	if o.hasOrg() {
		if err := ensureOrganization(ctx, db, o, out); err != nil {
			return err
		}
	}
	if o.NoBackup {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "WARNING: no break-glass backup administrator was created. Keep at least two")
		fmt.Fprintln(out, "administrators, one of them a local break-glass account (re-run with -backup-email).")
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Admin console (browser): open "+consoleAddress(o.AdminPublicURL)+" and sign in with the email and")
	fmt.Fprintln(out, "temporary password, then change the password and enroll an authenticator app.")
	if !o.NoBackup {
		fmt.Fprintln(out, "Store the break-glass credentials offline (e.g. a sealed envelope or a vault).")
		fmt.Fprintln(out, "Every break-glass sign-in is audited with high severity and alerted to the other administrators.")
	}
	if !o.hasOrg() {
		fmt.Fprintln(out, "Organizations are created by a platform administrator: in the console (Organizations),")
		fmt.Fprintln(out, "or by re-running this command with -org-name and -org-owner-email.")
	}
	return nil
}

// consoleAddress names where administrators open the console: the configured
// origin, or the description of the default one (the console has its own site,
// not the organization sign-in page).
func consoleAddress(adminPublicURL string) string {
	if u := strings.TrimRight(strings.TrimSpace(adminPublicURL), "/"); u != "" {
		return u
	}
	return "the platform console's own site (https://<host>:8443 by default, or your OPENCTEM_ADMIN_HOST)"
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

// adminState is an existing administrator row.
type adminState struct {
	ID         string
	Role       string
	Active     bool
	BreakGlass bool
	Linked     bool
}

func statusLabel(active bool) string {
	if active {
		return "active"
	}
	return "inactive"
}

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// lookupAdmin returns the administrator with this email, or nil. forUpdate
// locks the row until the transaction ends.
func lookupAdmin(ctx context.Context, q queryRower, email string, forUpdate bool) (*adminState, error) {
	query := `SELECT id, role, is_active, is_break_glass, user_id IS NOT NULL FROM admin_users WHERE lower(email) = $1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	var st adminState
	err := q.QueryRowContext(ctx, query, email).Scan(&st.ID, &st.Role, &st.Active, &st.BreakGlass, &st.Linked)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("checking existing admin: %w", err)
	}
	return &st, nil
}

type stepAction int

const (
	actionCreate stepAction = iota
	actionKeep
	actionReplace
)

// planStep is what the run will do with one administrator.
type planStep struct {
	spec     adminSpec // with the role the new row gets
	existing *adminState
	action   stepAction
}

func specLabel(s adminSpec) string {
	if s.BreakGlass {
		return "Break-glass administrator"
	}
	return "Administrator"
}

// planAdmins decides, before anything is written, what happens to each
// administrator. -force replaces only the -email administrator and
// -force-backup only the break-glass backup, so replacing one never destroys
// the other's credentials and authenticator. A replaced -email administrator
// keeps its role unless -role is given, and an inactive one is never brought
// back without an explicit -role.
func planAdmins(ctx context.Context, db *sql.DB, o Options, specs []adminSpec) ([]planStep, error) {
	plan := make([]planStep, 0, len(specs))
	for _, s := range specs {
		force, flagName := o.Force, "-force"
		if s.BreakGlass {
			force, flagName = o.ForceBackup, "-force-backup"
		}
		st, err := lookupAdmin(ctx, db, s.Email, false)
		if err != nil {
			return nil, err
		}
		label := specLabel(s)
		switch {
		case st == nil:
			plan = append(plan, planStep{spec: s, action: actionCreate})
		case !force && !st.Linked:
			// An administrator from before sign-in accounts (v0.8 and older: an
			// API key only). Migration 000227 revoked its key and deactivated
			// it, so reporting it as existing would leave the operator with no
			// usable administrator and no hint why.
			hint := fmt.Sprintf("Run bootstrap-admin -email=%s -link to give it a sign-in account and reactivate it, "+
				"or -force -role=<role> to replace it", s.Email)
			if s.BreakGlass {
				hint = fmt.Sprintf("Run bootstrap-admin -email=%s -link to give it a sign-in account and reactivate it, "+
					"or -force-backup to replace it", s.Email)
			}
			return nil, fmt.Errorf("%s %s exists from before v0.9.0 with no sign-in account; migration 000227 revoked its API key "+
				"and deactivated it. %s", strings.ToLower(label[:1])+label[1:], s.Email, hint)
		case !force:
			plan = append(plan, planStep{spec: s, existing: st, action: actionKeep})
		default:
			if !s.BreakGlass && !o.RoleExplicit {
				if !st.Active {
					return nil, fmt.Errorf("administrator %s is %s (role %s). %s would bring it back as an active administrator: "+
						"pass -role explicitly (-role=%s to keep its role) if that is intended", s.Email, statusLabel(st.Active), st.Role, flagName, st.Role)
				}
				// Never change the role as a side effect of a re-create.
				s.Role = st.Role
			}
			// Nor the break-glass mark: -email naming the backup replaces it
			// as the backup, not as an ordinary administrator.
			if st.BreakGlass {
				s.BreakGlass = true
			}
			plan = append(plan, planStep{spec: s, existing: st, action: actionReplace})
		}
	}
	return plan, nil
}

// confirmReplacements prints what each replacement changes and asks for it to
// be confirmed: the email typed back on a terminal, or -yes.
func confirmReplacements(o Options, plan []planStep, out io.Writer) error {
	var replaced []planStep
	for _, st := range plan {
		if st.action == actionReplace {
			replaced = append(replaced, st)
		}
	}
	if len(replaced) == 0 {
		return nil
	}
	fmt.Fprintln(out, "The following administrators will be DELETED and re-created (new sign-in account,")
	fmt.Fprintln(out, "new temporary password; the old password, authenticator and sessions stop working):")
	for _, st := range replaced {
		fmt.Fprintf(out, "  %s %s\n", specLabel(st.spec), st.spec.Email)
		fmt.Fprintf(out, "    before: role %s, %s\n", st.existing.Role, statusLabel(st.existing.Active))
		fmt.Fprintf(out, "    after:  role %s, active\n", st.spec.Role)
	}
	if o.Yes {
		return nil
	}
	if o.Confirm == nil {
		return errors.New("replacing an administrator needs confirmation: run the command on a terminal, or pass -yes. Nothing was changed")
	}
	for _, st := range replaced {
		if !o.Confirm(st.spec.Email) {
			return fmt.Errorf("confirmation for %s did not match. Nothing was changed", st.spec.Email)
		}
	}
	return nil
}

// adminChange is one administrator this run created, replaced or linked.
type adminChange struct {
	Action string // admin.created, admin.replaced, admin.relinked
	Spec   adminSpec
	ID     string
	Before *adminState // nil for a new administrator
	// ActiveAfter is the administrator's status after the change.
	ActiveAfter bool
	Temp        string
	// Reactivated is set by -link on an inactive administrator.
	Reactivated bool
}

// errLastSuperAdmin refuses a run that would leave no active super admin.
var errLastSuperAdmin = errors.New("this would leave the platform with no active super admin: " +
	"replace the administrator with -role=super_admin, or create another super admin first. Nothing was changed")

// applyAdmins writes the plan in one transaction: the administrators, their
// sign-in accounts and one audit entry per change commit together or not at
// all.
func applyAdmins(ctx context.Context, db *sql.DB, o Options, plan []planStep) ([]adminChange, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	actor := o.Actor.normalized()
	changes := make([]adminChange, 0, len(plan))
	replaced := false
	for _, st := range plan {
		if st.action == actionKeep {
			continue
		}
		action := AuditActionAdminCreated
		if st.action == actionReplace {
			action = AuditActionAdminReplaced
			replaced = true
			// The row must still be the one shown to the operator.
			cur, err := lookupAdmin(ctx, tx, st.spec.Email, true)
			if err != nil {
				return nil, err
			}
			if cur == nil || cur.ID != st.existing.ID || cur.Role != st.existing.Role || cur.Active != st.existing.Active {
				return nil, fmt.Errorf("administrator %s changed while this command ran. Nothing was changed; run it again", st.spec.Email)
			}
			// The linked sign-in account goes too (it belongs to no
			// organization and exists only for this administrator); the admin
			// row cascades with it.
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM users WHERE id = (SELECT user_id FROM admin_users WHERE id = $1)`, cur.ID); err != nil {
				return nil, fmt.Errorf("deleting existing admin account: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM admin_users WHERE id = $1`, cur.ID); err != nil {
				return nil, fmt.Errorf("deleting existing admin: %w", err)
			}
		}

		// The sign-in account first, so a refused email leaves no admin row behind.
		userID, temp, err := createAccount(ctx, tx, st.spec.Email, st.spec.Name)
		if err != nil {
			return nil, err
		}
		adminID := uuid.New().String()
		now := time.Now()
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO admin_users (id, email, name, role, is_active, user_id, is_break_glass,
			                         password_change_required, created_at, updated_at)
			VALUES ($1, $2, $3, $4, TRUE, $5, $6, TRUE, $7, $7)
		`, adminID, st.spec.Email, st.spec.Name, st.spec.Role, userID, st.spec.BreakGlass, now); err != nil {
			return nil, fmt.Errorf("creating admin: %w", err)
		}
		c := adminChange{Action: action, Spec: st.spec, ID: adminID, Before: st.existing, ActiveAfter: true, Temp: temp}
		if err := writeAudit(ctx, tx, actor, c); err != nil {
			return nil, err
		}
		changes = append(changes, c)
	}

	// Replacing deletes rows: never leave the platform without an active
	// super admin. Re-creating the last one as super admin in this same
	// transaction keeps the count at one, so it is allowed; re-creating it
	// with a lower -role is refused. A first install that creates only a
	// non-super admin (-role with -no-backup) deletes nothing and is allowed.
	if replaced {
		var supers int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM admin_users WHERE role = 'super_admin' AND is_active`).Scan(&supers); err != nil {
			return nil, fmt.Errorf("counting super admins: %w", err)
		}
		if supers == 0 {
			return nil, errLastSuperAdmin
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("creating admin: %w", err)
	}
	return changes, nil
}

func reportKept(out io.Writer, o Options, st planStep) {
	label := specLabel(st.spec)
	fmt.Fprintf(out, "%s %s already exists (ID: %s, role %s, %s), left unchanged.\n",
		label, st.spec.Email, st.existing.ID, st.existing.Role, statusLabel(st.existing.Active))
	if st.spec.BreakGlass && !st.existing.BreakGlass {
		fmt.Fprintf(out, "  NOTE: %s is not marked break-glass. Mark it in the console (Administrators) if it is the backup.\n", st.spec.Email)
	}
	if st.spec.BreakGlass && o.Force {
		fmt.Fprintln(out, "  NOTE: -force replaces only the -email administrator; pass -force-backup to replace the backup.")
	}
	if !st.spec.BreakGlass && o.RoleExplicit && st.existing.Role != st.spec.Role {
		fmt.Fprintf(out, "  NOTE: -role=%s was not applied; change the role in the console (Administrators).\n", st.spec.Role)
	}
}

func reportChange(out io.Writer, c adminChange) {
	fmt.Fprintln(out)
	switch c.Action {
	case AuditActionAdminRelinked:
		fmt.Fprintln(out, "=== Administrator linked to a sign-in account ===")
		fmt.Fprintf(out, "  Admin ID: %s\n", c.ID)
		fmt.Fprintf(out, "  Email:    %s\n", c.Spec.Email)
		fmt.Fprintf(out, "  Role:     %s (unchanged)\n", c.Spec.Role)
		if c.Reactivated {
			// Migration 000227 deactivated every administrator without a
			// sign-in account; linking is the operator's explicit request to
			// use it again.
			fmt.Fprintln(out, "  Status:   reactivated, inactive -> active (it had been deactivated when admin API keys were removed)")
		}
	default:
		verb := "created"
		if c.Action == AuditActionAdminReplaced {
			verb = "replaced"
		}
		fmt.Fprintf(out, "=== %s %s ===\n", specLabel(c.Spec), verb)
		fmt.Fprintf(out, "  ID:       %s\n", c.ID)
		fmt.Fprintf(out, "  Name:     %s\n", c.Spec.Name)
		fmt.Fprintf(out, "  Email:    %s\n", c.Spec.Email)
		if c.Before != nil {
			fmt.Fprintf(out, "  Role:     %s -> %s\n", c.Before.Role, c.Spec.Role)
			fmt.Fprintf(out, "  Status:   %s -> active\n", statusLabel(c.Before.Active))
		} else {
			fmt.Fprintf(out, "  Role:     %s\n", c.Spec.Role)
		}
		if c.Spec.BreakGlass {
			fmt.Fprintln(out, "  Type:     break-glass (local emergency access; never bound to an identity provider)")
		}
	}
	fmt.Fprintf(out, "  Password: %s   (temporary, shown once; must be changed at first sign-in)\n", c.Temp)
}

// link links an administrator created before revision 2 (every v0.8 and older
// administrator: an API key only) to a new sign-in account, and reactivates it:
// migration 000227 deactivated such rows when admin API keys were removed.
// An administrator deactivated in the console is always linked, so -link can
// never bring one back.
func link(ctx context.Context, db *sql.DB, o Options, out io.Writer) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	st, err := lookupAdmin(ctx, tx, o.Email, true)
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("no admin with email %s. Run without -link to create one", o.Email)
	}
	if st.Linked {
		return fmt.Errorf("admin %s already has a sign-in account; nothing to link", o.Email)
	}
	userID, temp, err := createAccount(ctx, tx, o.Email, o.Name)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE admin_users
		   SET user_id = $2, password_change_required = TRUE, is_active = TRUE, updated_at = NOW()
		 WHERE id = $1`,
		st.ID, userID); err != nil {
		return fmt.Errorf("linking the account: %w", err)
	}
	c := adminChange{
		Action: AuditActionAdminRelinked,
		Spec:   adminSpec{Email: o.Email, Name: o.Name, Role: st.Role, BreakGlass: st.BreakGlass},
		ID:     st.ID, Before: st, ActiveAfter: true, Temp: temp, Reactivated: !st.Active,
	}
	if err := writeAudit(ctx, tx, o.Actor.normalized(), c); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("linking the account: %w", err)
	}
	reportChange(out, c)
	notifyAdmins(ctx, db, o, []adminChange{c}, out)
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
