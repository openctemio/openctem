package adminbootstrap

// The first organization (bootstrap-admin -org-name/-org-owner-email).
//
// A fresh installation has no organization, so no one can use the product
// until one exists. The
// installer can create it in the same step. It goes through the same application services as the admin
// console's Organizations -> Create (tenantapp.OrganizationCreator): the
// organization and the owner's membership and role are written atomically,
// tenant.created and user.created are audited in the new organization, and a
// new owner gets a one-time set-password link. Nothing here writes SQL.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AuditActor identifies this command as the actor in the audit log (it runs
// with database credentials, not as a signed-in user).
const AuditActor = "bootstrap-admin"

func (o *Options) hasOrg() bool {
	return o.OrgName != "" || o.OrgSlug != "" || o.OrgOwnerEmail != "" || o.OrgOwnerName != ""
}

// normalizeOrg validates the -org-* inputs and derives the slug.
func (o *Options) normalizeOrg() error {
	o.OrgName = strings.TrimSpace(o.OrgName)
	o.OrgSlug = strings.ToLower(strings.TrimSpace(o.OrgSlug))
	o.OrgOwnerEmail = strings.ToLower(strings.TrimSpace(o.OrgOwnerEmail))
	o.OrgOwnerName = strings.TrimSpace(o.OrgOwnerName)
	if !o.hasOrg() {
		return nil
	}
	switch {
	case o.OrgName == "":
		return errors.New("-org-name is required with the other -org-* flags (or set ORG_NAME)")
	case o.OrgOwnerEmail == "":
		return errors.New("-org-owner-email is required with -org-name: the organization needs an owner (or set ORG_OWNER_EMAIL)")
	case !strings.Contains(o.OrgOwnerEmail, "@"):
		return errors.New("invalid organization owner email")
	case o.OrgOwnerEmail == o.BackupEmail:
		// The break-glass account is for emergencies on the console only.
		return errors.New("the break-glass administrator cannot own an organization: use a different -org-owner-email")
	}
	if n := utf8.RuneCountInString(o.OrgName); n < 2 || n > 100 {
		return errors.New("-org-name must be 2 to 100 characters")
	}
	if o.OrgSlug == "" {
		o.OrgSlug = tenantdom.GenerateSlug(o.OrgName)
		if !tenantdom.IsValidSlug(o.OrgSlug) {
			return fmt.Errorf("cannot derive a URL slug from -org-name %q: pass -org-slug (lowercase letters, numbers and hyphens, 3 to 100 characters)", o.OrgName)
		}
	} else if !tenantdom.IsValidSlug(o.OrgSlug) {
		return errors.New("invalid -org-slug: use lowercase letters, numbers and hyphens, 3 to 100 characters")
	}
	return nil
}

// ensureOrganization creates the first organization unless one with the slug
// exists (idempotent: re-running reports it and changes nothing).
func ensureOrganization(ctx context.Context, db *sql.DB, o Options, out io.Writer) error {
	log := o.Logger
	if log == nil {
		log = logger.NewNop()
	}
	pdb := &postgres.DB{DB: db}
	tenantRepo := postgres.NewTenantRepository(pdb)
	userRepo := postgres.NewUserRepository(pdb)

	existing, err := tenantRepo.GetBySlug(ctx, o.OrgSlug)
	switch {
	case err == nil && (existing.ID().IsZero() || existing.ID().String() == tenantdom.SystemTenantID):
		return fmt.Errorf("the slug %q is reserved: choose another -org-slug", o.OrgSlug)
	case err == nil:
		fmt.Fprintln(out)
		fmt.Fprintf(out, "Organization %s already exists (ID: %s), left unchanged.\n", o.OrgSlug, existing.ID())
		return nil
	case !shared.IsNotFound(err):
		return fmt.Errorf("checking organization: %w", err)
	}

	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(pdb), log)
	tenantSvc := tenantapp.NewTenantService(tenantRepo, log, tenantapp.WithTenantAuditService(auditSvc))
	// No role granter: the owner's role is written with the organization
	// (CreateWithOwner); provisioning here only creates the owner's account and
	// issues its link.
	// A failed send is caught here so the link can be printed (see
	// unsentLinkMailer); the nil check keeps an untyped nil for "no SMTP".
	var mailer tenantapp.AccountSetupMailer
	var unsent *unsentLinkMailer
	if o.OrgSetupMailer != nil {
		unsent = &unsentLinkMailer{AccountSetupMailer: o.OrgSetupMailer}
		mailer = unsent
	}
	provisioning := tenantapp.NewUserProvisioningService(tenantRepo, userRepo, nil, mailer, auditSvc, log)
	created, err := tenantapp.NewOrganizationCreator(tenantSvc, provisioning, userRepo, log).
		Create(ctx, tenantapp.CreateOrganizationInput{
			Name: o.OrgName, Slug: o.OrgSlug,
			OwnerEmail: o.OrgOwnerEmail, OwnerName: o.OrgOwnerName,
			// The operator runs this on the host: naming an existing account is deliberate.
			AllowExistingOwner: true,
		}, auditapp.AuditContext{ActorEmail: AuditActor})
	if err != nil {
		if errors.Is(err, tenantdom.ErrBreakGlassMembership) {
			return fmt.Errorf("%s is a break-glass administrator, which stays console-only and cannot own an organization: use a different -org-owner-email", o.OrgOwnerEmail)
		}
		return fmt.Errorf("creating organization: %w", err)
	}

	t := created.Tenant
	fmt.Fprintln(out)
	fmt.Fprintln(out, "=== Organization created ===")
	fmt.Fprintf(out, "  ID:       %s\n", t.ID())
	fmt.Fprintf(out, "  Name:     %s\n", t.Name())
	fmt.Fprintf(out, "  Slug:     %s\n", t.Slug())
	switch {
	case !created.OwnerCreated:
		fmt.Fprintf(out, "  Owner:    %s (existing account: signs in with its own credentials)\n", created.Owner.Email())
	case created.OwnerSetup == nil, !created.OwnerSetup.EmailSent && linkToken(created.OwnerSetup, unsent) == "":
		fmt.Fprintf(out, "  Owner:    %s (new account)\n", created.Owner.Email())
		fmt.Fprintln(out, "  The set-password link could not be issued. The owner can use \"Forgot password\" on")
		fmt.Fprintln(out, "  the sign-in page, or an administrator issues a new link from the console.")
	case created.OwnerSetup.EmailSent:
		fmt.Fprintf(out, "  Owner:    %s (new account)\n", created.Owner.Email())
		fmt.Fprintf(out, "  A one-time set-password link was emailed to the owner (valid %d hours).\n", int(tenantapp.AccountSetupTTL.Hours()))
	default:
		fmt.Fprintf(out, "  Owner:    %s (new account)\n", created.Owner.Email())
		if created.OwnerSetup.EmailFailed {
			fmt.Fprintln(out, "  WARNING: the set-password email could not be sent (check the platform e-mail")
			fmt.Fprintln(out, "  settings or BOOTSTRAP_SMTP_*). The link below is a secret: anyone who has it")
			fmt.Fprintln(out, "  can set the owner's password. Do not paste it into tickets or chat logs.")
		}
		fmt.Fprintf(out, "  Set-password link (shown once, valid %d hours; give it to the owner over a trusted channel):\n", int(tenantapp.AccountSetupTTL.Hours()))
		fmt.Fprintf(out, "    %s\n", setupLinkURL(o.UIBaseURL, linkToken(created.OwnerSetup, unsent)))
	}
	return nil
}

// unsentLinkMailer remembers the token of a set-password email that failed to
// send. The first-owner rule never hands an emailed link to the platform
// administrator in the console; this command is different, because whoever
// runs it holds the database credentials and could set any password anyway.
// Without it a failed send (an unreachable relay) left the new owner with no
// link at all. The token is only ever written to this command's stdout, never
// to a log.
type unsentLinkMailer struct {
	tenantapp.AccountSetupMailer
	token string
}

func (m *unsentLinkMailer) SendAccountSetupEmail(ctx context.Context, tenantID, recipientEmail, recipientName, teamName, token string, expiresIn time.Duration) error {
	err := m.AccountSetupMailer.SendAccountSetupEmail(ctx, tenantID, recipientEmail, recipientName, teamName, token, expiresIn)
	if err != nil {
		m.token = token
	}
	return err
}

// linkToken is the token to print: returned by the service when no email
// could be attempted, or kept from a failed send.
func linkToken(setup *tenantapp.ProvisionedUser, unsent *unsentLinkMailer) string {
	if setup.SetupToken != "" {
		return setup.SetupToken
	}
	if setup.EmailFailed && unsent != nil {
		return unsent.token
	}
	return ""
}

// setupLinkURL is the UI page that consumes a one-time set-password token (the
// same URL the email carries).
func setupLinkURL(base, token string) string {
	base = strings.TrimSuffix(strings.TrimSpace(base), "/")
	if base == "" {
		base = "<ui-url>"
	}
	return base + "/set-password#token=" + token
}
