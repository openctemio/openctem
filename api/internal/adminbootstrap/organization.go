package adminbootstrap

// The first organization (bootstrap-admin -org-name/-org-owner-email).
//
// A platform administrator belongs to no organization, so a fresh installation
// has no one who can use the product until an organization exists. The
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
	case o.OrgOwnerEmail == o.Email || o.OrgOwnerEmail == o.BackupEmail:
		// A platform administrator belongs to no organization (RFC-022 rev.2).
		return errors.New("a platform administrator cannot own an organization: use a different -org-owner-email")
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
	provisioning := tenantapp.NewUserProvisioningService(tenantRepo, userRepo, nil, o.OrgSetupMailer, auditSvc, log)
	created, err := tenantapp.NewOrganizationCreator(tenantSvc, provisioning, userRepo, log).
		Create(ctx, tenantapp.CreateOrganizationInput{
			Name: o.OrgName, Slug: o.OrgSlug,
			OwnerEmail: o.OrgOwnerEmail, OwnerName: o.OrgOwnerName,
		}, auditapp.AuditContext{ActorEmail: AuditActor})
	if err != nil {
		if errors.Is(err, tenantdom.ErrPlatformAdminMembership) {
			return fmt.Errorf("%s is a platform administrator, and a platform administrator cannot own an organization: use a different -org-owner-email", o.OrgOwnerEmail)
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
	case created.OwnerSetup == nil:
		fmt.Fprintf(out, "  Owner:    %s (new account)\n", created.Owner.Email())
		fmt.Fprintln(out, "  The set-password link could not be issued. The owner can use \"Forgot password\" on")
		fmt.Fprintln(out, "  the sign-in page, or an administrator issues a new link from the console.")
	case created.OwnerSetup.EmailSent:
		fmt.Fprintf(out, "  Owner:    %s (new account)\n", created.Owner.Email())
		fmt.Fprintf(out, "  A one-time set-password link was emailed to the owner (valid %d hours).\n", int(tenantapp.AccountSetupTTL.Hours()))
	default:
		fmt.Fprintf(out, "  Owner:    %s (new account)\n", created.Owner.Email())
		fmt.Fprintf(out, "  Set-password link (shown once, valid %d hours; give it to the owner over a trusted channel):\n", int(tenantapp.AccountSetupTTL.Hours()))
		fmt.Fprintf(out, "    %s\n", setupLinkURL(o.UIBaseURL, created.OwnerSetup.SetupToken))
	}
	return nil
}

// setupLinkURL is the UI page that consumes a one-time set-password token (the
// same URL the email carries).
func setupLinkURL(base, token string) string {
	base = strings.TrimSuffix(strings.TrimSpace(base), "/")
	if base == "" {
		base = "<ui-url>"
	}
	return base + "/set-password?token=" + token
}
