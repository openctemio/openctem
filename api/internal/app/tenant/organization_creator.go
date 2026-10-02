package tenant

// Organizations created by the platform administrator: from the admin console
// (POST /api/v1/admin/tenants) and from the bootstrap-admin command at first
// install. Both go through OrganizationCreator so the organization, its owner
// account, the owner's membership and role, the audit trail and the owner's
// one-time set-password link are the same whichever way it was created.

import (
	"context"
	"fmt"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ErrOwnerAccountRequired is returned when the owner email has no account and
// this installation cannot create one (no account provisioning wired).
var ErrOwnerAccountRequired = fmt.Errorf("%w: owner_email must belong to an existing user", shared.ErrValidation)

// CreateOrganizationInput describes an organization the platform administrator
// creates, and who owns it.
type CreateOrganizationInput struct {
	Name        string
	Slug        string
	Description string
	// OwnerEmail is the owner's account. When no account has this email, a new
	// password-less one is created and the owner sets a password through a
	// one-time link.
	OwnerEmail string
	// OwnerName is used only for a new account (defaults to the email).
	OwnerName string
}

// CreatedOrganization is the result of OrganizationCreator.Create.
type CreatedOrganization struct {
	Tenant *tenantdom.Tenant
	Owner  *userdom.User
	// OwnerCreated is true when the owner's account was created for this
	// organization.
	OwnerCreated bool
	// OwnerSetup carries the owner's one-time set-password link (emailed, or
	// SetupToken returned once). Nil when the owner already had an account, or
	// when the link could not be issued (the owner then uses forgot-password).
	OwnerSetup *ProvisionedUser
}

// OrganizationCreator creates an organization together with its owner on
// behalf of the platform administrator. It works in either
// TENANT_CREATION_MODE: that setting governs self-service creation only.
type OrganizationCreator struct {
	tenants      *TenantService
	provisioning *UserProvisioningService
	users        userdom.Repository
	logger       *logger.Logger
}

// NewOrganizationCreator wires the creator. provisioning may be nil: the owner
// must then already have an account.
func NewOrganizationCreator(tenants *TenantService, provisioning *UserProvisioningService, users userdom.Repository, log *logger.Logger) *OrganizationCreator {
	return &OrganizationCreator{
		tenants: tenants, provisioning: provisioning, users: users,
		logger: log.With("service", "organization_creator"),
	}
}

// Create creates the organization with in.OwnerEmail as its owner (atomic
// tenant + owner membership + owner role, audited tenant.created). A new owner
// account is audited user.created in the new organization and gets its
// set-password link; if creating the organization fails, that account is
// removed again.
func (c *OrganizationCreator) Create(ctx context.Context, in CreateOrganizationInput, actx auditapp.AuditContext) (*CreatedOrganization, error) {
	ownerEmail := strings.ToLower(strings.TrimSpace(in.OwnerEmail))
	if ownerEmail == "" || !strings.Contains(ownerEmail, "@") {
		return nil, fmt.Errorf("%w: a valid owner email is required", shared.ErrValidation)
	}

	owner, err := c.users.GetByEmail(ctx, ownerEmail)
	ownerCreated := false
	if err != nil {
		if !shared.IsNotFound(err) {
			return nil, fmt.Errorf("look up owner: %w", err)
		}
		if c.provisioning == nil {
			return nil, ErrOwnerAccountRequired
		}
		// No account yet: create one for the owner. The password is set
		// through a one-time link issued once the organization exists.
		owner, err = c.provisioning.CreateAccount(ctx, ownerEmail, in.OwnerName)
		if err != nil {
			return nil, err
		}
		ownerCreated = true
	}

	t, err := c.tenants.CreateTenant(ctx, CreateTenantInput{
		Name: in.Name, Slug: in.Slug, Description: in.Description,
	}, owner.ID(), actx)
	if err != nil {
		// tenantdom.ErrPlatformAdminMembership (the owner is a platform
		// administrator) and slug conflicts surface unchanged.
		if ownerCreated {
			c.provisioning.DiscardAccount(ctx, owner.ID())
		}
		return nil, err
	}

	res := &CreatedOrganization{Tenant: t, Owner: owner, OwnerCreated: ownerCreated}
	if !ownerCreated {
		return res, nil
	}

	// The first-owner rule (console and bootstrap-admin alike): the link is
	// emailed when the organization can send email and never handed to the
	// administrator then; it is returned once only when email is impossible.
	// It also writes the owner's user.created event to the organization's log.
	setup, err := c.provisioning.IssueFirstOwnerSetupLink(ctx, t, owner, actx)
	if err != nil {
		// The organization exists; the owner can still use forgot-password.
		c.logger.Error("issue owner setup link", "tenant_id", t.ID().String(), "error", logger.SanitizeError(err))
		return res, nil
	}
	res.OwnerSetup = setup
	return res, nil
}
