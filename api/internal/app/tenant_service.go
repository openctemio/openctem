package app

// Compatibility shim — real impl lives in internal/app/tenant/.
// Covers tenant, user, tenant_membership_adapter (tenant bounded context).

import "github.com/openctemio/openctem/api/internal/app/tenant"

type (
	TenantService           = tenant.TenantService
	TenantServiceOption     = tenant.TenantServiceOption
	UserService             = tenant.UserService
	TenantMembershipAdapter = tenant.TenantMembershipAdapter

	UserProvisioningService = tenant.UserProvisioningService
	AccountSetupMailer      = tenant.AccountSetupMailer
	CreateUserInput         = tenant.CreateUserInput
	ProvisionedUser         = tenant.ProvisionedUser

	AddMemberInput              = tenant.AddMemberInput
	BranchTypeRuleInput         = tenant.BranchTypeRuleInput
	CreateInvitationInput       = tenant.CreateInvitationInput
	CreateTenantInput           = tenant.CreateTenantInput
	EmailJobEnqueuer            = tenant.EmailJobEnqueuer
	MemberStatusEmailNotifier   = tenant.MemberStatusEmailNotifier
	TeamInvitationJobPayload    = tenant.TeamInvitationJobPayload
	UpdateBranchSettingsInput   = tenant.UpdateBranchSettingsInput
	UpdateBrandingSettingsInput = tenant.UpdateBrandingSettingsInput
	UpdateGeneralSettingsInput  = tenant.UpdateGeneralSettingsInput
	UpdateMemberRoleInput       = tenant.UpdateMemberRoleInput
	UpdatePentestSettingsInput  = tenant.UpdatePentestSettingsInput
	UpdateProfileInput          = tenant.UpdateProfileInput
	UpdateSecuritySettingsInput = tenant.UpdateSecuritySettingsInput
	UpdateTenantInput           = tenant.UpdateTenantInput
	UserInfoProvider            = tenant.UserInfoProvider
)

// Errors re-exported from the tenant bounded context.
var (
	ErrAccountExists                = tenant.ErrAccountExists
	ErrEmailDomainNotAllowed        = tenant.ErrEmailDomainNotAllowed
	ErrNotPendingSetup              = tenant.ErrNotPendingSetup
	ErrSetupLinkForbidden           = tenant.ErrSetupLinkForbidden
	ErrIPAllowlistExcludesRequester = tenant.ErrIPAllowlistExcludesRequester
)

var (
	NewTenantService                   = tenant.NewTenantService
	NewUserService                     = tenant.NewUserService
	NewUserProvisioningService         = tenant.NewUserProvisioningService
	NewTenantMembershipAdapter         = tenant.NewTenantMembershipAdapter
	WithEmailEnqueuer                  = tenant.WithEmailEnqueuer
	WithTenantAuditService             = tenant.WithTenantAuditService
	WithTenantPermissionCacheService   = tenant.WithTenantPermissionCacheService
	WithTenantPermissionVersionService = tenant.WithTenantPermissionVersionService
	WithUserInfoProvider               = tenant.WithUserInfoProvider
)
