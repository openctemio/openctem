package accesscontrol

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/serviceaccount"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ServiceAccountService manages service accounts: organization-owned
// identities for integrations. A new account holds no role; roles are given
// with the usual role APIs (grant ceiling included) and API keys are minted
// for it with the API key APIs. It can never sign in, never be an owner or
// administrator, and never hold full data access.
type ServiceAccountService struct {
	repo   serviceaccount.Repository
	audit  *auditapp.AuditService
	logger *logger.Logger
}

// NewServiceAccountService creates the service.
func NewServiceAccountService(repo serviceaccount.Repository, audit *auditapp.AuditService, log *logger.Logger) *ServiceAccountService {
	return &ServiceAccountService{repo: repo, audit: audit, logger: log.With("service", "service_account")}
}

// CreateServiceAccountInput creates a service account.
type CreateServiceAccountInput struct {
	Name        string `json:"name" validate:"required,max=100"`
	Description string `json:"description" validate:"max=500"`
}

func (s *ServiceAccountService) log(ctx context.Context, actx auditapp.AuditContext, e auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, e); err != nil {
		s.logger.Error("failed to log audit event", "error", err)
	}
}

// Create makes a service account in the caller's organization, with the
// caller as the accountable person.
func (s *ServiceAccountService) Create(ctx context.Context, input CreateServiceAccountInput, actx auditapp.AuditContext) (*serviceaccount.ServiceAccount, error) {
	tid, err := shared.IDFromString(actx.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	name, err := serviceaccount.ValidateName(input.Name)
	if err != nil {
		return nil, err
	}
	if len(input.Description) > 500 {
		return nil, fmt.Errorf("%w: the description is too long", serviceaccount.ErrInvalid)
	}
	a := &serviceaccount.ServiceAccount{
		ID: shared.NewID(), TenantID: tid, Name: name, Description: input.Description, Status: "active",
	}
	if owner, err := shared.IDFromString(actx.ActorID); err == nil {
		a.OwnerID = &owner
	}
	if err := s.repo.Create(ctx, a); err != nil {
		return nil, err
	}
	s.log(ctx, actx, auditapp.NewSuccessEvent(audit.ActionUserCreated, audit.ResourceTypeUser, a.ID.String()).
		WithResourceName(a.Name).
		WithMessage(fmt.Sprintf("Service account %q created", a.Name)).
		WithMetadata("kind", "service").
		WithSeverity(audit.SeverityHigh))
	return s.repo.Get(ctx, tid, a.ID)
}

// List returns the organization's service accounts.
func (s *ServiceAccountService) List(ctx context.Context, tenantID string) ([]*serviceaccount.ServiceAccount, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return s.repo.List(ctx, tid)
}

// Delete removes a service account; its roles, team memberships and API keys
// go with it at once.
func (s *ServiceAccountService) Delete(ctx context.Context, id string, actx auditapp.AuditContext) error {
	tid, err := shared.IDFromString(actx.TenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	aid, err := shared.IDFromString(id)
	if err != nil {
		return serviceaccount.ErrNotFound
	}
	a, err := s.repo.Get(ctx, tid, aid)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, tid, aid); err != nil {
		return err
	}
	s.log(ctx, actx, auditapp.NewSuccessEvent(audit.ActionUserDeleted, audit.ResourceTypeUser, a.ID.String()).
		WithResourceName(a.Name).
		WithMessage(fmt.Sprintf("Service account %q deleted with its roles and API keys", a.Name)).
		WithMetadata("kind", "service").
		WithMetadata("api_keys_revoked", a.APIKeys).
		WithSeverity(audit.SeverityHigh))
	return nil
}
