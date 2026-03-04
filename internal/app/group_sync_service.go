package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/group"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// GroupSyncService handles synchronization of groups from external providers
// such as GitHub Teams, GitLab Groups, Azure AD, and Okta.
type GroupSyncService struct {
	groupRepo group.Repository
	logger    *logger.Logger
}

// NewGroupSyncService creates a new GroupSyncService.
func NewGroupSyncService(groupRepo group.Repository, log *logger.Logger) *GroupSyncService {
	return &GroupSyncService{
		groupRepo: groupRepo,
		logger:    log.With("service", "group-sync"),
	}
}

// SyncFromProvider synchronizes groups from an external provider.
// This is a placeholder implementation. Actual provider integration (GitHub Teams,
// GitLab Groups, Azure AD, Okta) will be implemented as separate tasks.
//
// The config parameter would contain provider-specific configuration such as:
//   - GitHub: org name, API token
//   - GitLab: group ID, API token
//   - Azure AD: tenant ID, client credentials
//   - Okta: domain, API token
func (s *GroupSyncService) SyncFromProvider(ctx context.Context, tenantID shared.ID, provider string, config map[string]interface{}) error {
	src := group.ExternalSource(provider)
	if !src.IsValid() {
		return fmt.Errorf("%w: unsupported provider '%s'", shared.ErrValidation, provider)
	}

	s.logger.Info("sync from provider requested (not yet implemented)",
		"tenant_id", tenantID.String(),
		"provider", provider,
	)

	return fmt.Errorf("%w: external group sync not yet available", shared.ErrNotImplemented)
}

// SyncAll synchronizes all configured external providers for a tenant.
// This is a placeholder implementation that iterates over groups with external sources
// and triggers sync for each unique provider.
func (s *GroupSyncService) SyncAll(ctx context.Context, tenantID shared.ID) error {
	s.logger.Info("sync all providers requested (not yet implemented)",
		"tenant_id", tenantID.String(),
	)

	return fmt.Errorf("%w: external group sync not yet available", shared.ErrNotImplemented)
}
