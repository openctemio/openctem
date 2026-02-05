package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/capability"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

const defaultCapabilityColor = "gray"

// CapabilityService handles capability business operations.
type CapabilityService struct {
	repo         capability.Repository
	auditService *AuditService
	logger       *logger.Logger
}

// NewCapabilityService creates a new CapabilityService.
func NewCapabilityService(
	repo capability.Repository,
	auditService *AuditService,
	log *logger.Logger,
) *CapabilityService {
	return &CapabilityService{
		repo:         repo,
		auditService: auditService,
		logger:       log.With("service", "capability"),
	}
}

// =============================================================================
// List Operations
// =============================================================================

// ListCapabilitiesInput represents the input for listing capabilities.
type ListCapabilitiesInput struct {
	TenantID  string
	IsBuiltin *bool
	Category  *string
	Search    string
	Page      int
	PerPage   int
}

// ListCapabilities returns capabilities matching the filter.
// Always includes platform (builtin) capabilities.
// If TenantID is provided, also includes that tenant's custom capabilities.
func (s *CapabilityService) ListCapabilities(ctx context.Context, input ListCapabilitiesInput) (pagination.Result[*capability.Capability], error) {
	s.logger.Debug("listing capabilities", "tenant_id", input.TenantID, "search", input.Search)

	var tenantID *shared.ID
	if input.TenantID != "" {
		tid, err := shared.IDFromString(input.TenantID)
		if err != nil {
			return pagination.Result[*capability.Capability]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		tenantID = &tid
	}

	filter := capability.Filter{
		TenantID:  tenantID,
		IsBuiltin: input.IsBuiltin,
		Category:  input.Category,
		Search:    input.Search,
	}

	page := pagination.New(input.Page, input.PerPage)

	return s.repo.List(ctx, filter, page)
}

// ListAllCapabilities returns all capabilities for a tenant context (for dropdowns).
func (s *CapabilityService) ListAllCapabilities(ctx context.Context, tenantID string) ([]*capability.Capability, error) {
	s.logger.Debug("listing all capabilities", "tenant_id", tenantID)

	var tid *shared.ID
	if tenantID != "" {
		t, err := shared.IDFromString(tenantID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		tid = &t
	}

	return s.repo.ListAll(ctx, tid)
}

// ListCapabilitiesByNames returns capabilities by their names.
func (s *CapabilityService) ListCapabilitiesByNames(ctx context.Context, tenantID string, names []string) ([]*capability.Capability, error) {
	s.logger.Debug("listing capabilities by names", "tenant_id", tenantID, "names", names)

	if len(names) == 0 {
		return nil, nil
	}

	var tid *shared.ID
	if tenantID != "" {
		t, err := shared.IDFromString(tenantID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		tid = &t
	}

	return s.repo.ListByNames(ctx, tid, names)
}

// ListCapabilitiesByCategory returns all capabilities in a category.
func (s *CapabilityService) ListCapabilitiesByCategory(ctx context.Context, tenantID string, category string) ([]*capability.Capability, error) {
	s.logger.Debug("listing capabilities by category", "tenant_id", tenantID, "category", category)

	var tid *shared.ID
	if tenantID != "" {
		t, err := shared.IDFromString(tenantID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		tid = &t
	}

	return s.repo.ListByCategory(ctx, tid, category)
}

// GetCapability returns a capability by ID.
func (s *CapabilityService) GetCapability(ctx context.Context, id string) (*capability.Capability, error) {
	s.logger.Debug("getting capability", "id", id)

	capabilityID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid capability id", shared.ErrValidation)
	}

	return s.repo.GetByID(ctx, capabilityID)
}

// GetCategories returns all unique capability categories.
func (s *CapabilityService) GetCategories(ctx context.Context) ([]string, error) {
	s.logger.Debug("getting capability categories")

	return s.repo.GetCategories(ctx)
}

// =============================================================================
// Tenant Custom Capability Operations
// =============================================================================

// CreateCapabilityInput represents the input for creating a tenant custom capability.
type CreateCapabilityInput struct {
	TenantID    string `json:"-"`
	CreatedBy   string `json:"-"`
	Name        string `json:"name" validate:"required,min=2,max=50"`
	DisplayName string `json:"display_name" validate:"required,max=100"`
	Description string `json:"description" validate:"max=500"`
	Icon        string `json:"icon" validate:"max=50"`
	Color       string `json:"color" validate:"max=20"`
	Category    string `json:"category" validate:"max=50"`

	// Audit context (set by handler)
	AuditContext AuditContext `json:"-"`
}

// CreateCapability creates a new tenant custom capability.
func (s *CapabilityService) CreateCapability(ctx context.Context, input CreateCapabilityInput) (*capability.Capability, error) {
	s.logger.Info("creating capability", "tenant_id", input.TenantID, "name", input.Name)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	createdBy, err := shared.IDFromString(input.CreatedBy)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid created_by user id", shared.ErrValidation)
	}

	// Security: Rate limiting - check custom capability count per tenant
	count, err := s.repo.CountByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to check capability count: %w", err)
	}
	if count >= capability.MaxCustomCapabilitiesPerTenant {
		s.logger.Warn("capability limit exceeded",
			"tenant_id", input.TenantID,
			"current_count", count,
			"limit", capability.MaxCustomCapabilitiesPerTenant,
		)
		return nil, fmt.Errorf("%w: maximum custom capabilities limit reached (%d)",
			shared.ErrValidation, capability.MaxCustomCapabilitiesPerTenant)
	}

	// Check if capability name already exists (in platform or tenant scope)
	existsInPlatform, err := s.repo.ExistsByName(ctx, nil, input.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check capability: %w", err)
	}
	if existsInPlatform {
		// Security: Generic error message to prevent information disclosure
		return nil, fmt.Errorf("%w: capability name is not available", shared.ErrConflict)
	}

	existsInTenant, err := s.repo.ExistsByName(ctx, &tenantID, input.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check capability: %w", err)
	}
	if existsInTenant {
		// Security: Generic error message to prevent information disclosure
		return nil, fmt.Errorf("%w: capability name is not available", shared.ErrConflict)
	}

	// Set defaults
	icon := input.Icon
	if icon == "" {
		icon = "zap"
	}

	color := input.Color
	if color == "" {
		color = defaultCapabilityColor
	}

	c, err := capability.NewTenantCapability(
		tenantID,
		createdBy,
		input.Name,
		input.DisplayName,
		input.Description,
		icon,
		color,
		input.Category,
	)
	if err != nil {
		return nil, err
	}

	if err := s.repo.Create(ctx, c); err != nil {
		return nil, fmt.Errorf("failed to create capability: %w", err)
	}

	s.logger.Info("capability created", "id", c.ID.String(), "name", c.Name)

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogEvent(ctx, input.AuditContext, NewSuccessEvent(
			audit.ActionCapabilityCreated,
			audit.ResourceTypeCapability,
			c.ID.String(),
		).WithResourceName(c.Name).
			WithMessage(fmt.Sprintf("Capability '%s' created", c.DisplayName)))
	}

	return c, nil
}

// UpdateCapabilityInput represents the input for updating a capability.
type UpdateCapabilityInput struct {
	TenantID    string `json:"-"`
	ID          string `json:"-"`
	DisplayName string `json:"display_name" validate:"required,max=100"`
	Description string `json:"description" validate:"max=500"`
	Icon        string `json:"icon" validate:"max=50"`
	Color       string `json:"color" validate:"max=20"`
	Category    string `json:"category" validate:"max=50"`

	// Audit context (set by handler)
	AuditContext AuditContext `json:"-"`
}

// UpdateCapability updates an existing tenant custom capability.
func (s *CapabilityService) UpdateCapability(ctx context.Context, input UpdateCapabilityInput) (*capability.Capability, error) {
	s.logger.Info("updating capability", "id", input.ID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	capabilityID, err := shared.IDFromString(input.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid capability id", shared.ErrValidation)
	}

	c, err := s.repo.GetByID(ctx, capabilityID)
	if err != nil {
		return nil, err
	}

	// Check ownership - only tenant's own capabilities can be updated
	if !c.CanBeModifiedByTenant(tenantID) {
		return nil, fmt.Errorf("%w: cannot modify this capability", shared.ErrForbidden)
	}

	// Track changes for audit
	oldDisplayName := c.DisplayName
	oldDescription := c.Description

	// Set defaults
	icon := input.Icon
	if icon == "" {
		icon = "zap"
	}

	color := input.Color
	if color == "" {
		color = defaultCapabilityColor
	}

	if err := c.Update(input.DisplayName, input.Description, icon, color, input.Category); err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, c); err != nil {
		return nil, fmt.Errorf("failed to update capability: %w", err)
	}

	s.logger.Info("capability updated", "id", c.ID.String())

	// Audit log
	if s.auditService != nil {
		changes := audit.NewChanges()
		if oldDisplayName != c.DisplayName {
			changes = changes.Set("display_name", oldDisplayName, c.DisplayName)
		}
		if oldDescription != c.Description {
			changes = changes.Set("description", oldDescription, c.Description)
		}

		_ = s.auditService.LogEvent(ctx, input.AuditContext, NewSuccessEvent(
			audit.ActionCapabilityUpdated,
			audit.ResourceTypeCapability,
			c.ID.String(),
		).WithResourceName(c.Name).
			WithChanges(changes).
			WithMessage(fmt.Sprintf("Capability '%s' updated", c.DisplayName)))
	}

	return c, nil
}

// DeleteCapabilityInput represents the input for deleting a capability.
type DeleteCapabilityInput struct {
	TenantID     string
	CapabilityID string
	Force        bool // Force delete even if capability is in use

	// Audit context (set by handler)
	AuditContext AuditContext
}

// CapabilityUsageStatsOutput represents usage statistics for a capability.
type CapabilityUsageStatsOutput struct {
	ToolCount  int      `json:"tool_count"`
	AgentCount int      `json:"agent_count"`
	ToolNames  []string `json:"tool_names,omitempty"`
	AgentNames []string `json:"agent_names,omitempty"`
}

// DeleteCapability deletes a tenant custom capability.
// If capability is in use and Force is false, returns ErrConflict with usage info.
func (s *CapabilityService) DeleteCapability(ctx context.Context, input DeleteCapabilityInput) error {
	s.logger.Info("deleting capability", "tenant_id", input.TenantID, "id", input.CapabilityID)

	tid, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	cid, err := shared.IDFromString(input.CapabilityID)
	if err != nil {
		return fmt.Errorf("%w: invalid capability id", shared.ErrValidation)
	}

	c, err := s.repo.GetByID(ctx, cid)
	if err != nil {
		return err
	}

	// Check ownership - only tenant's own capabilities can be deleted
	if !c.CanBeModifiedByTenant(tid) {
		return fmt.Errorf("%w: cannot delete this capability", shared.ErrForbidden)
	}

	capabilityName := c.Name
	capabilityDisplayName := c.DisplayName

	// Check if capability is in use by any tools or agents
	if !input.Force {
		stats, err := s.repo.GetUsageStats(ctx, cid)
		if err != nil {
			s.logger.Warn("failed to check capability usage", "error", err)
			// Continue with delete if usage check fails (non-critical)
		} else if stats.ToolCount > 0 || stats.AgentCount > 0 {
			return fmt.Errorf("%w: capability is in use by %d tool(s) and %d agent(s). Use force=true to delete anyway",
				shared.ErrConflict, stats.ToolCount, stats.AgentCount)
		}
	}

	if err := s.repo.Delete(ctx, cid); err != nil {
		return err
	}

	s.logger.Info("capability deleted", "id", input.CapabilityID, "force", input.Force)

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogEvent(ctx, input.AuditContext, NewSuccessEvent(
			audit.ActionCapabilityDeleted,
			audit.ResourceTypeCapability,
			input.CapabilityID,
		).WithResourceName(capabilityName).
			WithSeverity(audit.SeverityMedium).
			WithMessage(fmt.Sprintf("Capability '%s' deleted", capabilityDisplayName)))
	}

	return nil
}

// GetCapabilityUsageStats returns usage statistics for a capability.
// Security: Validates tenant has access to view the capability (platform or owned custom).
func (s *CapabilityService) GetCapabilityUsageStats(ctx context.Context, tenantIDStr string, capabilityID string) (*CapabilityUsageStatsOutput, error) {
	s.logger.Debug("getting capability usage stats", "id", capabilityID, "tenantID", tenantIDStr)

	cid, err := shared.IDFromString(capabilityID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid capability id", shared.ErrValidation)
	}

	// Parse tenant ID
	var tenantID *shared.ID
	if tenantIDStr != "" {
		tid, err := shared.IDFromString(tenantIDStr)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		tenantID = &tid
	}

	// Check if capability exists and tenant has access
	cap, err := s.repo.GetByID(ctx, cid)
	if err != nil {
		return nil, err
	}

	// Security: Ensure tenant can access this capability
	// Platform capabilities (is_builtin=true) are accessible to all
	// Custom capabilities are only accessible to their owning tenant
	if !cap.IsBuiltin && cap.TenantID != nil {
		if tenantID == nil || *cap.TenantID != *tenantID {
			return nil, fmt.Errorf("%w: capability not found", shared.ErrNotFound)
		}
	}

	stats, err := s.repo.GetUsageStats(ctx, cid)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage stats: %w", err)
	}

	return &CapabilityUsageStatsOutput{
		ToolCount:  stats.ToolCount,
		AgentCount: stats.AgentCount,
		ToolNames:  stats.ToolNames,
		AgentNames: stats.AgentNames,
	}, nil
}

// GetCapabilitiesUsageStatsBatch returns usage statistics for multiple capabilities.
// Security: Filters out capabilities the tenant doesn't have access to.
func (s *CapabilityService) GetCapabilitiesUsageStatsBatch(ctx context.Context, tenantIDStr string, capabilityIDs []string) (map[string]*CapabilityUsageStatsOutput, error) {
	s.logger.Debug("getting capability usage stats batch", "count", len(capabilityIDs), "tenantID", tenantIDStr)

	if len(capabilityIDs) == 0 {
		return map[string]*CapabilityUsageStatsOutput{}, nil
	}

	// Parse tenant ID
	var tenantID *shared.ID
	if tenantIDStr != "" {
		tid, err := shared.IDFromString(tenantIDStr)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		tenantID = &tid
	}

	ids := make([]shared.ID, 0, len(capabilityIDs))
	for _, idStr := range capabilityIDs {
		id, err := shared.IDFromString(idStr)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid capability id %s", shared.ErrValidation, idStr)
		}
		ids = append(ids, id)
	}

	// Security: Get capabilities and filter to only those tenant can access
	// This prevents information disclosure about other tenants' capabilities
	accessibleIDs := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		cap, err := s.repo.GetByID(ctx, id)
		if err != nil {
			// Skip capabilities that don't exist
			continue
		}
		// Platform capabilities are accessible to all
		// Custom capabilities only to their owning tenant
		if cap.IsBuiltin {
			accessibleIDs = append(accessibleIDs, id)
		} else if cap.TenantID != nil && tenantID != nil && *cap.TenantID == *tenantID {
			accessibleIDs = append(accessibleIDs, id)
		}
	}

	if len(accessibleIDs) == 0 {
		return map[string]*CapabilityUsageStatsOutput{}, nil
	}

	stats, err := s.repo.GetUsageStatsBatch(ctx, accessibleIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage stats: %w", err)
	}

	result := make(map[string]*CapabilityUsageStatsOutput, len(stats))
	for id, stat := range stats {
		result[id.String()] = &CapabilityUsageStatsOutput{
			ToolCount:  stat.ToolCount,
			AgentCount: stat.AgentCount,
			ToolNames:  stat.ToolNames,
			AgentNames: stat.AgentNames,
		}
	}

	return result, nil
}
