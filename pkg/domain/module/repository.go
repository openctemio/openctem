package module

import (
	"context"

	"github.com/google/uuid"
)

// PlanRepository defines the interface for plan persistence operations.
type PlanRepository interface {
	// GetByID retrieves a plan by its ID.
	GetByID(ctx context.Context, id ID) (*Plan, error)

	// GetBySlug retrieves a plan by its slug.
	GetBySlug(ctx context.Context, slug string) (*Plan, error)

	// ListPublicPlans returns all public plans.
	ListPublicPlans(ctx context.Context) ([]*Plan, error)

	// ListAllPlans returns all plans (including non-public).
	ListAllPlans(ctx context.Context) ([]*Plan, error)

	// GetPlanWithModules retrieves a plan with its modules populated.
	GetPlanWithModules(ctx context.Context, id ID) (*Plan, error)
}

// ModuleRepository defines the interface for module persistence operations.
type ModuleRepository interface {
	// GetByID retrieves a module by its ID.
	GetByID(ctx context.Context, id string) (*Module, error)

	// GetBySlug retrieves a module by its slug.
	GetBySlug(ctx context.Context, slug string) (*Module, error)

	// ListAll returns all modules.
	ListAll(ctx context.Context) ([]*Module, error)

	// ListActive returns all active modules.
	ListActive(ctx context.Context) ([]*Module, error)

	// ListByCategory returns modules filtered by category.
	ListByCategory(ctx context.Context, category string) ([]*Module, error)

	// GetModulesForPlan returns all modules included in a plan.
	GetModulesForPlan(ctx context.Context, planID ID) ([]*Module, error)

	// GetEventTypesForModule returns event types associated with a module.
	GetEventTypesForModule(ctx context.Context, moduleID string) ([]string, error)

	// GetModuleForEventType returns the module that owns a specific event type.
	GetModuleForEventType(ctx context.Context, eventType string) (*Module, error)
}

// SubscriptionRepository defines the interface for subscription persistence operations.
type SubscriptionRepository interface {
	// GetByTenantID retrieves the subscription for a tenant.
	GetByTenantID(ctx context.Context, tenantID uuid.UUID) (*TenantSubscription, error)

	// GetEnabledModuleIDs returns the module IDs enabled for a tenant.
	GetEnabledModuleIDs(ctx context.Context, tenantID uuid.UUID) ([]string, error)

	// HasModule checks if a tenant has access to a specific module.
	HasModule(ctx context.Context, tenantID uuid.UUID, moduleID string) (bool, error)

	// GetModuleLimit returns the effective limit for a module metric.
	GetModuleLimit(ctx context.Context, tenantID uuid.UUID, moduleID, metric string) (int64, error)

	// UpdateSubscription updates a tenant's subscription.
	UpdateSubscription(ctx context.Context, subscription *TenantSubscription) error

	// UpdatePlan changes a tenant's plan.
	UpdatePlan(ctx context.Context, tenantID, planID uuid.UUID) error

	// UpdateStatus updates the subscription status.
	UpdateStatus(ctx context.Context, tenantID uuid.UUID, status SubscriptionStatus) error

	// SetLimitsOverride sets custom limits for a tenant.
	SetLimitsOverride(ctx context.Context, tenantID uuid.UUID, limits map[string]any) error
}
