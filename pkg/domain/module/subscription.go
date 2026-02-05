package module

import (
	"time"

	"github.com/google/uuid"
)

// SubscriptionStatus represents the status of a tenant's subscription.
type SubscriptionStatus string

const (
	StatusActive   SubscriptionStatus = "active"
	StatusTrial    SubscriptionStatus = "trial"
	StatusPastDue  SubscriptionStatus = "past_due"
	StatusCanceled SubscriptionStatus = "cancelled"
	StatusExpired  SubscriptionStatus = "expired"
)

// BillingCycle represents the billing frequency.
type BillingCycle string

const (
	BillingMonthly BillingCycle = "monthly"
	BillingYearly  BillingCycle = "yearly"
)

// TenantSubscription represents a tenant's subscription to a plan.
type TenantSubscription struct {
	tenantID       uuid.UUID
	planID         uuid.UUID
	plan           *Plan
	status         SubscriptionStatus
	billingCycle   BillingCycle
	startedAt      time.Time
	expiresAt      *time.Time
	canceledAt     *time.Time
	limitsOverride map[string]any

	// Stripe integration
	stripeCustomerID     string
	stripeSubscriptionID string

	// Billing contact
	billingEmail string
}

// Getters

func (s *TenantSubscription) TenantID() uuid.UUID            { return s.tenantID }
func (s *TenantSubscription) PlanID() uuid.UUID              { return s.planID }
func (s *TenantSubscription) Plan() *Plan                    { return s.plan }
func (s *TenantSubscription) Status() SubscriptionStatus     { return s.status }
func (s *TenantSubscription) BillingCycle() BillingCycle     { return s.billingCycle }
func (s *TenantSubscription) StartedAt() time.Time           { return s.startedAt }
func (s *TenantSubscription) ExpiresAt() *time.Time          { return s.expiresAt }
func (s *TenantSubscription) CanceledAt() *time.Time         { return s.canceledAt }
func (s *TenantSubscription) LimitsOverride() map[string]any { return s.limitsOverride }
func (s *TenantSubscription) StripeCustomerID() string       { return s.stripeCustomerID }
func (s *TenantSubscription) StripeSubscriptionID() string   { return s.stripeSubscriptionID }
func (s *TenantSubscription) BillingEmail() string           { return s.billingEmail }

// IsActive checks if the subscription is currently active.
func (s *TenantSubscription) IsActive() bool {
	switch s.status {
	case StatusActive, StatusTrial:
		return true
	case StatusCanceled:
		// Canceled but not yet expired
		if s.expiresAt != nil && s.expiresAt.After(time.Now()) {
			return true
		}
		return false
	default:
		return false
	}
}

// HasModule checks if the tenant has access to a specific module.
func (s *TenantSubscription) HasModule(moduleID string) bool {
	if !s.IsActive() {
		return false
	}
	if s.plan == nil {
		return false
	}
	return s.plan.HasModule(moduleID)
}

// GetModuleLimit returns the effective limit for a module metric.
// Override limits take precedence over plan limits.
// Returns -1 if unlimited.
func (s *TenantSubscription) GetModuleLimit(moduleID, metric string) int64 {
	// Check override first
	overrideKey := moduleID + ":" + metric
	if override, ok := s.limitsOverride[overrideKey]; ok {
		if f, ok := override.(float64); ok {
			return int64(f)
		}
	}
	// Check metric directly in override
	if override, ok := s.limitsOverride[metric]; ok {
		if f, ok := override.(float64); ok {
			return int64(f)
		}
	}

	// Fall back to plan limit
	if s.plan != nil {
		return s.plan.GetModuleLimit(moduleID, metric)
	}

	return 0
}

// GetEnabledModuleIDs returns all module IDs available to this subscription.
func (s *TenantSubscription) GetEnabledModuleIDs() []string {
	if s.plan == nil || !s.IsActive() {
		return nil
	}
	return s.plan.GetModuleIDs()
}

// ReconstructTenantSubscription creates a TenantSubscription from stored data.
func ReconstructTenantSubscription(
	tenantID, planID uuid.UUID,
	plan *Plan,
	status SubscriptionStatus,
	billingCycle BillingCycle,
	startedAt time.Time,
	expiresAt, canceledAt *time.Time,
	limitsOverride map[string]any,
	stripeCustomerID, stripeSubscriptionID, billingEmail string,
) *TenantSubscription {
	return &TenantSubscription{
		tenantID:             tenantID,
		planID:               planID,
		plan:                 plan,
		status:               status,
		billingCycle:         billingCycle,
		startedAt:            startedAt,
		expiresAt:            expiresAt,
		canceledAt:           canceledAt,
		limitsOverride:       limitsOverride,
		stripeCustomerID:     stripeCustomerID,
		stripeSubscriptionID: stripeSubscriptionID,
		billingEmail:         billingEmail,
	}
}
