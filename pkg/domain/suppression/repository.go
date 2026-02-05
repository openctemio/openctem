package suppression

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Repository defines the interface for suppression rule persistence.
type Repository interface {
	// Rule operations
	Save(ctx context.Context, rule *Rule) error
	FindByID(ctx context.Context, tenantID, id shared.ID) (*Rule, error)
	Delete(ctx context.Context, tenantID, id shared.ID) error

	// Query operations
	FindByTenant(ctx context.Context, tenantID shared.ID, filter RuleFilter) ([]*Rule, error)
	FindActiveByTenant(ctx context.Context, tenantID shared.ID) ([]*Rule, error)
	FindPendingByTenant(ctx context.Context, tenantID shared.ID) ([]*Rule, error)

	// Matching
	FindMatchingRules(ctx context.Context, tenantID shared.ID, match FindingMatch) ([]*Rule, error)

	// Bulk operations
	ExpireRules(ctx context.Context) (int64, error)

	// Finding suppressions
	RecordSuppression(ctx context.Context, findingID, ruleID shared.ID, appliedBy string) error
	FindSuppressionsByFinding(ctx context.Context, findingID shared.ID) ([]*FindingSuppression, error)
	RemoveSuppression(ctx context.Context, findingID, ruleID shared.ID) error

	// Audit
	RecordAudit(ctx context.Context, ruleID shared.ID, action string, actorID *shared.ID, details map[string]any) error
}

// RuleFilter provides filtering options for rule queries.
type RuleFilter struct {
	Status          *RuleStatus
	SuppressionType *SuppressionType
	ToolName        *string
	AssetID         *shared.ID
	RequestedBy     *shared.ID
	IncludeExpired  bool
	Limit           int
	Offset          int
}

// FindingSuppression represents a suppression applied to a finding.
type FindingSuppression struct {
	ID                shared.ID
	FindingID         shared.ID
	SuppressionRuleID shared.ID
	AppliedAt         string
	AppliedBy         string
}
