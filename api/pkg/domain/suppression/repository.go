package suppression

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Repository defines the interface for suppression rule persistence.
type Repository interface {
	// Rule operations
	Save(ctx context.Context, rule *Rule) error
	// SaveWithAudit persists the rule and records its audit entry atomically
	// (both commit or neither), so rule state and audit trail cannot diverge.
	SaveWithAudit(ctx context.Context, rule *Rule, action string, actorID *shared.ID, details map[string]any) error
	FindByID(ctx context.Context, tenantID, id shared.ID) (*Rule, error)
	// Delete removes the rule and, in the same transaction, lifts every
	// suppression it applied: each finding it hid (still in the disposition
	// the suppression gave it) is re-linked to another active rule of the
	// tenant that matches it, or reopened.
	Delete(ctx context.Context, tenantID, id shared.ID) error

	// Approve persists the approved rule, records its "approved" audit entry
	// (details plus the number of findings changed) and gives every open
	// finding of the tenant the rule matches the rule's disposition, all in
	// one transaction. At most limit findings change. It refuses with
	// ErrRuleNotPending or ErrRuleChangedSinceReview when the stored rule is
	// no longer the pending version the approver reviewed.
	Approve(ctx context.Context, rule *Rule, reviewedUpdatedAt time.Time, actorID shared.ID, details map[string]any, limit int) (ApplyResult, error)
	// CountMatchingOpenFindings counts the tenant's open findings that the
	// rule's criteria match and an approval would change, counting at most
	// limit+1 so the caller can tell the count was capped.
	CountMatchingOpenFindings(ctx context.Context, rule *Rule, limit int) (int, error)
	// SampleMatchingOpenFindings is the preview of one caller: how many of
	// the matching open findings sit on assets the scope admits (at most
	// limit+1) and the first sampleSize of them in id order, read-only. The
	// scope is asked per page of candidates; a nil scope admits nothing.
	SampleMatchingOpenFindings(ctx context.Context, rule *Rule, scope ScopeFilter, limit, sampleSize int) (int, []SampleFinding, error)

	// Query operations
	FindByTenant(ctx context.Context, tenantID shared.ID, filter RuleFilter) ([]*Rule, error)
	FindActiveByTenant(ctx context.Context, tenantID shared.ID) ([]*Rule, error)
	FindPendingByTenant(ctx context.Context, tenantID shared.ID) ([]*Rule, error)

	// Matching
	FindMatchingRules(ctx context.Context, tenantID shared.ID, match FindingMatch) ([]*Rule, error)

	// Bulk operations
	// ExpireRules marks approved rules past expires_at as expired and lifts
	// their suppressions the same way Delete does. Returns the number of rules
	// expired.
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

// ApplyResult is what approving a rule did to existing findings.
type ApplyResult struct {
	// Applied is the number of findings given the rule's disposition.
	Applied int
	// Capped: more findings matched than the per-approval limit; the rest
	// stay open (the CI gate and ingest still honor the rule).
	Capped bool
}

// ScopeFilter returns, for the caller of ctx, a function telling whether an
// asset is inside the caller's data scope (datascope.Enforcer.FilterForCaller).
type ScopeFilter func(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (func(shared.ID) bool, error)

// SampleFinding is one finding of a preview sample: enough to recognize the
// finding, never its evidence or a secret.
type SampleFinding struct {
	ID        shared.ID
	AssetID   shared.ID
	AssetName string
	RuleID    string
	FilePath  string
	Title     string
	Severity  string
	Status    string
}
