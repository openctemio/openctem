// Package suppression provides domain logic for platform-controlled false positive management.
package suppression

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// SuppressionType represents the type of suppression.
type SuppressionType string

const (
	SuppressionTypeFalsePositive SuppressionType = "false_positive"
	SuppressionTypeAcceptedRisk  SuppressionType = "accepted_risk"
	SuppressionTypeWontFix       SuppressionType = "wont_fix"
)

// IsValid checks if the suppression type is valid.
func (t SuppressionType) IsValid() bool {
	switch t {
	case SuppressionTypeFalsePositive, SuppressionTypeAcceptedRisk, SuppressionTypeWontFix:
		return true
	default:
		return false
	}
}

// RuleStatus represents the approval status of a suppression rule.
type RuleStatus string

const (
	RuleStatusPending  RuleStatus = "pending"
	RuleStatusApproved RuleStatus = "approved"
	RuleStatusRejected RuleStatus = "rejected"
	RuleStatusExpired  RuleStatus = "expired"
)

// IsValid checks if the rule status is valid.
func (s RuleStatus) IsValid() bool {
	switch s {
	case RuleStatusPending, RuleStatusApproved, RuleStatusRejected, RuleStatusExpired:
		return true
	default:
		return false
	}
}

// Rule represents a suppression rule for findings.
type Rule struct {
	id       shared.ID
	tenantID shared.ID

	// Matching criteria
	ruleID      string     // Tool rule ID pattern (e.g., "semgrep.sql-injection")
	toolName    string     // Tool name (e.g., "semgrep", "gitleaks")
	pathPattern string     // File path pattern (glob: "tests/**")
	assetID     *shared.ID // Optional: limit to specific asset

	// Details
	name            string
	description     string
	suppressionType SuppressionType

	// Approval workflow
	status          RuleStatus
	requestedBy     shared.ID
	requestedAt     time.Time
	approvedBy      *shared.ID
	approvedAt      *time.Time
	rejectedBy      *shared.ID
	rejectedAt      *time.Time
	rejectionReason string

	// Expiration
	expiresAt *time.Time

	// Audit
	createdAt time.Time
	updatedAt time.Time
}

// NewRule creates a new suppression rule.
func NewRule(
	tenantID shared.ID,
	name string,
	suppressionType SuppressionType,
	requestedBy shared.ID,
) (*Rule, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant id is required", shared.ErrValidation)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if !suppressionType.IsValid() {
		return nil, fmt.Errorf("%w: invalid suppression type", shared.ErrValidation)
	}
	if requestedBy.IsZero() {
		return nil, fmt.Errorf("%w: requested_by is required", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &Rule{
		id:              shared.NewID(),
		tenantID:        tenantID,
		name:            name,
		suppressionType: suppressionType,
		status:          RuleStatusPending,
		requestedBy:     requestedBy,
		requestedAt:     now,
		createdAt:       now,
		updatedAt:       now,
	}, nil
}

// RuleData contains all data needed to reconstitute a Rule from persistence.
type RuleData struct {
	ID              shared.ID
	TenantID        shared.ID
	RuleID          string
	ToolName        string
	PathPattern     string
	AssetID         *shared.ID
	Name            string
	Description     string
	SuppressionType SuppressionType
	Status          RuleStatus
	RequestedBy     shared.ID
	RequestedAt     time.Time
	ApprovedBy      *shared.ID
	ApprovedAt      *time.Time
	RejectedBy      *shared.ID
	RejectedAt      *time.Time
	RejectionReason string
	ExpiresAt       *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ReconstituteRule recreates a Rule from persistence.
func ReconstituteRule(data RuleData) *Rule {
	return &Rule{
		id:              data.ID,
		tenantID:        data.TenantID,
		ruleID:          data.RuleID,
		toolName:        data.ToolName,
		pathPattern:     data.PathPattern,
		assetID:         data.AssetID,
		name:            data.Name,
		description:     data.Description,
		suppressionType: data.SuppressionType,
		status:          data.Status,
		requestedBy:     data.RequestedBy,
		requestedAt:     data.RequestedAt,
		approvedBy:      data.ApprovedBy,
		approvedAt:      data.ApprovedAt,
		rejectedBy:      data.RejectedBy,
		rejectedAt:      data.RejectedAt,
		rejectionReason: data.RejectionReason,
		expiresAt:       data.ExpiresAt,
		createdAt:       data.CreatedAt,
		updatedAt:       data.UpdatedAt,
	}
}

// Getters

func (r *Rule) ID() shared.ID                    { return r.id }
func (r *Rule) TenantID() shared.ID              { return r.tenantID }
func (r *Rule) RuleID() string                   { return r.ruleID }
func (r *Rule) ToolName() string                 { return r.toolName }
func (r *Rule) PathPattern() string              { return r.pathPattern }
func (r *Rule) AssetID() *shared.ID              { return r.assetID }
func (r *Rule) Name() string                     { return r.name }
func (r *Rule) Description() string              { return r.description }
func (r *Rule) SuppressionType() SuppressionType { return r.suppressionType }
func (r *Rule) Status() RuleStatus               { return r.status }
func (r *Rule) RequestedBy() shared.ID           { return r.requestedBy }
func (r *Rule) RequestedAt() time.Time           { return r.requestedAt }
func (r *Rule) ApprovedBy() *shared.ID           { return r.approvedBy }
func (r *Rule) ApprovedAt() *time.Time           { return r.approvedAt }
func (r *Rule) RejectedBy() *shared.ID           { return r.rejectedBy }
func (r *Rule) RejectedAt() *time.Time           { return r.rejectedAt }
func (r *Rule) RejectionReason() string          { return r.rejectionReason }
func (r *Rule) ExpiresAt() *time.Time            { return r.expiresAt }
func (r *Rule) CreatedAt() time.Time             { return r.createdAt }
func (r *Rule) UpdatedAt() time.Time             { return r.updatedAt }

// Setters for criteria

// SetName sets the rule name.
func (r *Rule) SetName(name string) {
	r.name = name
	r.updatedAt = time.Now().UTC()
}

// SetRuleIDPattern sets the rule ID pattern.
func (r *Rule) SetRuleIDPattern(pattern string) {
	r.ruleID = pattern
	r.updatedAt = time.Now().UTC()
}

// SetToolName sets the tool name filter.
func (r *Rule) SetToolName(toolName string) {
	r.toolName = toolName
	r.updatedAt = time.Now().UTC()
}

// SetPathPattern sets the file path pattern.
func (r *Rule) SetPathPattern(pattern string) {
	r.pathPattern = pattern
	r.updatedAt = time.Now().UTC()
}

// SetAssetID sets the asset ID filter.
func (r *Rule) SetAssetID(assetID *shared.ID) {
	r.assetID = assetID
	r.updatedAt = time.Now().UTC()
}

// SetDescription sets the description.
func (r *Rule) SetDescription(description string) {
	r.description = description
	r.updatedAt = time.Now().UTC()
}

// SetExpiresAt sets the expiration date.
func (r *Rule) SetExpiresAt(expiresAt *time.Time) {
	r.expiresAt = expiresAt
	r.updatedAt = time.Now().UTC()
}

// Workflow methods

// Approve approves the suppression rule.
func (r *Rule) Approve(approvedBy shared.ID) error {
	if r.status != RuleStatusPending {
		return fmt.Errorf("%w: can only approve pending rules", shared.ErrConflict)
	}
	if approvedBy.IsZero() {
		return fmt.Errorf("%w: approved_by is required", shared.ErrValidation)
	}

	now := time.Now().UTC()
	r.status = RuleStatusApproved
	r.approvedBy = &approvedBy
	r.approvedAt = &now
	r.updatedAt = now
	return nil
}

// Reject rejects the suppression rule.
func (r *Rule) Reject(rejectedBy shared.ID, reason string) error {
	if r.status != RuleStatusPending {
		return fmt.Errorf("%w: can only reject pending rules", shared.ErrConflict)
	}
	if rejectedBy.IsZero() {
		return fmt.Errorf("%w: rejected_by is required", shared.ErrValidation)
	}

	now := time.Now().UTC()
	r.status = RuleStatusRejected
	r.rejectedBy = &rejectedBy
	r.rejectedAt = &now
	r.rejectionReason = reason
	r.updatedAt = now
	return nil
}

// Expire marks the rule as expired.
func (r *Rule) Expire() {
	r.status = RuleStatusExpired
	r.updatedAt = time.Now().UTC()
}

// IsActive checks if the rule is currently active.
func (r *Rule) IsActive() bool {
	if r.status != RuleStatusApproved {
		return false
	}
	if r.expiresAt != nil && r.expiresAt.Before(time.Now().UTC()) {
		return false
	}
	return true
}

// IsExpired checks if the rule has expired.
func (r *Rule) IsExpired() bool {
	return r.expiresAt != nil && r.expiresAt.Before(time.Now().UTC())
}

// HasCriteria checks if the rule has at least one matching criterion.
func (r *Rule) HasCriteria() bool {
	return r.ruleID != "" || r.pathPattern != "" || r.assetID != nil
}

// Validate validates the rule has proper criteria.
func (r *Rule) Validate() error {
	if !r.HasCriteria() {
		return fmt.Errorf("%w: at least one matching criterion is required (rule_id, path_pattern, or asset_id)", shared.ErrValidation)
	}
	return nil
}

// MatchesFinding checks if the rule matches a finding.
type FindingMatch struct {
	ToolName string
	RuleID   string
	FilePath string
	AssetID  shared.ID
}

// Matches checks if this suppression rule matches the given finding.
func (r *Rule) Matches(f FindingMatch) bool {
	if !r.IsActive() {
		return false
	}

	// Check tool name
	if r.toolName != "" && !strings.EqualFold(r.toolName, f.ToolName) {
		return false
	}

	// Check rule ID (supports wildcard suffix)
	if r.ruleID != "" {
		if strings.HasSuffix(r.ruleID, "*") {
			prefix := strings.TrimSuffix(r.ruleID, "*")
			if !strings.HasPrefix(f.RuleID, prefix) {
				return false
			}
		} else if r.ruleID != f.RuleID {
			return false
		}
	}

	// Check asset ID
	if r.assetID != nil && *r.assetID != f.AssetID {
		return false
	}

	// Check path pattern (glob matching)
	if r.pathPattern != "" && f.FilePath != "" {
		matched, err := filepath.Match(r.pathPattern, f.FilePath)
		if err != nil || !matched {
			// Try with ** pattern support
			if !matchGlob(r.pathPattern, f.FilePath) {
				return false
			}
		}
	}

	return true
}

// matchGlob provides extended glob matching with ** support.
func matchGlob(pattern, path string) bool {
	// Handle ** patterns
	if strings.Contains(pattern, "**") {
		parts := strings.Split(pattern, "**")
		if len(parts) == 2 {
			prefix := parts[0]
			suffix := parts[1]

			// Check prefix
			if prefix != "" && !strings.HasPrefix(path, strings.TrimSuffix(prefix, "/")) {
				return false
			}

			// Check suffix
			if suffix != "" {
				suffix = strings.TrimPrefix(suffix, "/")
				matched, _ := filepath.Match(suffix, filepath.Base(path))
				if !matched && !strings.HasSuffix(path, suffix) {
					return false
				}
			}

			return true
		}
	}

	// Fallback to standard glob
	matched, _ := filepath.Match(pattern, path)
	return matched
}
