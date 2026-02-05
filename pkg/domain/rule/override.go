package rule

import (
	"path/filepath"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Override represents a tenant-specific rule enable/disable configuration.
// Overrides allow tenants to:
// - Disable noisy/false-positive rules
// - Enable rules that are disabled by default
// - Override severity for specific rules
type Override struct {
	ID       shared.ID
	TenantID shared.ID
	ToolID   *shared.ID

	// What to override
	RulePattern string // Glob pattern (e.g., "java.lang.*") or exact rule_id
	IsPattern   bool   // true = glob pattern, false = exact match

	// Override settings
	Enabled          bool     // Force enable or disable
	SeverityOverride Severity // Override severity (empty = no override)

	// Optional scope
	AssetGroupID  *shared.ID
	ScanProfileID *shared.ID

	// Audit
	Reason    string
	CreatedBy *shared.ID

	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt *time.Time // Optional expiration
}

// NewOverride creates a new rule override.
func NewOverride(
	tenantID shared.ID,
	toolID *shared.ID,
	rulePattern string,
	isPattern bool,
	enabled bool,
	reason string,
	createdBy *shared.ID,
) *Override {
	now := time.Now()
	return &Override{
		ID:          shared.NewID(),
		TenantID:    tenantID,
		ToolID:      toolID,
		RulePattern: rulePattern,
		IsPattern:   isPattern,
		Enabled:     enabled,
		Reason:      reason,
		CreatedBy:   createdBy,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// Matches checks if this override matches a given rule ID.
func (o *Override) Matches(ruleID string) bool {
	if !o.IsPattern {
		return o.RulePattern == ruleID
	}
	// Use filepath.Match for glob pattern matching
	matched, err := filepath.Match(o.RulePattern, ruleID)
	if err != nil {
		return false
	}
	return matched
}

// IsExpired checks if the override has expired.
func (o *Override) IsExpired() bool {
	if o.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*o.ExpiresAt)
}

// SetExpiration sets the expiration time.
func (o *Override) SetExpiration(expiresAt *time.Time) {
	o.ExpiresAt = expiresAt
	o.UpdatedAt = time.Now()
}

// SetSeverityOverride sets the severity override.
func (o *Override) SetSeverityOverride(severity Severity) {
	o.SeverityOverride = severity
	o.UpdatedAt = time.Now()
}

// SetScope sets the scope (asset group and/or scan profile).
func (o *Override) SetScope(assetGroupID, scanProfileID *shared.ID) {
	o.AssetGroupID = assetGroupID
	o.ScanProfileID = scanProfileID
	o.UpdatedAt = time.Now()
}
