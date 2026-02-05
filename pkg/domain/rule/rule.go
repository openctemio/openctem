package rule

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Severity represents the rule severity level.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityUnknown  Severity = "unknown"
)

// IsValid checks if the severity is valid.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo, SeverityUnknown:
		return true
	}
	return false
}

// Rule represents an individual security rule from a source.
type Rule struct {
	ID       shared.ID
	SourceID shared.ID
	TenantID shared.ID
	ToolID   *shared.ID

	// Rule identification (tool-specific)
	RuleID string // e.g., "java.lang.security.audit.sqli"
	Name   string

	// Classification
	Severity    Severity
	Category    string
	Subcategory string
	Tags        []string

	// Metadata
	Description    string
	Recommendation string
	References     []string
	CWEIDs         []string
	OWASPIDs       []string

	// File info within source
	FilePath    string
	ContentHash string

	// Additional metadata
	Metadata map[string]any

	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewRule creates a new rule from sync data.
func NewRule(
	sourceID shared.ID,
	tenantID shared.ID,
	toolID *shared.ID,
	ruleID string,
	name string,
	severity Severity,
) *Rule {
	now := time.Now()
	return &Rule{
		ID:        shared.NewID(),
		SourceID:  sourceID,
		TenantID:  tenantID,
		ToolID:    toolID,
		RuleID:    ruleID,
		Name:      name,
		Severity:  severity,
		Tags:      []string{},
		Metadata:  make(map[string]any),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// Update updates the rule from sync data.
func (r *Rule) Update(
	name string,
	severity Severity,
	category string,
	description string,
	contentHash string,
) {
	r.Name = name
	r.Severity = severity
	r.Category = category
	r.Description = description
	r.ContentHash = contentHash
	r.UpdatedAt = time.Now()
}

// SetClassification sets the rule classification.
func (r *Rule) SetClassification(category, subcategory string, tags []string) {
	r.Category = category
	r.Subcategory = subcategory
	r.Tags = tags
	r.UpdatedAt = time.Now()
}

// SetReferences sets security references.
func (r *Rule) SetReferences(refs, cweIDs, owaspIDs []string) {
	r.References = refs
	r.CWEIDs = cweIDs
	r.OWASPIDs = owaspIDs
	r.UpdatedAt = time.Now()
}
