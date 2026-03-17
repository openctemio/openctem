// Package compliance defines the Compliance Framework Mapping domain types.
package compliance

import "fmt"

// ControlStatus represents the assessment status of a control.
type ControlStatus string

const (
	ControlStatusNotAssessed     ControlStatus = "not_assessed"
	ControlStatusImplemented     ControlStatus = "implemented"
	ControlStatusPartial         ControlStatus = "partial"
	ControlStatusNotImplemented  ControlStatus = "not_implemented"
	ControlStatusNotApplicable   ControlStatus = "not_applicable"
)

// ParseControlStatus parses a string to ControlStatus.
func ParseControlStatus(s string) (ControlStatus, error) {
	cs := ControlStatus(s)
	switch cs {
	case ControlStatusNotAssessed, ControlStatusImplemented, ControlStatusPartial,
		ControlStatusNotImplemented, ControlStatusNotApplicable:
		return cs, nil
	default:
		return "", fmt.Errorf("invalid control status: %s", s)
	}
}

// Priority represents the priority of a control assessment.
type Priority string

const (
	PriorityCritical Priority = "critical"
	PriorityHigh     Priority = "high"
	PriorityMedium   Priority = "medium"
	PriorityLow      Priority = "low"
)

// ParsePriority parses a string to Priority.
func ParsePriority(s string) (Priority, error) {
	if s == "" {
		return "", nil
	}
	p := Priority(s)
	switch p {
	case PriorityCritical, PriorityHigh, PriorityMedium, PriorityLow:
		return p, nil
	default:
		return "", fmt.Errorf("invalid priority: %s", s)
	}
}

// FrameworkCategory represents the category of a compliance framework.
type FrameworkCategory string

const (
	FrameworkCategoryRegulatory   FrameworkCategory = "regulatory"
	FrameworkCategoryIndustry     FrameworkCategory = "industry"
	FrameworkCategoryInternal     FrameworkCategory = "internal"
	FrameworkCategoryBestPractice FrameworkCategory = "best_practice"
)

// ImpactType represents the impact type of a finding-to-control mapping.
type ImpactType string

const (
	ImpactDirect        ImpactType = "direct"
	ImpactIndirect      ImpactType = "indirect"
	ImpactInformational ImpactType = "informational"
)

// EvidenceType represents the type of evidence for an assessment.
type EvidenceType string

const (
	EvidenceFinding       EvidenceType = "finding"
	EvidenceDocument      EvidenceType = "document"
	EvidenceConfiguration EvidenceType = "configuration"
	EvidenceAttestation   EvidenceType = "attestation"
)
