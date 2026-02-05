// Package aitriage provides domain entities for AI-powered vulnerability triage.
package aitriage

import (
	"encoding/json"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// Triage Status
// =============================================================================

// TriageStatus represents the status of a triage job.
type TriageStatus string

const (
	TriageStatusPending    TriageStatus = "pending"
	TriageStatusProcessing TriageStatus = "processing"
	TriageStatusCompleted  TriageStatus = "completed"
	TriageStatusFailed     TriageStatus = "failed"
)

// IsValid checks if the status is valid.
func (s TriageStatus) IsValid() bool {
	switch s {
	case TriageStatusPending, TriageStatusProcessing, TriageStatusCompleted, TriageStatusFailed:
		return true
	}
	return false
}

// IsTerminal returns true if the status is final (completed or failed).
func (s TriageStatus) IsTerminal() bool {
	return s == TriageStatusCompleted || s == TriageStatusFailed
}

// =============================================================================
// Triage Type
// =============================================================================

// TriageType represents how the triage was initiated.
type TriageType string

const (
	TriageTypeAuto   TriageType = "auto"   // Triggered automatically on finding creation
	TriageTypeManual TriageType = "manual" // Triggered by user request
	TriageTypeBulk   TriageType = "bulk"   // Part of a bulk triage operation
)

// IsValid checks if the type is valid.
func (t TriageType) IsValid() bool {
	switch t {
	case TriageTypeAuto, TriageTypeManual, TriageTypeBulk:
		return true
	}
	return false
}

// =============================================================================
// Exploitability
// =============================================================================

// Exploitability represents how easily a vulnerability can be exploited.
type Exploitability string

const (
	ExploitabilityHigh        Exploitability = "high"        // Actively exploited or easy to exploit
	ExploitabilityMedium      Exploitability = "medium"      // Requires some skill/conditions
	ExploitabilityLow         Exploitability = "low"         // Difficult to exploit
	ExploitabilityTheoretical Exploitability = "theoretical" // Not practically exploitable
)

// IsValid checks if the exploitability is valid.
func (e Exploitability) IsValid() bool {
	switch e {
	case ExploitabilityHigh, ExploitabilityMedium, ExploitabilityLow, ExploitabilityTheoretical:
		return true
	}
	return false
}

// =============================================================================
// Remediation Step
// =============================================================================

// RemediationStep represents a step in the remediation process.
type RemediationStep struct {
	Step        int    `json:"step"`
	Description string `json:"description"`
	Effort      string `json:"effort"` // "low", "medium", "high"
}

// =============================================================================
// Triage Result Entity
// =============================================================================

// TriageResult represents the result of an AI triage analysis.
type TriageResult struct {
	id        shared.ID
	tenantID  shared.ID
	findingID shared.ID

	// Request info
	triageType  TriageType
	requestedBy *shared.ID // User who requested (nil for auto)
	requestedAt time.Time

	// Processing info
	status       TriageStatus
	startedAt    *time.Time
	completedAt  *time.Time
	errorMessage string

	// AI Provider info
	llmProvider      string // "claude", "openai"
	llmModel         string // "claude-3-5-sonnet", "gpt-4-turbo"
	promptTokens     int
	completionTokens int

	// Analysis results
	severityAssessment    string  // AI recommended severity
	severityJustification string  // Why the severity was chosen
	riskScore             float64 // 0-100
	exploitability        Exploitability
	exploitabilityDetails string
	businessImpact        string

	// Recommendations
	priorityRank            int               // 1-100 (1 = most urgent)
	remediationSteps        []RemediationStep // Steps to fix
	falsePositiveLikelihood float64           // 0-1
	falsePositiveReason     string
	relatedCVEs             []string
	relatedCWEs             []string

	// Full response
	rawResponse     map[string]any // Raw JSON response from LLM
	analysisSummary string         // Human-readable summary

	// Metadata
	metadata  map[string]any
	createdAt time.Time
	updatedAt time.Time
}

// =============================================================================
// Constructor
// =============================================================================

// NewTriageResult creates a new pending triage result.
func NewTriageResult(
	tenantID shared.ID,
	findingID shared.ID,
	triageType TriageType,
	requestedBy *shared.ID,
) (*TriageResult, error) {
	if !triageType.IsValid() {
		return nil, shared.NewDomainError("VALIDATION", "invalid triage type", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &TriageResult{
		id:          shared.NewID(),
		tenantID:    tenantID,
		findingID:   findingID,
		triageType:  triageType,
		requestedBy: requestedBy,
		requestedAt: now,
		status:      TriageStatusPending,
		createdAt:   now,
		updatedAt:   now,
	}, nil
}

// =============================================================================
// Reconstitute
// =============================================================================

// Reconstitute creates a TriageResult from database values.
func Reconstitute(
	id, tenantID, findingID shared.ID,
	triageType TriageType,
	requestedBy *shared.ID,
	requestedAt time.Time,
	status TriageStatus,
	startedAt, completedAt *time.Time,
	errorMessage string,
	llmProvider, llmModel string,
	promptTokens, completionTokens int,
	severityAssessment, severityJustification string,
	riskScore float64,
	exploitability Exploitability,
	exploitabilityDetails, businessImpact string,
	priorityRank int,
	remediationSteps []RemediationStep,
	falsePositiveLikelihood float64,
	falsePositiveReason string,
	relatedCVEs, relatedCWEs []string,
	rawResponse map[string]any,
	analysisSummary string,
	metadata map[string]any,
	createdAt, updatedAt time.Time,
) *TriageResult {
	return &TriageResult{
		id:                      id,
		tenantID:                tenantID,
		findingID:               findingID,
		triageType:              triageType,
		requestedBy:             requestedBy,
		requestedAt:             requestedAt,
		status:                  status,
		startedAt:               startedAt,
		completedAt:             completedAt,
		errorMessage:            errorMessage,
		llmProvider:             llmProvider,
		llmModel:                llmModel,
		promptTokens:            promptTokens,
		completionTokens:        completionTokens,
		severityAssessment:      severityAssessment,
		severityJustification:   severityJustification,
		riskScore:               riskScore,
		exploitability:          exploitability,
		exploitabilityDetails:   exploitabilityDetails,
		businessImpact:          businessImpact,
		priorityRank:            priorityRank,
		remediationSteps:        remediationSteps,
		falsePositiveLikelihood: falsePositiveLikelihood,
		falsePositiveReason:     falsePositiveReason,
		relatedCVEs:             relatedCVEs,
		relatedCWEs:             relatedCWEs,
		rawResponse:             rawResponse,
		analysisSummary:         analysisSummary,
		metadata:                metadata,
		createdAt:               createdAt,
		updatedAt:               updatedAt,
	}
}

// =============================================================================
// Getters
// =============================================================================

func (r *TriageResult) ID() shared.ID                       { return r.id }
func (r *TriageResult) TenantID() shared.ID                 { return r.tenantID }
func (r *TriageResult) FindingID() shared.ID                { return r.findingID }
func (r *TriageResult) TriageType() TriageType              { return r.triageType }
func (r *TriageResult) RequestedBy() *shared.ID             { return r.requestedBy }
func (r *TriageResult) RequestedAt() time.Time              { return r.requestedAt }
func (r *TriageResult) Status() TriageStatus                { return r.status }
func (r *TriageResult) StartedAt() *time.Time               { return r.startedAt }
func (r *TriageResult) CompletedAt() *time.Time             { return r.completedAt }
func (r *TriageResult) ErrorMessage() string                { return r.errorMessage }
func (r *TriageResult) LLMProvider() string                 { return r.llmProvider }
func (r *TriageResult) LLMModel() string                    { return r.llmModel }
func (r *TriageResult) PromptTokens() int                   { return r.promptTokens }
func (r *TriageResult) CompletionTokens() int               { return r.completionTokens }
func (r *TriageResult) TotalTokens() int                    { return r.promptTokens + r.completionTokens }
func (r *TriageResult) SeverityAssessment() string          { return r.severityAssessment }
func (r *TriageResult) SeverityJustification() string       { return r.severityJustification }
func (r *TriageResult) RiskScore() float64                  { return r.riskScore }
func (r *TriageResult) Exploitability() Exploitability      { return r.exploitability }
func (r *TriageResult) ExploitabilityDetails() string       { return r.exploitabilityDetails }
func (r *TriageResult) BusinessImpact() string              { return r.businessImpact }
func (r *TriageResult) PriorityRank() int                   { return r.priorityRank }
func (r *TriageResult) RemediationSteps() []RemediationStep { return r.remediationSteps }
func (r *TriageResult) FalsePositiveLikelihood() float64    { return r.falsePositiveLikelihood }
func (r *TriageResult) FalsePositiveReason() string         { return r.falsePositiveReason }
func (r *TriageResult) RelatedCVEs() []string               { return r.relatedCVEs }
func (r *TriageResult) RelatedCWEs() []string               { return r.relatedCWEs }
func (r *TriageResult) RawResponse() map[string]any         { return r.rawResponse }
func (r *TriageResult) AnalysisSummary() string             { return r.analysisSummary }
func (r *TriageResult) Metadata() map[string]any            { return r.metadata }
func (r *TriageResult) CreatedAt() time.Time                { return r.createdAt }
func (r *TriageResult) UpdatedAt() time.Time                { return r.updatedAt }

// =============================================================================
// State Mutations
// =============================================================================

// MarkProcessing marks the triage as processing.
func (r *TriageResult) MarkProcessing() error {
	if r.status != TriageStatusPending {
		return shared.NewDomainError("INVALID_STATE", "can only start processing from pending state", shared.ErrConflict)
	}
	now := time.Now().UTC()
	r.status = TriageStatusProcessing
	r.startedAt = &now
	r.updatedAt = now
	return nil
}

// MarkCompleted marks the triage as completed with results.
func (r *TriageResult) MarkCompleted(result TriageAnalysis) error {
	if r.status != TriageStatusProcessing {
		return shared.NewDomainError("INVALID_STATE", "can only complete from processing state", shared.ErrConflict)
	}

	now := time.Now().UTC()
	r.status = TriageStatusCompleted
	r.completedAt = &now
	r.updatedAt = now

	// Set LLM info
	r.llmProvider = result.Provider
	r.llmModel = result.Model
	r.promptTokens = result.PromptTokens
	r.completionTokens = result.CompletionTokens

	// Set analysis results
	r.severityAssessment = result.SeverityAssessment
	r.severityJustification = result.SeverityJustification
	r.riskScore = result.RiskScore
	r.exploitability = result.Exploitability
	r.exploitabilityDetails = result.ExploitabilityDetails
	r.businessImpact = result.BusinessImpact
	r.priorityRank = result.PriorityRank
	r.remediationSteps = result.RemediationSteps
	r.falsePositiveLikelihood = result.FalsePositiveLikelihood
	r.falsePositiveReason = result.FalsePositiveReason
	r.relatedCVEs = result.RelatedCVEs
	r.relatedCWEs = result.RelatedCWEs
	r.rawResponse = result.RawResponse
	r.analysisSummary = result.Summary

	return nil
}

// MarkFailed marks the triage as failed with an error message.
func (r *TriageResult) MarkFailed(errMsg string) error {
	now := time.Now().UTC()
	r.status = TriageStatusFailed
	r.completedAt = &now
	r.errorMessage = errMsg
	r.updatedAt = now
	return nil
}

// =============================================================================
// Analysis Result (Input for MarkCompleted)
// =============================================================================

// TriageAnalysis holds the parsed analysis from the LLM.
type TriageAnalysis struct {
	Provider         string
	Model            string
	PromptTokens     int
	CompletionTokens int

	SeverityAssessment      string
	SeverityJustification   string
	RiskScore               float64
	Exploitability          Exploitability
	ExploitabilityDetails   string
	BusinessImpact          string
	PriorityRank            int
	RemediationSteps        []RemediationStep
	FalsePositiveLikelihood float64
	FalsePositiveReason     string
	RelatedCVEs             []string
	RelatedCWEs             []string
	RawResponse             map[string]any
	Summary                 string
}

// ParseTriageAnalysis parses the LLM response into a TriageAnalysis.
func ParseTriageAnalysis(content string, provider, model string, promptTokens, completionTokens int) (*TriageAnalysis, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return nil, shared.NewDomainError("PARSE_ERROR", "failed to parse AI response as JSON", shared.ErrValidation)
	}

	analysis := &TriageAnalysis{
		Provider:         provider,
		Model:            model,
		PromptTokens:     promptTokens,
		CompletionTokens: completionTokens,
		RawResponse:      raw,
	}

	// Extract fields with type safety
	if v, ok := raw["severity_assessment"].(string); ok {
		analysis.SeverityAssessment = v
	}
	if v, ok := raw["severity_justification"].(string); ok {
		analysis.SeverityJustification = v
	}
	if v, ok := raw["risk_score"].(float64); ok {
		analysis.RiskScore = v
	}
	if v, ok := raw["exploitability"].(string); ok {
		analysis.Exploitability = Exploitability(v)
	}
	if v, ok := raw["exploitability_details"].(string); ok {
		analysis.ExploitabilityDetails = v
	}
	if v, ok := raw["business_impact"].(string); ok {
		analysis.BusinessImpact = v
	}
	if v, ok := raw["priority_rank"].(float64); ok {
		analysis.PriorityRank = int(v)
	}
	if v, ok := raw["false_positive_likelihood"].(float64); ok {
		analysis.FalsePositiveLikelihood = v
	}
	if v, ok := raw["false_positive_reason"].(string); ok {
		analysis.FalsePositiveReason = v
	}
	if v, ok := raw["summary"].(string); ok {
		analysis.Summary = v
	}

	// Parse remediation steps
	if steps, ok := raw["remediation_steps"].([]any); ok {
		for _, s := range steps {
			if stepMap, ok := s.(map[string]any); ok {
				step := RemediationStep{}
				if v, ok := stepMap["step"].(float64); ok {
					step.Step = int(v)
				}
				if v, ok := stepMap["description"].(string); ok {
					step.Description = v
				}
				if v, ok := stepMap["effort"].(string); ok {
					step.Effort = v
				}
				analysis.RemediationSteps = append(analysis.RemediationSteps, step)
			}
		}
	}

	// Parse related CVEs
	if cves, ok := raw["related_cves"].([]any); ok {
		for _, c := range cves {
			if cve, ok := c.(string); ok {
				analysis.RelatedCVEs = append(analysis.RelatedCVEs, cve)
			}
		}
	}

	// Parse related CWEs
	if cwes, ok := raw["related_cwes"].([]any); ok {
		for _, c := range cwes {
			if cwe, ok := c.(string); ok {
				analysis.RelatedCWEs = append(analysis.RelatedCWEs, cwe)
			}
		}
	}

	return analysis, nil
}
