package aianalysis

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	aitriagedom "github.com/openctemio/openctem/api/pkg/domain/aitriage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Legacy AI triage (ai_triage_results) keeps running until its contract step;
// every completed legacy result is also written as a run with suggestions, so
// the governance view, undo and the quality signal cover it. The legacy prompt
// asks for no evidence, so its suggestions are stored needs_review: they are
// never applied automatically, a person may apply them.

// legacyFields are the finding fields the legacy prompt sends.
var legacyFields = []string{"finding.title", "finding.description", "finding.severity", "finding.cvss", "finding.source",
	"finding.tool", "finding.file", "finding.snippet", "finding.cve", "finding.cwe", "finding.owasp",
	"finding.internet_accessible", "finding.data_exposure", "finding.compliance"}

// RecordTriageRun writes a completed legacy triage result as a run (same id)
// and its suggestions. A second call for the same result does nothing.
func (s *Service) RecordTriageRun(ctx context.Context, result *aitriagedom.TriageResult, a *aitriagedom.TriageAnalysis, promptDigest string) error {
	if result == nil || a == nil {
		return nil
	}
	if _, err := s.repo.GetRun(ctx, result.TenantID(), result.ID()); err == nil {
		return nil
	} else if !errors.Is(err, shared.ErrNotFound) {
		return err
	}
	trigger := aidom.TriggerOnDemand
	if result.TriageType() == aitriagedom.TriageTypeAuto {
		trigger = aidom.TriggerOnIngest
	}
	completed := result.CompletedAt()
	if completed == nil {
		now := s.now()
		completed = &now
	}
	run := &aidom.Run{
		ID: result.ID(), TenantID: result.TenantID(), UseCase: aidom.UseCaseTriage, Kind: "triage.legacy",
		SubjectType: aidom.SubjectFinding, SubjectID: result.FindingID(), Executor: aidom.ExecutorBuiltin,
		Status: aidom.RunCompleted, DataClass: aidom.DataClassInternal, FieldsSent: legacyFields,
		PromptTemplateID: "triage.legacy", PromptTemplateDigest: promptDigest, OutputSchema: "openctem.ai.triage/legacy",
		Provider: a.Provider, Model: a.Model, TokensIn: a.PromptTokens, TokensOut: a.CompletionTokens,
		RequestedBy: result.RequestedBy(), Trigger: trigger, StartedAt: result.StartedAt(), CompletedAt: completed,
	}
	if run.StartedAt != nil {
		d := int(completed.Sub(*run.StartedAt) / time.Millisecond)
		run.DurationMS = &d
	}
	if err := s.repo.CreateRun(ctx, run); err != nil {
		return err
	}
	var reasons []string
	if len(a.ValidationWarnings) > 0 {
		reasons = append(reasons, aidom.ReviewValidatorCoerced)
	}
	_, err := s.Record(ctx, RecordInput{Run: run, Proposals: legacyProposals(a), RunReviewReasons: reasons,
		SchemaVersion: "openctem.ai.triage/legacy"})
	return err
}

func legacyProposals(a *aitriagedom.TriageAnalysis) []Proposal {
	var out []Proposal
	add := func(kind string, payload any, conf *float64) {
		b, err := json.Marshal(payload)
		if err == nil {
			out = append(out, Proposal{Kind: kind, Payload: b, Confidence: conf})
		}
	}
	fp := a.FalsePositiveLikelihood
	switch {
	case fp >= 0.9:
		c := fp
		add("verdict", aidom.VerdictPayload{Verdict: aidom.VerdictLikelyFalsePositive, Reason: clip(a.FalsePositiveReason, aidom.MaxReasonRunes)}, &c)
	case fp < 0.5:
		c := 1 - fp
		add("verdict", aidom.VerdictPayload{Verdict: aidom.VerdictTruePositive, Reason: clip(a.SeverityJustification, aidom.MaxReasonRunes)}, &c)
	default:
		c := 0.5
		add("verdict", aidom.VerdictPayload{Verdict: aidom.VerdictNeedsInfo, Reason: clip(a.FalsePositiveReason, aidom.MaxReasonRunes)}, &c)
	}
	if a.SeverityAssessment != "" {
		add("severity", aidom.SeverityPayload{Severity: a.SeverityAssessment, Reason: clip(a.SeverityJustification, aidom.MaxReasonRunes)}, nil)
	}
	if len(a.RemediationSteps) > 0 {
		steps := make([]aidom.RemediationStep, 0, len(a.RemediationSteps))
		for i, st := range a.RemediationSteps {
			if i >= aidom.MaxSteps {
				break
			}
			steps = append(steps, aidom.RemediationStep{Step: i + 1, Description: clip(st.Description, aidom.MaxStepRunes), Effort: st.Effort})
		}
		add("remediation_steps", aidom.RemediationPayload{Steps: steps}, nil)
	}
	if a.Summary != "" {
		add("summary", aidom.SummaryPayload{Text: clip(a.Summary, aidom.MaxSummaryRunes)}, nil)
	}
	return out
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
