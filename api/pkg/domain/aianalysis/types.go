// Package aianalysis is the governance model for AI results: every result is
// a typed suggestion with provenance, the platform computes whether it adds
// information, raises risk or lowers risk, and the organization's mode per use
// case decides what happens to it. Design: docs/architecture/ai-analysis.md.
package aianalysis

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// UseCase is one AI use case an organization turns on or off.
type UseCase string

const (
	UseCaseTriage      UseCase = "triage"
	UseCaseRemediation UseCase = "remediation"
	UseCaseSummary     UseCase = "summary"
)

// UseCases lists the use cases in display order.
func UseCases() []UseCase { return []UseCase{UseCaseTriage, UseCaseRemediation, UseCaseSummary} }

// ParseUseCase validates a use case.
func ParseUseCase(s string) (UseCase, error) {
	for _, u := range UseCases() {
		if string(u) == s {
			return u, nil
		}
	}
	return "", fmt.Errorf("%w: unknown AI use case", shared.ErrValidation)
}

// Mode is what happens to a use case's suggestions.
type Mode string

const (
	// ModeOff: the use case never runs.
	ModeOff Mode = "off"
	// ModeSuggest: suggestions wait for a person.
	ModeSuggest Mode = "suggest"
	// ModeAutoApply: additive and risk-raising suggestions are applied at
	// once (undo available); risk-lowering ones still become approval
	// requests.
	ModeAutoApply Mode = "auto_apply"
)

// ParseMode validates a mode.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeOff, ModeSuggest, ModeAutoApply:
		return Mode(s), nil
	}
	return "", fmt.Errorf("%w: unknown AI mode", shared.ErrValidation)
}

// Executor is where a run executes.
type Executor string

const (
	// ExecutorBuiltin: a single model call in the API process.
	ExecutorBuiltin Executor = "builtin"
	// ExecutorPlatformWorker: an analyst sensor the platform operator runs.
	ExecutorPlatformWorker Executor = "platform_worker"
	// ExecutorTenantWorker: an analyst sensor the organization runs.
	ExecutorTenantWorker Executor = "tenant_worker"
)

// ParseExecutor validates an executor.
func ParseExecutor(s string) (Executor, error) {
	switch Executor(s) {
	case ExecutorBuiltin, ExecutorPlatformWorker, ExecutorTenantWorker:
		return Executor(s), nil
	}
	return "", fmt.Errorf("%w: unknown AI executor", shared.ErrValidation)
}

// DataClass is the sensitivity of the data a run may send to a model,
// lowest first.
type DataClass string

const (
	DataClassPublic     DataClass = "public"
	DataClassInternal   DataClass = "internal"
	DataClassRestricted DataClass = "restricted"
	DataClassTenantOnly DataClass = "tenant_only"
)

// Rank orders data classes (public lowest); 0 for an unknown class.
func (c DataClass) Rank() int {
	switch c {
	case DataClassPublic:
		return 1
	case DataClassInternal:
		return 2
	case DataClassRestricted:
		return 3
	case DataClassTenantOnly:
		return 4
	}
	return 0
}

// ParseDataClass validates a data class.
func ParseDataClass(s string) (DataClass, error) {
	if DataClass(s).Rank() == 0 {
		return "", fmt.Errorf("%w: unknown AI data class", shared.ErrValidation)
	}
	return DataClass(s), nil
}

// Trigger starts a run.
type Trigger string

const (
	TriggerOnDemand Trigger = "on_demand"
	TriggerOnIngest Trigger = "on_ingest"
	TriggerWorkflow Trigger = "workflow"
	TriggerSchedule Trigger = "schedule"
)

// ParseTrigger validates a trigger.
func ParseTrigger(s string) (Trigger, error) {
	switch Trigger(s) {
	case TriggerOnDemand, TriggerOnIngest, TriggerWorkflow, TriggerSchedule:
		return Trigger(s), nil
	}
	return "", fmt.Errorf("%w: unknown AI trigger", shared.ErrValidation)
}

// SubjectType is what a run is about.
type SubjectType string

const (
	SubjectFinding SubjectType = "finding"
)

// Kind is the type of a suggestion.
type Kind string

const (
	KindVerdict          Kind = "verdict"
	KindSeverity         Kind = "severity"
	KindRemediationSteps Kind = "remediation_steps"
	KindSummary          Kind = "summary"
)

// ParseKind validates a suggestion kind the platform can store and apply.
func ParseKind(s string) (Kind, error) {
	switch Kind(s) {
	case KindVerdict, KindSeverity, KindRemediationSteps, KindSummary:
		return Kind(s), nil
	}
	return "", fmt.Errorf("%w: unknown AI suggestion kind", shared.ErrValidation)
}

// Direction is what applying a suggestion does to risk. Computed by the
// platform from the finding's facts, never taken from the model.
type Direction string

const (
	DirectionAdditive   Direction = "additive"
	DirectionRaisesRisk Direction = "raises_risk"
	DirectionLowersRisk Direction = "lowers_risk"
)

// State is where a suggestion is in its life.
type State string

const (
	StateOpen            State = "open"
	StateApplied         State = "applied"
	StateAutoApplied     State = "auto_applied"
	StatePendingApproval State = "pending_approval"
	StateDismissed       State = "dismissed"
	StateSuperseded      State = "superseded"
	StateUndone          State = "undone"
	StateNeedsReview     State = "needs_review"
	StateShadow          State = "shadow"
)

// IsApplied reports a state whose change is in effect (undo possible).
func (s State) IsApplied() bool { return s == StateApplied || s == StateAutoApplied }

// IsActionable reports a state a person may still apply or dismiss.
func (s State) IsActionable() bool { return s == StateOpen || s == StateNeedsReview }

// RunStatus is the status of a run.
type RunStatus string

const (
	RunPending    RunStatus = "pending"
	RunRunning    RunStatus = "running"
	RunCompleted  RunStatus = "completed"
	RunIncomplete RunStatus = "incomplete"
	RunFailed     RunStatus = "failed"
	RunRefused    RunStatus = "refused"
)

// ApprovalKind names the approval store a pending suggestion waits in.
type ApprovalKind string

const (
	// ApprovalKindStatus: a finding status request (false positive).
	ApprovalKindStatus ApprovalKind = "status"
	// ApprovalKindSeverity: a severity change request.
	ApprovalKindSeverity ApprovalKind = "severity"
)

// Review reasons recorded on a suggestion that must not be applied
// automatically.
const (
	ReviewUnresolvedEvidence = "unresolved_evidence"
	ReviewNoEvidence         = "no_evidence"
	ReviewInjectionSuspected = "injection_suspected"
	ReviewUnknownPlaceholder = "unknown_placeholder"
	ReviewValidatorCoerced   = "validator_coerced"
)
