// Package aianalysis is the model of AI analysts: service accounts that take
// part in triage like a person (same commands, permissions, approvals and
// audit), each with accountable owners, plus the ledger of their runs.
// Design: docs/architecture/ai-analysis.md.
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

// Executor is where a run executes.
type Executor string

const (
	// ExecutorBuiltin: a single model call in the API process.
	ExecutorBuiltin Executor = "builtin"
	// ExecutorPlatformWorker: an analyst sensor the platform operator runs.
	ExecutorPlatformWorker Executor = "platform_worker"
	// ExecutorTenantWorker: an analyst sensor the organization runs.
	ExecutorTenantWorker Executor = "tenant_worker"
	// ExecutorExternal: an outside program acting with the analyst's
	// service-account key.
	ExecutorExternal Executor = "external"
)

// ParseExecutor validates an executor.
func ParseExecutor(s string) (Executor, error) {
	switch Executor(s) {
	case ExecutorBuiltin, ExecutorPlatformWorker, ExecutorTenantWorker, ExecutorExternal:
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
	TriggerMention  Trigger = "mention"
)

// ParseTrigger validates a trigger.
func ParseTrigger(s string) (Trigger, error) {
	switch Trigger(s) {
	case TriggerOnDemand, TriggerOnIngest, TriggerWorkflow, TriggerSchedule, TriggerMention:
		return Trigger(s), nil
	}
	return "", fmt.Errorf("%w: unknown AI trigger", shared.ErrValidation)
}

// SubjectType is what a run is about.
type SubjectType string

const (
	SubjectFinding SubjectType = "finding"
)

// Kind is the type of one item of model output (an intended action the
// executor turns into a command of the analyst).
type Kind string

const (
	KindVerdict          Kind = "verdict"
	KindSeverity         Kind = "severity"
	KindRemediationSteps Kind = "remediation_steps"
	KindSummary          Kind = "summary"
)

// ParseKind validates an output item kind.
func ParseKind(s string) (Kind, error) {
	switch Kind(s) {
	case KindVerdict, KindSeverity, KindRemediationSteps, KindSummary:
		return Kind(s), nil
	}
	return "", fmt.Errorf("%w: unknown AI output kind", shared.ErrValidation)
}

// RunStatus is the status of a run.
type RunStatus string

const (
	RunQueued          RunStatus = "queued"
	RunRunning         RunStatus = "running"
	RunWaitingTool     RunStatus = "waiting_tool"
	RunWaitingApproval RunStatus = "waiting_approval"
	RunCompleted       RunStatus = "completed"
	RunFailed          RunStatus = "failed"
	RunCanceled        RunStatus = "canceled"
	RunRefused         RunStatus = "refused"
)

// IsLive reports a status that still holds the subject's in-flight slot.
func (s RunStatus) IsLive() bool {
	switch s {
	case RunQueued, RunRunning, RunWaitingTool, RunWaitingApproval:
		return true
	}
	return false
}

// Review reasons recorded on output the executor did not act on (it is
// written as a comment for a person instead).
const (
	ReviewUnresolvedEvidence = "unresolved_evidence"
	ReviewNoEvidence         = "no_evidence"
	ReviewInjectionSuspected = "injection_suspected"
	ReviewUnknownPlaceholder = "unknown_placeholder"
	ReviewValidatorCoerced   = "validator_coerced"
)
