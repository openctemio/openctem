package aianalysis

import (
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// RunDeadline bounds a run. A live run past its deadline is failed with
// ErrorTimeout when the next run of the same subject and use case starts, so
// a crashed executor never blocks the subject. Liveness of a run that waits
// on a job is the job's lease (the command system).
const RunDeadline = 30 * time.Minute

// ErrorTimeout is the error code of a run that passed its deadline.
const ErrorTimeout = "timeout"

// Error codes of a worker run the platform settles because its analysis
// job ended without a result (RunRepository.SettleWorkerRuns).
const (
	// ErrorDeadlineExceeded: the run passed its deadline, or its job
	// expired, before a worker returned a result.
	ErrorDeadlineExceeded = "deadline_exceeded"
	// ErrorWorkerError: the job failed without a result.
	ErrorWorkerError = "worker_error"
	// ErrorWorkerUnavailable: the job is gone (deleted) or was never queued.
	ErrorWorkerUnavailable = "worker_unavailable"
	// ErrorJobCanceled: the job was canceled before a worker returned a
	// result.
	ErrorJobCanceled = "job_canceled"
)

// Run is one execution of a use case by an AI agent, with its provenance.
type Run struct {
	ID          shared.ID
	TenantID    shared.ID
	AIAgentID   *shared.ID // nil only for a legacy row or after the AI agent was deleted
	UseCase     UseCase
	Kind        string
	SubjectType SubjectType
	SubjectID   shared.ID
	Executor    Executor
	Status      RunStatus
	DataClass   DataClass
	// SensorID is the AI worker that took the run's analysis job (worker
	// executors only; nil while the job waits for a worker).
	SensorID *shared.ID
	// CommandID is the analysis job the run sent to a worker (worker
	// executors only).
	CommandID *shared.ID
	// ResultDigest is the sha256 of the result bytes a worker returned.
	ResultDigest string
	// InjectionSuspected: the bundle carried text that matched an
	// injection pattern, so the run's output may only become comments. It is
	// stored so a worker's result, applied in a later request, is held to
	// the same rule.
	InjectionSuspected bool
	// SubjectRowVersion is the finding's row version when the run built its
	// bundle (nil: unknown). A worker's result is applied against it, so a
	// change someone made in between turns the AI agent's changes into
	// comments.
	SubjectRowVersion *int64
	// ModelFamily is the model family a worker reported (lower case).
	ModelFamily string
	// Outcome is what the run did to its subject ("" while live).
	Outcome RunOutcome
	// ActionLog is each suggestion and what became of it (codes only).
	ActionLog []ActionLogEntry

	FieldsSent           []string
	FieldsWithheld       []string
	BundleDigest         string
	PromptTemplateID     string
	PromptTemplateDigest string
	OutputSchema         string
	Provider             string
	Model                string

	Steps        int
	ToolCalls    int
	Actions      int
	TokensIn     int
	TokensOut    int
	CostMicroUSD int64
	DurationMS   *int
	ErrorCode    string

	TriggeredBy *shared.ID
	Trigger     Trigger
	// Accountable is the AI agent's owners when the run started.
	Accountable []OwnerRef
	// LegacyOutput is the stored result of a run made before AI agents.
	LegacyOutput map[string]any

	DeadlineAt  *time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	CreatedAt   time.Time
}

// RunOutcome is what a finished run did to its subject, in one word.
type RunOutcome string

const (
	// OutcomeApplied: the AI agent changed the subject.
	OutcomeApplied RunOutcome = "applied"
	// OutcomeProposed: a suggestion or a request waits for a person.
	OutcomeProposed RunOutcome = "proposed"
	// OutcomeNoChange: the run only added information (a summary, a plan,
	// a verdict that agrees with the current state).
	OutcomeNoChange RunOutcome = "no_change"
	// OutcomeAbstained: nothing usable came back.
	OutcomeAbstained RunOutcome = "abstained"
)

// MaxActionLog bounds a run's action log (also a database constraint).
const MaxActionLog = 32

// ActionLogEntry is one suggestion of a run and what became of it. Codes
// only: the text the AI agent wrote is in its comments.
type ActionLogEntry struct {
	Kind    string `json:"kind"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
}

// Error codes of a worker result the platform refused or that failed
// (docs/architecture/ai-analysis.md, "Applying a worker's result").
const (
	// ErrorJobMismatch: the result names another job than the one the
	// platform sent for the run.
	ErrorJobMismatch = "job_mismatch"
	// ErrorNoResult: the job completed without a result document.
	ErrorNoResult = "no_result"
	// ErrorResultTooLarge: the result is over the document limit.
	ErrorResultTooLarge = "result_too_large"
	// ErrorAIAgentUnavailable: the AI agent can no longer act (paused,
	// disabled, deleted, no permission left, the finding out of its scope).
	ErrorAIAgentUnavailable = "ai_agent_unavailable"
)

// workerErrorCodes are the error codes a worker may report on a refused,
// failed or incomplete result; any other code is recorded as
// ErrorWorkerError. A code starting with "not_assessable_" is kept too.
var workerErrorCodes = map[string]bool{
	"unsupported_kind": true, "policy_restricted": true, "bundle_too_large": true, "model_refused": true,
	"budget_exhausted": true, "invalid_output": true, "provider_error": true, "deadline_exceeded": true,
}

// WorkerErrorCode is the code recorded for a worker's error code: the
// allow-listed code, a not_assessable_<reason> code, or ErrorWorkerError.
func WorkerErrorCode(code string) string {
	if workerErrorCodes[code] {
		return code
	}
	const prefix = "not_assessable_"
	if len(code) > len(prefix) && len(code) <= 64 && code[:len(prefix)] == prefix {
		for _, r := range code[len(prefix):] {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
				return ErrorWorkerError
			}
		}
		return code
	}
	return ErrorWorkerError
}
