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
