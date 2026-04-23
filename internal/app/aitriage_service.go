package app

// Compatibility shim — real impl lives in internal/app/aitriage/.

import "github.com/openctemio/api/internal/app/aitriage"

type (
	AITriageService                  = aitriage.AITriageService
	AITriageJobEnqueuer              = aitriage.AITriageJobEnqueuer
	WorkflowEventDispatcherInterface = aitriage.WorkflowEventDispatcherInterface
	TriageBroadcaster                = aitriage.TriageBroadcaster
	TriageRequest                    = aitriage.TriageRequest
	TriageResponse                   = aitriage.TriageResponse
	TriageResultResponse             = aitriage.TriageResultResponse
	BulkTriageRequest                = aitriage.BulkTriageRequest
	BulkTriageResponse               = aitriage.BulkTriageResponse
	BulkTriageJob                    = aitriage.BulkTriageJob
	RecoverStuckJobsInput            = aitriage.RecoverStuckJobsInput
	RecoverStuckJobsOutput           = aitriage.RecoverStuckJobsOutput
	AIConfigInfo                     = aitriage.AIConfigInfo
	TriageOutputValidator            = aitriage.TriageOutputValidator
	PromptSanitizer                  = aitriage.PromptSanitizer
	TokenLimitError                  = aitriage.TokenLimitError

	// RFC-008 per-tenant LLM token budget.
	AITriageBudgetService       = aitriage.BudgetService
	AITriageBudgetServiceConfig = aitriage.BudgetServiceConfig
	AITriageBudgetRepository    = aitriage.BudgetRepository
	AITriageBudgetRow           = aitriage.BudgetRow
	AITriageBudgetStatus        = aitriage.BudgetStatus
)

var (
	NewAITriageService        = aitriage.NewAITriageService
	NewTriageOutputValidator  = aitriage.NewTriageOutputValidator
	NewPromptSanitizer        = aitriage.NewPromptSanitizer
	CheckTokenLimit           = aitriage.CheckTokenLimit
	NewAITriageBudgetService  = aitriage.NewBudgetService
	ErrAITriageBudgetExceeded = aitriage.ErrBudgetExceeded
	ErrAITriageBudgetUnavail  = aitriage.ErrBudgetUnavailable
)

const TypeAITriage = aitriage.TypeAITriage
