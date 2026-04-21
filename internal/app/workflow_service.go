package app

// Compatibility shim — real impl lives in internal/app/workflow/.

import "github.com/openctemio/api/internal/app/workflow"

type (
	WorkflowService              = workflow.WorkflowService
	WorkflowServiceOption        = workflow.WorkflowServiceOption
	WorkflowExecutor             = workflow.WorkflowExecutor
	WorkflowExecutorConfig       = workflow.WorkflowExecutorConfig
	WorkflowExecutorOption       = workflow.WorkflowExecutorOption
	WorkflowEventDispatcher      = workflow.WorkflowEventDispatcher
	ActionHandler                = workflow.ActionHandler
	ActionInput                  = workflow.ActionInput
	AITriageActionHandler        = workflow.AITriageActionHandler
	AITriageEvent                = workflow.AITriageEvent
	ConditionEvaluator           = workflow.ConditionEvaluator
	DefaultConditionEvaluator    = workflow.DefaultConditionEvaluator
	DefaultNotificationHandler   = workflow.DefaultNotificationHandler
	ExecutionContext             = workflow.ExecutionContext
	FindingActionHandler         = workflow.FindingActionHandler
	FindingEvent                 = workflow.FindingEvent
	HTTPRequestHandler           = workflow.HTTPRequestHandler
	NotificationHandler          = workflow.NotificationHandler
	NotificationInput            = workflow.NotificationInput
	PipelineTriggerHandler       = workflow.PipelineTriggerHandler
	ScriptRunnerHandler          = workflow.ScriptRunnerHandler
	TicketActionHandler          = workflow.TicketActionHandler

	AddEdgeInput                 = workflow.AddEdgeInput
	AddNodeInput                 = workflow.AddNodeInput
	CreateEdgeInput              = workflow.CreateEdgeInput
	CreateNodeInput              = workflow.CreateNodeInput
	CreateWorkflowInput          = workflow.CreateWorkflowInput
	ListWorkflowRunsInput        = workflow.ListWorkflowRunsInput
	ListWorkflowsInput           = workflow.ListWorkflowsInput
	TriggerWorkflowInput         = workflow.TriggerWorkflowInput
	UpdateNodeInput              = workflow.UpdateNodeInput
	UpdateWorkflowGraphInput     = workflow.UpdateWorkflowGraphInput
	UpdateWorkflowInput          = workflow.UpdateWorkflowInput
)

var (
	NewWorkflowService              = workflow.NewWorkflowService
	NewWorkflowExecutor             = workflow.NewWorkflowExecutor
	NewWorkflowEventDispatcher      = workflow.NewWorkflowEventDispatcher
	NewAITriageActionHandler        = workflow.NewAITriageActionHandler
	NewFindingActionHandler         = workflow.NewFindingActionHandler
	NewHTTPRequestHandler           = workflow.NewHTTPRequestHandler
	NewPipelineTriggerHandler       = workflow.NewPipelineTriggerHandler
	NewScriptRunnerHandler          = workflow.NewScriptRunnerHandler
	NewTicketActionHandler          = workflow.NewTicketActionHandler
	RegisterAllActionHandlers       = workflow.RegisterAllActionHandlers
	RegisterAllActionHandlersWithAI = workflow.RegisterAllActionHandlersWithAI
	ValidateSourceFilter            = workflow.ValidateSourceFilter

	WithExecutorAuditService        = workflow.WithExecutorAuditService
	WithExecutorDB                  = workflow.WithExecutorDB
	WithExecutorIntegrationService  = workflow.WithExecutorIntegrationService
	WithExecutorOutboxService       = workflow.WithExecutorOutboxService
	WithWorkflowAuditService        = workflow.WithWorkflowAuditService
	WithWorkflowExecutor            = workflow.WithWorkflowExecutor

	DefaultWorkflowExecutorConfig = workflow.DefaultWorkflowExecutorConfig
)
