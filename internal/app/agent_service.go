package app

// Compatibility shim — real impl lives in internal/app/agent/.
// See internal/app/audit_service.go for the pattern rationale.

import "github.com/openctemio/api/internal/app/agent"

type (
	AgentService                      = agent.AgentService
	AgentSelector                     = agent.AgentSelector
	AgentConfigTemplateService        = agent.AgentConfigTemplateService
	AgentAvailabilityResult           = agent.AgentAvailabilityResult
	AgentHeartbeatData                = agent.AgentHeartbeatData
	AgentHeartbeatInput               = agent.AgentHeartbeatInput
	AgentSelectionMode                = agent.AgentSelectionMode
	AgentTemplateData                 = agent.AgentTemplateData
	CreateAgentInput                  = agent.CreateAgentInput
	CreateAgentOutput                 = agent.CreateAgentOutput
	ListAgentsInput                   = agent.ListAgentsInput
	PlatformStatsOutput               = agent.PlatformStatsOutput
	PlatformTierStats                 = agent.PlatformTierStats
	RenderedTemplates                 = agent.RenderedTemplates
	SelectAgentRequest                = agent.SelectAgentRequest
	SelectAgentResult                 = agent.SelectAgentResult
	TenantAvailableCapabilitiesOutput = agent.TenantAvailableCapabilitiesOutput
	UpdateAgentInput                  = agent.UpdateAgentInput
)

var (
	NewAgentService               = agent.NewAgentService
	NewAgentSelector              = agent.NewAgentSelector
	NewAgentConfigTemplateService = agent.NewAgentConfigTemplateService
	ErrNoAgentAvailable           = agent.ErrNoAgentAvailable
)

// Selection-mode constants re-exported for legacy callers.
const (
	SelectTenantOnly = agent.SelectTenantOnly
	SelectAny        = agent.SelectAny
)
