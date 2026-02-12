package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/llm"
	"github.com/openctemio/api/pkg/domain/aitriage"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// AI Triage licensing errors
var (
	ErrAITriageNotAvailable      = errors.New("AI triage is not available on your current plan")
	ErrBulkTriageNotAvailable    = errors.New("bulk AI triage is not available on your current plan")
	ErrAutoTriageNotAvailable    = errors.New("auto AI triage is not available on your current plan")
	ErrAITriageBYOKNotAvailable  = errors.New("BYOK mode is not available on your current plan")
	ErrAITriageAgentNotAvailable = errors.New("self-hosted agent mode is not available on your current plan")
)

// categorizeError returns a user-friendly error message based on the error type.
// SECURITY: This function maps internal errors to safe external messages.
//
//nolint:cyclop // Switch/case for error categorization is naturally branchy.
func categorizeError(err error) string {
	if err == nil {
		return "Unknown error occurred"
	}

	errStr := err.Error()
	errLower := strings.ToLower(errStr)

	// Rate limiting
	if errors.Is(err, llm.ErrRateLimited) || strings.Contains(errLower, "rate limit") || strings.Contains(errLower, "429") {
		return "AI service is temporarily busy. Please try again in a few minutes."
	}

	// Authentication/Authorization errors
	if strings.Contains(errLower, "unauthorized") || strings.Contains(errLower, "401") ||
		strings.Contains(errLower, "invalid api key") || strings.Contains(errLower, "authentication") {
		return "AI service authentication failed. Please contact your administrator."
	}

	// Quota/Billing errors
	if strings.Contains(errLower, "quota") || strings.Contains(errLower, "billing") ||
		strings.Contains(errLower, "insufficient") || strings.Contains(errLower, "exceeded") {
		return "AI service quota exceeded. Please check your subscription or try again later."
	}

	// Context/timeout errors
	if errors.Is(err, llm.ErrContextCanceled) || strings.Contains(errLower, "context") ||
		strings.Contains(errLower, "timeout") || strings.Contains(errLower, "deadline") {
		return "AI analysis timed out. Please try again with a simpler finding."
	}

	// Model/Content errors
	if strings.Contains(errLower, "content_filter") || strings.Contains(errLower, "safety") ||
		strings.Contains(errLower, "blocked") {
		return "AI analysis was blocked by content filters. Finding may contain sensitive content."
	}

	// Token limit errors
	if errors.Is(err, llm.ErrTokenLimitExceeded) || strings.Contains(errLower, "token") {
		return "Finding is too large for AI analysis. Try a finding with less content."
	}

	// Server errors
	if strings.Contains(errLower, "500") || strings.Contains(errLower, "502") ||
		strings.Contains(errLower, "503") || strings.Contains(errLower, "server error") {
		return "AI service is temporarily unavailable. Please try again later."
	}

	// Invalid response
	if errors.Is(err, llm.ErrInvalidResponse) || strings.Contains(errLower, "parse") ||
		strings.Contains(errLower, "invalid response") {
		return "AI returned an invalid response. Please try again."
	}

	// Configuration errors (admin should fix)
	if errors.Is(err, llm.ErrProviderNotConfigured) || strings.Contains(errLower, "not configured") {
		return "AI service is not properly configured. Please contact your administrator."
	}

	// Default fallback
	return "AI analysis failed. Please try again later."
}

// AITriageJobEnqueuer defines the interface for enqueueing AI triage jobs.
type AITriageJobEnqueuer interface {
	EnqueueAITriage(ctx context.Context, resultID, tenantID, findingID string, delay time.Duration) error
}

// WorkflowEventDispatcherInterface defines the interface for dispatching workflow events.
// This avoids circular dependency with workflow package.
type WorkflowEventDispatcherInterface interface {
	DispatchAITriageCompleted(ctx context.Context, tenantID, findingID, triageID shared.ID, triageData map[string]any)
	DispatchAITriageFailed(ctx context.Context, tenantID, findingID, triageID shared.ID, errorMessage string)
}

// AITriageModuleChecker defines the interface for checking AI Triage module.
// This avoids circular dependency with module package.
type AITriageModuleChecker interface {
	TenantHasModule(ctx context.Context, tenantID, moduleID string) (bool, error)
	GetTenantModuleLimit(ctx context.Context, tenantID, moduleID, metric string) (*GetModuleLimitOutput, error)
}

// TriageBroadcaster broadcasts triage events for real-time WebSocket updates.
type TriageBroadcaster interface {
	// BroadcastTriage sends a triage event to subscribers.
	// channel: the channel to broadcast to (e.g., "triage:{finding_id}")
	// data: the triage event data
	// tenantID: tenant isolation for the broadcast
	BroadcastTriage(channel string, data any, tenantID string)
}

// AITriageService handles AI-powered vulnerability triage operations.
type AITriageService struct {
	triageRepo         aitriage.Repository
	findingRepo        vulnerability.FindingRepository
	tenantRepo         tenant.Repository
	activitySvc        *FindingActivityService
	auditSvc           *AuditService
	llmFactory         *llm.Factory
	jobEnqueuer        AITriageJobEnqueuer
	workflowDispatcher WorkflowEventDispatcherInterface
	licenseChecker     AITriageModuleChecker
	triageBroadcaster  TriageBroadcaster // For real-time WebSocket updates
	platformCfg        config.AITriageConfig
	logger             *logger.Logger
	outputValidator    *TriageOutputValidator
	promptSanitizer    *PromptSanitizer
}

// NewAITriageService creates a new AITriageService.
func NewAITriageService(
	triageRepo aitriage.Repository,
	findingRepo vulnerability.FindingRepository,
	tenantRepo tenant.Repository,
	activitySvc *FindingActivityService,
	llmFactory *llm.Factory,
	platformCfg config.AITriageConfig,
	log *logger.Logger,
) *AITriageService {
	return &AITriageService{
		triageRepo:      triageRepo,
		findingRepo:     findingRepo,
		tenantRepo:      tenantRepo,
		activitySvc:     activitySvc,
		llmFactory:      llmFactory,
		platformCfg:     platformCfg,
		logger:          log.With("service", "ai_triage"),
		outputValidator: NewTriageOutputValidator(),
		promptSanitizer: NewPromptSanitizer(),
	}
}

// SetAuditService sets the audit service for logging AI operations.
func (s *AITriageService) SetAuditService(auditSvc *AuditService) {
	s.auditSvc = auditSvc
}

// SetJobEnqueuer sets the job enqueuer for async processing.
func (s *AITriageService) SetJobEnqueuer(enqueuer AITriageJobEnqueuer) {
	s.jobEnqueuer = enqueuer
}

// SetWorkflowDispatcher sets the workflow event dispatcher for AI triage events.
func (s *AITriageService) SetWorkflowDispatcher(dispatcher WorkflowEventDispatcherInterface) {
	s.workflowDispatcher = dispatcher
}

// SetLicenseChecker sets the license checker for AI triage feature gating.
func (s *AITriageService) SetLicenseChecker(checker AITriageModuleChecker) {
	s.licenseChecker = checker
}

// SetTriageBroadcaster sets the broadcaster for real-time WebSocket updates.
func (s *AITriageService) SetTriageBroadcaster(broadcaster TriageBroadcaster) {
	s.triageBroadcaster = broadcaster
}

// =============================================================================
// Triage Request/Response Types
// =============================================================================

// TriageRequest represents a request to triage a finding.
type TriageRequest struct {
	TenantID   string  `validate:"required,uuid"`
	FindingID  string  `validate:"required,uuid"`
	TriageType string  `validate:"required,oneof=auto manual bulk"`
	UserID     *string `validate:"omitempty,uuid"` // For manual requests
}

// TriageResponse represents the response from a triage request.
type TriageResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

// TriageResultResponse represents the detailed triage result.
type TriageResultResponse struct {
	ID                      string     `json:"id"`
	Status                  string     `json:"status"`
	SeverityAssessment      string     `json:"severity_assessment,omitempty"`
	SeverityJustification   string     `json:"severity_justification,omitempty"`
	RiskScore               float64    `json:"risk_score,omitempty"`
	Exploitability          string     `json:"exploitability,omitempty"`
	ExploitabilityDetails   string     `json:"exploitability_details,omitempty"`
	BusinessImpact          string     `json:"business_impact,omitempty"`
	PriorityRank            int        `json:"priority_rank,omitempty"`
	FalsePositiveLikelihood float64    `json:"false_positive_likelihood,omitempty"`
	FalsePositiveReason     string     `json:"false_positive_reason,omitempty"`
	Summary                 string     `json:"summary,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
	CompletedAt             *time.Time `json:"completed_at,omitempty"`
	ErrorMessage            string     `json:"error_message,omitempty"`
}

// =============================================================================
// Request Triage (Enqueue Job)
// =============================================================================

// RequestTriage creates a triage job and enqueues it for processing.
func (s *AITriageService) RequestTriage(ctx context.Context, req TriageRequest) (*TriageResponse, error) {
	s.logger.Debug("requesting triage", "tenant_id", req.TenantID, "finding_id", req.FindingID)

	tenantID, err := shared.IDFromString(req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	findingID, err := shared.IDFromString(req.FindingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid finding id", shared.ErrValidation)
	}

	// Check plan access for AI Triage
	if err := s.checkPlanAccess(ctx, req.TenantID, req.TriageType); err != nil {
		return nil, err
	}

	// Get tenant to check AI settings
	t, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	aiSettings := t.TypedSettings().AI
	if aiSettings.Mode == tenant.AIModeDisabled {
		return nil, fmt.Errorf("%w: AI is disabled for this tenant", shared.ErrForbidden)
	}

	// Check BYOK/Agent mode is available on plan
	if err := s.checkAIModeAccess(ctx, req.TenantID, aiSettings.Mode); err != nil {
		return nil, err
	}

	// Verify finding exists and belongs to tenant
	_, err = s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, fmt.Errorf("failed to get finding: %w", err)
	}

	// DEDUPLICATION: Check if there's already a pending/processing triage for this finding
	hasPending, err := s.triageRepo.HasPendingOrProcessing(ctx, tenantID, findingID)
	if err != nil {
		s.logger.Warn("failed to check for existing triage", "error", err)
		// Continue anyway - deduplication is optimization, not critical
	} else if hasPending {
		return nil, fmt.Errorf("%w: a triage request is already in progress for this finding", aitriage.ErrDuplicateRequest)
	}

	// Parse user ID if provided
	var userID *shared.ID
	if req.UserID != nil && *req.UserID != "" {
		id, err := shared.IDFromString(*req.UserID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
		}
		userID = &id
	}

	// Create triage result
	triageType := aitriage.TriageType(req.TriageType)
	result, err := aitriage.NewTriageResult(tenantID, findingID, triageType, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to create triage result: %w", err)
	}

	// Persist the pending job
	if err := s.triageRepo.Create(ctx, result); err != nil {
		return nil, fmt.Errorf("failed to save triage job: %w", err)
	}

	// Enqueue for async processing (no delay for manual requests)
	if err := s.enqueueTriageJob(ctx, result.ID(), tenantID, findingID, 0); err != nil {
		s.logger.Error("failed to enqueue triage job", "error", err, "result_id", result.ID().String())
		// Mark as failed since we couldn't enqueue
		_ = result.MarkFailed("failed to enqueue job: " + err.Error())
		_ = s.triageRepo.Update(ctx, result)
		return nil, fmt.Errorf("failed to enqueue triage job: %w", err)
	}

	s.logger.Info("triage job enqueued",
		"result_id", result.ID().String(),
		"finding_id", req.FindingID,
		"type", req.TriageType,
	)

	// Broadcast real-time WebSocket event for triage pending (job queued)
	if s.triageBroadcaster != nil {
		channel := fmt.Sprintf("triage:%s", req.FindingID)
		event := map[string]any{
			"type": "triage_pending",
			"triage": map[string]any{
				"id":         result.ID().String(),
				"finding_id": req.FindingID,
				"tenant_id":  req.TenantID,
				"status":     "pending",
			},
		}
		s.triageBroadcaster.BroadcastTriage(channel, event, req.TenantID)
	}

	// Record activity: ai_triage_requested (with user as actor)
	if s.activitySvc != nil {
		_, actErr := s.activitySvc.RecordActivity(ctx, RecordActivityInput{
			TenantID:     req.TenantID,
			FindingID:    req.FindingID,
			ActivityType: string(vulnerability.ActivityAITriageRequested),
			ActorID:      req.UserID,
			ActorType:    string(vulnerability.ActorTypeUser),
			Changes: map[string]interface{}{
				"triage_result_id": result.ID().String(),
				"triage_type":      req.TriageType,
				"status":           "pending",
			},
			Source: string(vulnerability.SourceUI),
		})
		if actErr != nil {
			s.logger.Warn("failed to record AI triage requested activity", "error", actErr)
			// Don't fail the request - activity is non-critical
		}
	}

	// Audit log: triage requested
	s.logTriageRequested(ctx, req.TenantID, result.ID().String(), req.FindingID, req.TriageType, req.UserID)

	return &TriageResponse{
		JobID:  result.ID().String(),
		Status: string(result.Status()),
	}, nil
}

// enqueueTriageJob enqueues a triage job for async processing.
func (s *AITriageService) enqueueTriageJob(ctx context.Context, resultID, tenantID, findingID shared.ID, delay time.Duration) error {
	if s.jobEnqueuer == nil {
		return fmt.Errorf("job enqueuer not configured")
	}
	return s.jobEnqueuer.EnqueueAITriage(ctx, resultID.String(), tenantID.String(), findingID.String(), delay)
}

// =============================================================================
// Process Triage (Called by Worker)
// =============================================================================

// ProcessTriage processes a triage job. Called by the worker.
// Uses AcquireTriageSlot for atomic token limit check and status update.
// This prevents race conditions when multiple workers process jobs concurrently.
func (s *AITriageService) ProcessTriage(ctx context.Context, resultID, tenantID, findingID shared.ID) error {
	s.logger.Debug("processing triage", "result_id", resultID.String())

	// SECURITY: Atomically acquire processing slot with token limit check.
	// Uses SELECT FOR UPDATE to prevent race conditions where multiple workers
	// could exceed the token limit by processing jobs simultaneously.
	triageCtx, err := s.triageRepo.AcquireTriageSlot(ctx, tenantID, resultID)
	if err != nil {
		// Handle specific errors
		if errors.Is(err, aitriage.ErrAlreadyProcessing) {
			s.logger.Warn("triage already processed", "result_id", resultID.String())
			return nil // Already processed by another worker, skip
		}
		if errors.Is(err, aitriage.ErrTokenLimitExceeded) {
			// Need to get the result and token info to fail it properly
			// Use non-locking GetTriageContext since we're not processing
			ctx2, getErr := s.triageRepo.GetTriageContext(ctx, tenantID, resultID)
			if getErr != nil {
				s.logger.Error("failed to get triage context for token limit failure", "error", getErr)
				return fmt.Errorf("token limit exceeded and failed to update: %w", err)
			}
			// Audit log: token limit exceeded
			s.logTokenLimitExceeded(ctx, tenantID.String(), resultID.String(), findingID.String(),
				ctx2.TokensUsedMonth, ctx2.MonthlyTokenLimit)
			return s.failTriage(ctx, ctx2.Result, "Monthly token limit exceeded")
		}
		return fmt.Errorf("failed to acquire triage slot: %w", err)
	}
	result := triageCtx.Result

	// Broadcast real-time WebSocket event for triage started
	if s.triageBroadcaster != nil {
		channel := fmt.Sprintf("triage:%s", findingID.String())
		event := map[string]any{
			"type": "triage_started",
			"triage": map[string]any{
				"id":         resultID.String(),
				"finding_id": findingID.String(),
				"tenant_id":  tenantID.String(),
				"status":     "processing",
			},
		}
		s.triageBroadcaster.BroadcastTriage(channel, event, tenantID.String())
	}

	// Extract AI settings from tenant settings JSON
	aiSettings := s.extractAISettings(triageCtx.TenantSettings)

	// Get finding
	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return s.failTriage(ctx, result, "failed to get finding: "+err.Error())
	}

	// Create LLM provider
	provider, err := s.llmFactory.CreateProvider(aiSettings)
	if err != nil {
		// SECURITY: Log detailed error internally, return generic message to prevent info disclosure
		s.logger.Error("failed to create LLM provider", "error", err, "result_id", resultID.String())
		return s.failTriage(ctx, result, "AI provider configuration error")
	}

	// Build prompt with sanitization for prompt injection protection
	prompt := s.buildTriagePromptSafe(finding)

	// Call LLM with configured parameters
	temperature := s.platformCfg.Temperature
	if temperature == 0 {
		temperature = 0.1 // Default to low temperature for consistent results
	}
	llmResp, err := provider.Complete(ctx, llm.CompletionRequest{
		SystemPrompt: triageSystemPrompt,
		UserPrompt:   prompt,
		MaxTokens:    s.platformCfg.MaxTokens,
		Temperature:  temperature,
		JSONMode:     true,
	})
	if err != nil {
		// SECURITY: Log detailed error internally, return user-friendly categorized message
		s.logger.Error("LLM call failed",
			"error", err,
			"result_id", resultID.String(),
			"provider", provider.Name(),
			"model", provider.Model(),
		)
		return s.failTriage(ctx, result, categorizeError(err))
	}

	// Check for empty or truncated response
	if llmResp.Content == "" {
		s.logger.Error("LLM returned empty response",
			"result_id", resultID.String(),
			"finish_reason", llmResp.FinishReason,
			"stop_reason", llmResp.StopReason,
			"prompt_tokens", llmResp.PromptTokens,
			"completion_tokens", llmResp.CompletionTokens,
		)
		return s.failTriage(ctx, result, "AI returned empty response")
	}

	// Check if response was truncated (max_tokens reached)
	finishReason := strings.ToUpper(llmResp.FinishReason)
	if finishReason == "MAX_TOKENS" || finishReason == "LENGTH" {
		s.logger.Warn("LLM response truncated due to max_tokens",
			"result_id", resultID.String(),
			"finish_reason", llmResp.FinishReason,
			"completion_tokens", llmResp.CompletionTokens,
			"content_length", len(llmResp.Content),
		)
		// Try to parse anyway - might have valid JSON
	}

	// Validate and sanitize LLM output
	analysis, err := s.outputValidator.ValidateAndSanitize(llmResp.Content)
	if err != nil {
		// SECURITY: Log detailed error internally, return generic message
		// Log first 500 chars of content for debugging (truncate for safety)
		contentPreview := llmResp.Content
		if len(contentPreview) > 500 {
			contentPreview = contentPreview[:500] + "...[truncated]"
		}
		s.logger.Error("failed to validate LLM response",
			"error", err,
			"result_id", resultID.String(),
			"finish_reason", llmResp.FinishReason,
			"content_length", len(llmResp.Content),
			"content_preview", contentPreview,
		)
		return s.failTriage(ctx, result, "AI response validation failed")
	}

	// Set provider info
	analysis.Provider = provider.Name()
	analysis.Model = provider.Model()
	analysis.PromptTokens = llmResp.PromptTokens
	analysis.CompletionTokens = llmResp.CompletionTokens

	// Mark completed
	if err := result.MarkCompleted(*analysis); err != nil {
		return s.failTriage(ctx, result, "failed to mark completed: "+err.Error())
	}
	if err := s.triageRepo.Update(ctx, result); err != nil {
		return fmt.Errorf("failed to save triage result: %w", err)
	}

	// Record activity
	if s.activitySvc != nil {
		_, actErr := s.activitySvc.RecordActivity(ctx, RecordActivityInput{
			TenantID:     tenantID.String(),
			FindingID:    findingID.String(),
			ActivityType: string(vulnerability.ActivityAITriage),
			ActorID:      nil,
			ActorType:    string(vulnerability.ActorTypeAI),
			Changes: map[string]interface{}{
				"triage_result_id":  result.ID().String(),
				"severity":          analysis.SeverityAssessment,
				"risk_score":        analysis.RiskScore,
				"priority_rank":     analysis.PriorityRank,
				"ai_risk_level":     s.getRiskLevel(analysis.RiskScore),
				"ai_confidence":     s.getConfidence(analysis.FalsePositiveLikelihood),
				"ai_recommendation": analysis.Summary,
			},
			Source: string(vulnerability.SourceAuto),
		})
		if actErr != nil {
			s.logger.Error("failed to record AI triage activity", "error", actErr)
		}
	}

	s.logger.Info("triage completed",
		"result_id", resultID.String(),
		"severity", analysis.SeverityAssessment,
		"risk_score", analysis.RiskScore,
		"tokens", llmResp.TotalTokens,
	)

	// Audit log: triage completed
	s.logTriageCompleted(ctx, tenantID.String(), resultID.String(), findingID.String(), analysis.SeverityAssessment, analysis.RiskScore, llmResp.TotalTokens)

	// Dispatch workflow event for AI triage completion
	if s.workflowDispatcher != nil {
		triageData := map[string]any{
			"severity_assessment":       analysis.SeverityAssessment,
			"severity_justification":    analysis.SeverityJustification,
			"risk_score":                analysis.RiskScore,
			"exploitability":            analysis.Exploitability,
			"exploitability_details":    analysis.ExploitabilityDetails,
			"business_impact":           analysis.BusinessImpact,
			"priority_rank":             analysis.PriorityRank,
			"false_positive_likelihood": analysis.FalsePositiveLikelihood,
			"false_positive_reason":     analysis.FalsePositiveReason,
			"summary":                   analysis.Summary,
		}
		s.workflowDispatcher.DispatchAITriageCompleted(ctx, tenantID, findingID, resultID, triageData)
	}

	// Broadcast real-time WebSocket event for triage completion
	if s.triageBroadcaster != nil {
		channel := fmt.Sprintf("triage:%s", findingID.String())
		event := map[string]any{
			"type": "triage_completed",
			"triage": map[string]any{
				"id":         resultID.String(),
				"finding_id": findingID.String(),
				"tenant_id":  tenantID.String(),
				"status":     "completed",
			},
		}
		s.triageBroadcaster.BroadcastTriage(channel, event, tenantID.String())
	}

	return nil
}

// failTriage marks a triage job as failed and updates the repository.
func (s *AITriageService) failTriage(ctx context.Context, result *aitriage.TriageResult, errMsg string) error {
	s.logger.Error("triage failed", "result_id", result.ID().String(), "error", errMsg)
	_ = result.MarkFailed(errMsg)

	// Audit log: triage failed
	s.logTriageFailed(ctx, result.TenantID().String(), result.ID().String(), result.FindingID().String(), errMsg)

	if err := s.triageRepo.Update(ctx, result); err != nil {
		s.logger.Error("failed to update failed triage", "error", err)
	}

	// Record activity: ai_triage_failed
	if s.activitySvc != nil {
		_, actErr := s.activitySvc.RecordActivity(ctx, RecordActivityInput{
			TenantID:     result.TenantID().String(),
			FindingID:    result.FindingID().String(),
			ActivityType: string(vulnerability.ActivityAITriageFailed),
			ActorID:      nil,
			ActorType:    string(vulnerability.ActorTypeSystem),
			Changes: map[string]interface{}{
				"triage_result_id": result.ID().String(),
				"status":           "failed",
				"error_message":    errMsg,
			},
			Source: string(vulnerability.SourceAuto),
		})
		if actErr != nil {
			s.logger.Warn("failed to record AI triage failed activity", "error", actErr)
		}
	}

	// Dispatch workflow event for AI triage failure
	if s.workflowDispatcher != nil {
		s.workflowDispatcher.DispatchAITriageFailed(ctx, result.TenantID(), result.FindingID(), result.ID(), errMsg)
	}

	// Broadcast real-time WebSocket event for triage failure
	if s.triageBroadcaster != nil {
		channel := fmt.Sprintf("triage:%s", result.FindingID().String())
		event := map[string]any{
			"type": "triage_failed",
			"triage": map[string]any{
				"id":            result.ID().String(),
				"finding_id":    result.FindingID().String(),
				"tenant_id":     result.TenantID().String(),
				"status":        "failed",
				"error_message": errMsg,
			},
		}
		s.triageBroadcaster.BroadcastTriage(channel, event, result.TenantID().String())
	}

	return fmt.Errorf("triage failed: %s", errMsg)
}

// =============================================================================
// Get Triage Results
// =============================================================================

// GetTriageResult retrieves a triage result by ID.
func (s *AITriageService) GetTriageResult(ctx context.Context, tenantID, resultID string) (*TriageResultResponse, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	rid, err := shared.IDFromString(resultID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid result id", shared.ErrValidation)
	}

	result, err := s.triageRepo.GetByID(ctx, tid, rid)
	if err != nil {
		return nil, err
	}

	return s.toTriageResultResponse(result), nil
}

// GetLatestTriageByFinding retrieves the latest triage result for a finding.
func (s *AITriageService) GetLatestTriageByFinding(ctx context.Context, tenantID, findingID string) (*TriageResultResponse, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	fid, err := shared.IDFromString(findingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid finding id", shared.ErrValidation)
	}

	result, err := s.triageRepo.GetByFindingID(ctx, tid, fid)
	if err != nil {
		return nil, err
	}

	return s.toTriageResultResponse(result), nil
}

// ListTriageHistory retrieves triage history for a finding.
func (s *AITriageService) ListTriageHistory(ctx context.Context, tenantID, findingID string, limit, offset int) ([]*TriageResultResponse, int, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	fid, err := shared.IDFromString(findingID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: invalid finding id", shared.ErrValidation)
	}

	if limit <= 0 || limit > 100 {
		limit = 20
	}

	results, total, err := s.triageRepo.ListByFindingID(ctx, tid, fid, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	responses := make([]*TriageResultResponse, len(results))
	for i, r := range results {
		responses[i] = s.toTriageResultResponse(r)
	}

	return responses, total, nil
}

// =============================================================================
// Bulk Triage
// =============================================================================

// BulkTriageRequest represents a request to triage multiple findings.
type BulkTriageRequest struct {
	TenantID   string   `validate:"required,uuid"`
	FindingIDs []string `validate:"required,min=1,max=100,dive,uuid"`
	UserID     *string  `validate:"omitempty,uuid"`
}

// BulkTriageResponse represents the response from a bulk triage request.
type BulkTriageResponse struct {
	Jobs       []BulkTriageJob `json:"jobs"`
	TotalCount int             `json:"total_count"`
	Queued     int             `json:"queued"`
	Failed     int             `json:"failed"`
}

// BulkTriageJob represents a single job in bulk triage.
type BulkTriageJob struct {
	FindingID string `json:"finding_id"`
	JobID     string `json:"job_id,omitempty"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// RequestBulkTriage creates multiple triage jobs for a list of findings.
func (s *AITriageService) RequestBulkTriage(ctx context.Context, req BulkTriageRequest) (*BulkTriageResponse, error) {
	s.logger.Debug("requesting bulk triage", "tenant_id", req.TenantID, "count", len(req.FindingIDs))

	tenantID, err := shared.IDFromString(req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	// Get tenant to check AI settings
	t, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	aiSettings := t.TypedSettings().AI
	if aiSettings.Mode == tenant.AIModeDisabled {
		return nil, fmt.Errorf("%w: AI is disabled for this tenant", shared.ErrForbidden)
	}

	// Parse user ID if provided
	var userID *shared.ID
	if req.UserID != nil && *req.UserID != "" {
		id, err := shared.IDFromString(*req.UserID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
		}
		userID = &id
	}

	response := &BulkTriageResponse{
		Jobs:       make([]BulkTriageJob, 0, len(req.FindingIDs)),
		TotalCount: len(req.FindingIDs),
	}

	// OPTIMIZATION: Parse all finding IDs first and batch validate existence
	findingIDMap := make(map[string]shared.ID) // findingIDStr -> parsed ID
	validFindingIDs := make([]shared.ID, 0, len(req.FindingIDs))

	for _, findingIDStr := range req.FindingIDs {
		findingID, err := shared.IDFromString(findingIDStr)
		if err != nil {
			response.Jobs = append(response.Jobs, BulkTriageJob{
				FindingID: findingIDStr,
				Status:    notificationStatusFailed,
				Error:     "invalid finding id",
			})
			response.Failed++
			continue
		}
		findingIDMap[findingIDStr] = findingID
		validFindingIDs = append(validFindingIDs, findingID)
	}

	// OPTIMIZATION: Batch check which findings exist (1 query instead of N)
	existsMap, err := s.findingRepo.ExistsByIDs(ctx, tenantID, validFindingIDs)
	if err != nil {
		s.logger.Warn("failed to batch check findings, falling back to individual checks", "error", err)
		// Continue with empty map - will check individually
		existsMap = make(map[shared.ID]bool)
	}

	// Process each valid finding
	for findingIDStr, findingID := range findingIDMap {
		job := BulkTriageJob{
			FindingID: findingIDStr,
		}

		// Check if finding exists (from batch result)
		if !existsMap[findingID] {
			job.Status = notificationStatusFailed
			job.Error = "finding not found"
			response.Jobs = append(response.Jobs, job)
			response.Failed++
			continue
		}

		// Create triage result
		result, err := aitriage.NewTriageResult(tenantID, findingID, aitriage.TriageTypeBulk, userID)
		if err != nil {
			job.Status = notificationStatusFailed
			job.Error = "failed to create triage job"
			response.Jobs = append(response.Jobs, job)
			response.Failed++
			continue
		}

		if err := s.triageRepo.Create(ctx, result); err != nil {
			job.Status = notificationStatusFailed
			job.Error = "failed to save triage job"
			response.Jobs = append(response.Jobs, job)
			response.Failed++
			continue
		}

		// Enqueue for processing
		if err := s.enqueueTriageJob(ctx, result.ID(), tenantID, findingID, 0); err != nil {
			job.Status = notificationStatusFailed
			job.Error = "failed to enqueue job"
			_ = result.MarkFailed("failed to enqueue job: " + err.Error())
			_ = s.triageRepo.Update(ctx, result)
			response.Jobs = append(response.Jobs, job)
			response.Failed++
			continue
		}

		job.JobID = result.ID().String()
		job.Status = "queued"
		response.Jobs = append(response.Jobs, job)
		response.Queued++
	}

	s.logger.Info("bulk triage completed",
		"tenant_id", req.TenantID,
		"total", response.TotalCount,
		"queued", response.Queued,
		"failed", response.Failed,
	)

	// Audit log: bulk triage requested
	s.logBulkTriageRequested(ctx, req.TenantID, response.TotalCount, response.Queued, response.Failed)

	return response, nil
}

// =============================================================================
// Auto-Triage Check
// =============================================================================

// ShouldAutoTriage checks if a finding should be auto-triaged based on tenant settings.
func (s *AITriageService) ShouldAutoTriage(ctx context.Context, tenantID shared.ID, severity string) (bool, error) {
	if !s.platformCfg.Enabled {
		return false, nil
	}

	t, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return false, err
	}

	aiSettings := t.TypedSettings().AI
	if aiSettings.Mode == tenant.AIModeDisabled {
		return false, nil
	}
	if !aiSettings.AutoTriageEnabled {
		return false, nil
	}

	// Check if severity matches
	for _, s := range aiSettings.AutoTriageSeverities {
		if strings.EqualFold(s, severity) {
			return true, nil
		}
	}

	return false, nil
}

// EnqueueAutoTriage enqueues an auto-triage job with optional delay.
func (s *AITriageService) EnqueueAutoTriage(ctx context.Context, tenantID, findingID shared.ID) error {
	// Get delay from tenant settings
	t, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return err
	}

	aiSettings := t.TypedSettings().AI
	delay := time.Duration(aiSettings.AutoTriageDelaySeconds) * time.Second

	// Create triage result
	result, err := aitriage.NewTriageResult(tenantID, findingID, aitriage.TriageTypeAuto, nil)
	if err != nil {
		return err
	}

	if err := s.triageRepo.Create(ctx, result); err != nil {
		return err
	}

	// Enqueue with delay
	return s.enqueueTriageJob(ctx, result.ID(), tenantID, findingID, delay)
}

// =============================================================================
// Helpers
// =============================================================================

func (s *AITriageService) toTriageResultResponse(r *aitriage.TriageResult) *TriageResultResponse {
	return &TriageResultResponse{
		ID:                      r.ID().String(),
		Status:                  string(r.Status()),
		SeverityAssessment:      r.SeverityAssessment(),
		SeverityJustification:   r.SeverityJustification(),
		RiskScore:               r.RiskScore(),
		Exploitability:          string(r.Exploitability()),
		ExploitabilityDetails:   r.ExploitabilityDetails(),
		BusinessImpact:          r.BusinessImpact(),
		PriorityRank:            r.PriorityRank(),
		FalsePositiveLikelihood: r.FalsePositiveLikelihood(),
		FalsePositiveReason:     r.FalsePositiveReason(),
		Summary:                 r.AnalysisSummary(),
		CreatedAt:               r.CreatedAt(),
		CompletedAt:             r.CompletedAt(),
		ErrorMessage:            r.ErrorMessage(),
	}
}

// Risk level constants for AI triage scoring.
const (
	riskLevelCritical = "critical"
	riskLevelHigh     = "high"
	riskLevelMedium   = "medium"
	riskLevelLow      = "low"
)

func (s *AITriageService) getRiskLevel(score float64) string {
	switch {
	case score >= 70:
		return riskLevelCritical
	case score >= 50:
		return riskLevelHigh
	case score >= 30:
		return riskLevelMedium
	default:
		return riskLevelLow
	}
}

func (s *AITriageService) getConfidence(fpLikelihood float64) string {
	switch {
	case fpLikelihood > 0.5:
		return riskLevelLow
	case fpLikelihood > 0.2:
		return riskLevelMedium
	default:
		return riskLevelHigh
	}
}

// extractAISettings extracts AISettings from raw tenant settings JSON.
func (s *AITriageService) extractAISettings(settings map[string]any) tenant.AISettings {
	result := tenant.AISettings{}

	aiMap, ok := settings["ai"].(map[string]any)
	if !ok {
		return result
	}

	if mode, ok := aiMap["mode"].(string); ok {
		result.Mode = tenant.AIMode(mode)
	}
	if provider, ok := aiMap["provider"].(string); ok {
		result.Provider = tenant.LLMProvider(provider)
	}
	if apiKey, ok := aiMap["api_key"].(string); ok {
		result.APIKey = apiKey
	}
	if endpoint, ok := aiMap["azure_endpoint"].(string); ok {
		result.AzureEndpoint = endpoint
	}
	if model, ok := aiMap["model_override"].(string); ok {
		result.ModelOverride = model
	}
	if enabled, ok := aiMap["auto_triage_enabled"].(bool); ok {
		result.AutoTriageEnabled = enabled
	}
	if severities, ok := aiMap["auto_triage_severities"].([]any); ok {
		for _, sev := range severities {
			if s, ok := sev.(string); ok {
				result.AutoTriageSeverities = append(result.AutoTriageSeverities, s)
			}
		}
	}
	if delay, ok := aiMap["auto_triage_delay_seconds"].(float64); ok {
		result.AutoTriageDelaySeconds = int(delay)
	}
	if limit, ok := aiMap["monthly_token_limit"].(float64); ok {
		result.MonthlyTokenLimit = int(limit)
	}

	return result
}

// buildTriagePromptSafe builds the prompt for AI triage with sanitization.
func (s *AITriageService) buildTriagePromptSafe(f *vulnerability.Finding) string {
	var b strings.Builder

	// Sanitize all user-provided data to prevent prompt injection
	san := s.promptSanitizer

	b.WriteString("## Finding Information\n")
	fmt.Fprintf(&b, "- **Title**: %s\n", san.SanitizeForPrompt(f.Title()))
	fmt.Fprintf(&b, "- **Description**: %s\n", san.SanitizeForPrompt(f.Description()))
	fmt.Fprintf(&b, "- **Severity**: %s", f.Severity())
	if f.CVSSScore() != nil {
		fmt.Fprintf(&b, " (CVSS: %.1f)", *f.CVSSScore())
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "- **Source**: %s (%s)\n", f.Source(), f.ToolName())

	if f.FilePath() != "" {
		fmt.Fprintf(&b, "- **File**: %s:%d\n", san.SanitizeForPrompt(f.FilePath()), f.StartLine())
	}

	if f.Snippet() != "" {
		fmt.Fprintf(&b, "- **Code Snippet**:\n```\n%s\n```\n", san.SanitizeCodeSnippet(f.Snippet()))
	}

	b.WriteString("\n## Context\n")
	if f.CVEID() != "" {
		fmt.Fprintf(&b, "- **CVE**: %s\n", f.CVEID())
	}
	if len(f.CWEIDs()) > 0 {
		fmt.Fprintf(&b, "- **CWE**: %s\n", strings.Join(f.CWEIDs(), ", "))
	}
	if len(f.OWASPIDs()) > 0 {
		fmt.Fprintf(&b, "- **OWASP**: %s\n", strings.Join(f.OWASPIDs(), ", "))
	}
	fmt.Fprintf(&b, "- **Internet Accessible**: %t\n", f.IsInternetAccessible())
	fmt.Fprintf(&b, "- **Data Exposure Risk**: %s\n", f.DataExposureRisk())

	if len(f.ComplianceImpact()) > 0 {
		fmt.Fprintf(&b, "- **Compliance Frameworks**: %s\n", strings.Join(f.ComplianceImpact(), ", "))
	}

	b.WriteString("\n## Analysis Required\n")
	b.WriteString("1. **Severity Assessment**: Is the current severity appropriate? If not, what should it be?\n")
	b.WriteString("2. **Exploitability**: How easily can this be exploited in real-world?\n")
	b.WriteString("3. **Business Impact**: What is the potential impact on the organization?\n")
	b.WriteString("4. **False Positive**: Is this likely a false positive? Why?\n")
	b.WriteString("5. **Priority**: On a scale of 1-100, how urgent is this to fix?\n")
	b.WriteString("6. **Remediation**: What are the recommended steps to fix this?\n")

	return b.String()
}

// =============================================================================
// Task Type and System Prompt
// =============================================================================

// TypeAITriage is the asynq task type for AI triage jobs.
const TypeAITriage = "ai:triage"

const triageSystemPrompt = `You are an expert security analyst specialized in vulnerability assessment and triage.
Your task is to analyze security findings and provide actionable recommendations.

IMPORTANT: Respond ONLY with valid JSON in the exact format below. No additional text or explanation outside the JSON.

Response Format:
{
    "severity_assessment": "critical|high|medium|low|info",
    "severity_justification": "Explain why this severity is appropriate",
    "risk_score": 0-100,
    "exploitability": "high|medium|low|theoretical",
    "exploitability_details": "Explain exploitability factors",
    "business_impact": "Describe potential business impact",
    "false_positive_likelihood": 0.0-1.0,
    "false_positive_reason": "Why this might be a false positive (if applicable)",
    "priority_rank": 1-100,
    "remediation_steps": [
        {"step": 1, "description": "First remediation step", "effort": "low|medium|high"}
    ],
    "related_cves": ["CVE-..."],
    "related_cwes": ["CWE-..."],
    "summary": "Brief 1-2 sentence summary of the finding and recommendation"
}

Guidelines:
- Be precise and evidence-based in your analysis
- Consider the context (internet accessibility, data exposure, compliance)
- Risk score should reflect real-world exploitability and impact
- Remediation steps should be actionable and specific
- If unsure about false positive, use a moderate likelihood (0.2-0.3)
`

// =============================================================================
// Audit Logging Helpers
// =============================================================================

// logAuditEvent logs an AI triage audit event.
func (s *AITriageService) logAuditEvent(ctx context.Context, tenantID, resultID, findingID string, action audit.Action, result audit.Result, metadata map[string]any) {
	if s.auditSvc == nil {
		return
	}

	event := AuditEvent{
		Action:       action,
		ResourceType: audit.ResourceTypeAITriage,
		ResourceID:   resultID,
		Result:       result,
		Metadata:     metadata,
	}

	if result == audit.ResultFailure {
		event.Severity = audit.SeverityMedium
	}

	actx := AuditContext{
		TenantID: tenantID,
	}

	if err := s.auditSvc.LogEvent(ctx, actx, event); err != nil {
		s.logger.Error("failed to log audit event",
			"error", err,
			"action", action,
			"result_id", resultID,
		)
	}
}

// logTriageRequested logs when a triage is requested.
func (s *AITriageService) logTriageRequested(ctx context.Context, tenantID, resultID, findingID, triageType string, userID *string) {
	metadata := map[string]any{
		"finding_id":   findingID,
		"triage_type":  triageType,
		"requested_by": "system",
	}
	if userID != nil && *userID != "" {
		metadata["requested_by"] = *userID
	}
	s.logAuditEvent(ctx, tenantID, resultID, findingID, audit.ActionAITriageRequested, audit.ResultSuccess, metadata)
}

// logTriageCompleted logs when a triage completes successfully.
func (s *AITriageService) logTriageCompleted(ctx context.Context, tenantID, resultID, findingID string, severity string, riskScore float64, tokensUsed int) {
	s.logAuditEvent(ctx, tenantID, resultID, findingID, audit.ActionAITriageCompleted, audit.ResultSuccess, map[string]any{
		"finding_id":  findingID,
		"severity":    severity,
		"risk_score":  riskScore,
		"tokens_used": tokensUsed,
	})
}

// logTriageFailed logs when a triage fails.
func (s *AITriageService) logTriageFailed(ctx context.Context, tenantID, resultID, findingID, errMsg string) {
	s.logAuditEvent(ctx, tenantID, resultID, findingID, audit.ActionAITriageFailed, audit.ResultFailure, map[string]any{
		"finding_id": findingID,
		"error":      errMsg,
	})
}

// logBulkTriageRequested logs when a bulk triage is requested.
func (s *AITriageService) logBulkTriageRequested(ctx context.Context, tenantID string, count int, queued int, failed int) {
	s.logAuditEvent(ctx, tenantID, "", "", audit.ActionAITriageBulk, audit.ResultSuccess, map[string]any{
		"total_count": count,
		"queued":      queued,
		"failed":      failed,
	})
}

// logTokenLimitExceeded logs when token limit is exceeded.
func (s *AITriageService) logTokenLimitExceeded(ctx context.Context, tenantID, resultID, findingID string, usedTokens, limitTokens int) {
	s.logAuditEvent(ctx, tenantID, resultID, findingID, audit.ActionAITriageTokenLimit, audit.ResultDenied, map[string]any{
		"finding_id":   findingID,
		"tokens_used":  usedTokens,
		"tokens_limit": limitTokens,
	})
}

// =============================================================================
// Plan Access Checking
// =============================================================================

// checkPlanAccess verifies the tenant has access to AI Triage based on their plan.
// Returns nil if access is allowed, or an appropriate error if not.
func (s *AITriageService) checkPlanAccess(ctx context.Context, tenantID, triageType string) error {
	// If no license checker configured, allow all (backwards compatibility / dev mode)
	if s.licenseChecker == nil {
		return nil
	}

	// Check base AI Triage module access
	hasAccess, err := s.licenseChecker.TenantHasModule(ctx, tenantID, module.ModuleAITriage)
	if err != nil {
		s.logger.Warn("failed to check AI triage license", "error", err, "tenant_id", tenantID)
		// Fail open for license check errors (allow access but log warning)
		return nil
	}
	if !hasAccess {
		return fmt.Errorf("%w: %v", shared.ErrForbidden, ErrAITriageNotAvailable)
	}

	// Check bulk triage access if applicable
	if triageType == "bulk" {
		hasBulk, err := s.licenseChecker.TenantHasModule(ctx, tenantID, module.ModuleAITriageBulk)
		if err != nil {
			s.logger.Warn("failed to check bulk triage license", "error", err)
			return nil
		}
		if !hasBulk {
			return fmt.Errorf("%w: %v", shared.ErrForbidden, ErrBulkTriageNotAvailable)
		}
	}

	// Check auto triage access if applicable
	if triageType == "auto" {
		hasAuto, err := s.licenseChecker.TenantHasModule(ctx, tenantID, module.ModuleAITriageAuto)
		if err != nil {
			s.logger.Warn("failed to check auto triage license", "error", err)
			return nil
		}
		if !hasAuto {
			return fmt.Errorf("%w: %v", shared.ErrForbidden, ErrAutoTriageNotAvailable)
		}
	}

	return nil
}

// checkAIModeAccess verifies the tenant has access to the configured AI mode.
func (s *AITriageService) checkAIModeAccess(ctx context.Context, tenantID string, mode tenant.AIMode) error {
	// If no license checker configured, allow all
	if s.licenseChecker == nil {
		return nil
	}

	switch mode {
	case tenant.AIModeBYOK:
		hasBYOK, err := s.licenseChecker.TenantHasModule(ctx, tenantID, module.ModuleAITriageBYOK)
		if err != nil {
			s.logger.Warn("failed to check BYOK license", "error", err)
			return nil
		}
		if !hasBYOK {
			return fmt.Errorf("%w: %v", shared.ErrForbidden, ErrAITriageBYOKNotAvailable)
		}

	case tenant.AIModeAgent:
		hasAgent, err := s.licenseChecker.TenantHasModule(ctx, tenantID, module.ModuleAITriageAgent)
		if err != nil {
			s.logger.Warn("failed to check agent license", "error", err)
			return nil
		}
		if !hasAgent {
			return fmt.Errorf("%w: %v", shared.ErrForbidden, ErrAITriageAgentNotAvailable)
		}
	}

	return nil
}

// GetPlanTokenLimit returns the monthly token limit for a tenant based on their plan.
// Returns -1 if unlimited, 0 if not set.
func (s *AITriageService) GetPlanTokenLimit(ctx context.Context, tenantID string) (int64, error) {
	if s.licenseChecker == nil {
		return -1, nil // Unlimited if no license checker
	}

	result, err := s.licenseChecker.GetTenantModuleLimit(ctx, tenantID, module.ModuleAITriage, module.AITriageLimitMonthlyTokens)
	if err != nil {
		return -1, err
	}

	return result.Limit, nil
}

// =============================================================================
// Stuck Job Recovery
// =============================================================================

// RecoverStuckJobsInput contains parameters for stuck job recovery.
type RecoverStuckJobsInput struct {
	// StuckDuration is how long a job must be stuck before being recovered.
	// Default: 15 minutes
	StuckDuration time.Duration
	// Limit is the maximum number of stuck jobs to recover in one batch.
	// Default: 50
	Limit int
}

// RecoverStuckJobsOutput contains the results of stuck job recovery.
type RecoverStuckJobsOutput struct {
	// Total is the number of stuck jobs found.
	Total int `json:"total"`
	// Recovered is the number of jobs successfully marked as failed.
	Recovered int `json:"recovered"`
	// Skipped is the number of jobs that were already in a terminal state.
	Skipped int `json:"skipped"`
	// Errors is the number of jobs that failed to update.
	Errors int `json:"errors"`
}

// RecoverStuckJobs finds and marks stuck triage jobs as failed.
// Jobs are considered stuck if they've been in pending/processing state for longer than stuckDuration.
// This should be called periodically by a background job.
func (s *AITriageService) RecoverStuckJobs(ctx context.Context, input RecoverStuckJobsInput) (*RecoverStuckJobsOutput, error) {
	// Set defaults
	if input.StuckDuration == 0 {
		input.StuckDuration = 15 * time.Minute
	}
	if input.Limit <= 0 {
		input.Limit = 50
	}

	s.logger.Info("starting stuck job recovery",
		"stuck_duration", input.StuckDuration.String(),
		"limit", input.Limit,
	)

	// Find stuck jobs
	stuckJobs, err := s.triageRepo.FindStuckJobs(ctx, input.StuckDuration, input.Limit)
	if err != nil {
		return nil, fmt.Errorf("failed to find stuck jobs: %w", err)
	}

	output := &RecoverStuckJobsOutput{
		Total: len(stuckJobs),
	}

	if len(stuckJobs) == 0 {
		s.logger.Debug("no stuck jobs found")
		return output, nil
	}

	s.logger.Info("found stuck jobs", "count", len(stuckJobs))

	// Mark each stuck job as failed
	errorMsg := fmt.Sprintf("Job stuck in queue for more than %s - marked as failed by recovery job", input.StuckDuration.String())

	for _, job := range stuckJobs {
		updated, err := s.triageRepo.MarkStuckAsFailed(ctx, job.ID(), errorMsg)
		if err != nil {
			s.logger.Error("failed to mark stuck job as failed",
				"job_id", job.ID().String(),
				"error", err,
			)
			output.Errors++
			continue
		}

		if updated {
			output.Recovered++
			s.logger.Info("recovered stuck job",
				"job_id", job.ID().String(),
				"tenant_id", job.TenantID().String(),
				"finding_id", job.FindingID().String(),
				"status", job.Status(),
			)

			// Broadcast WebSocket event for the failed job
			if s.triageBroadcaster != nil {
				channel := fmt.Sprintf("triage:%s", job.FindingID().String())
				event := map[string]any{
					"type": "triage_failed",
					"triage": map[string]any{
						"id":            job.ID().String(),
						"finding_id":    job.FindingID().String(),
						"tenant_id":     job.TenantID().String(),
						"status":        "failed",
						"error_message": errorMsg,
					},
				}
				s.triageBroadcaster.BroadcastTriage(channel, event, job.TenantID().String())
			}

			// Log audit event
			s.logTriageFailed(ctx, job.TenantID().String(), job.ID().String(), job.FindingID().String(), errorMsg)
		} else {
			output.Skipped++
			s.logger.Debug("job already in terminal state",
				"job_id", job.ID().String(),
			)
		}
	}

	s.logger.Info("stuck job recovery completed",
		"total", output.Total,
		"recovered", output.Recovered,
		"skipped", output.Skipped,
		"errors", output.Errors,
	)

	return output, nil
}

// =============================================================================
// AI Configuration Info
// =============================================================================

// AIConfigInfo represents the AI configuration info returned to the UI.
type AIConfigInfo struct {
	// Mode is the AI mode: platform, byok, agent, disabled
	Mode string `json:"mode"`
	// Provider is the LLM provider: claude, openai, gemini
	Provider string `json:"provider"`
	// Model is the model being used
	Model string `json:"model"`
	// IsEnabled indicates if AI triage is enabled for this tenant
	IsEnabled bool `json:"is_enabled"`
	// AutoTriageEnabled indicates if auto-triage is enabled
	AutoTriageEnabled bool `json:"auto_triage_enabled"`
	// AutoTriageSeverities is the list of severities for auto-triage
	AutoTriageSeverities []string `json:"auto_triage_severities,omitempty"`
	// MonthlyTokenLimit is the monthly token limit (0 = unlimited)
	MonthlyTokenLimit int `json:"monthly_token_limit"`
	// TokensUsedThisMonth is the number of tokens used this month
	TokensUsedThisMonth int `json:"tokens_used_this_month"`
}

// GetAIConfig returns the AI configuration info for a tenant.
// This is used by the UI to display which model is being used.
func (s *AITriageService) GetAIConfig(ctx context.Context, tenantID string) (*AIConfigInfo, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	// Get tenant to check AI settings
	t, err := s.tenantRepo.GetByID(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	aiSettings := t.TypedSettings().AI

	// Build config info
	info := &AIConfigInfo{
		Mode:                 string(aiSettings.Mode),
		IsEnabled:            aiSettings.Mode != tenant.AIModeDisabled,
		AutoTriageEnabled:    aiSettings.AutoTriageEnabled,
		AutoTriageSeverities: aiSettings.AutoTriageSeverities,
		MonthlyTokenLimit:    aiSettings.MonthlyTokenLimit,
		TokensUsedThisMonth:  aiSettings.TokensUsedThisMonth,
	}

	// Determine provider and model based on mode
	switch aiSettings.Mode {
	case tenant.AIModeDisabled:
		info.Provider = ""
		info.Model = ""

	case tenant.AIModePlatform:
		// Use platform config
		info.Provider = s.platformCfg.PlatformProvider
		info.Model = s.platformCfg.PlatformModel
		if info.Provider == "" {
			info.Provider = "claude" // default
		}

	case tenant.AIModeBYOK:
		// Use tenant's provider config
		info.Provider = string(aiSettings.Provider)
		info.Model = aiSettings.ModelOverride
		if info.Model == "" {
			// Set default model based on provider
			switch aiSettings.Provider {
			case tenant.LLMProviderClaude:
				info.Model = "claude-sonnet-4-20250514"
			case tenant.LLMProviderOpenAI:
				info.Model = "gpt-4o"
			case tenant.LLMProviderGemini:
				info.Model = "gemini-2.0-flash"
			}
		}

	case tenant.AIModeAgent:
		info.Provider = "agent"
		info.Model = "self-hosted"
	}

	// Get token limit from license if available
	if s.licenseChecker != nil {
		limit, err := s.GetPlanTokenLimit(ctx, tenantID)
		if err == nil && limit > 0 {
			info.MonthlyTokenLimit = int(limit)
		}
	}

	return info, nil
}
