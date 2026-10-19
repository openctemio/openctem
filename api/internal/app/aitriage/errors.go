package aitriage

import (
	"errors"
	"strings"

	"github.com/openctemio/openctem/api/internal/infra/llm"
)

// Request errors the HTTP layer maps to distinct answers (errors.Is). None of
// them wraps shared.ErrForbidden: "AI is not available here" is not "you may
// not do this", and the person needs to know which one it is.
var (
	// ErrPlatformAINotSetUp: the organization uses platform AI and the
	// platform administrator has not set up a provider.
	ErrPlatformAINotSetUp = errors.New("platform AI is not set up on this installation")
	// ErrAIDisabled: AI triage is off for the organization.
	ErrAIDisabled = errors.New("AI triage is turned off for this organization")
	// ErrPolicyRestricted: the organization's AI data policy keeps this
	// finding's content on the platform (pentest TLP limit, campaign with AI
	// off).
	ErrPolicyRestricted = errors.New("the organization's AI data policy keeps this finding away from AI")
)

// Failure codes stored on a failed triage (error_message), sent to the web
// UI, workflows, the activity feed and the audit log. They are fixed values:
// raw internal error text (database, provider, network) never leaves the
// server log. The web UI translates each code.
const (
	FailInternal            = "internal_error"
	FailPolicyRestricted    = "ai_policy_restricted"
	FailNotConfigured       = "provider_not_configured"
	FailRateLimited         = "provider_rate_limited"
	FailAuth                = "provider_auth_failed"
	FailQuota               = "provider_quota_exceeded"
	FailTimeout             = "provider_timeout"
	FailUnavailable         = "provider_unavailable"
	FailContentBlocked      = "content_blocked"
	FailInputTooLarge       = "input_too_large"
	FailInvalidResponse     = "invalid_response"
	FailEmptyResponse       = "empty_response"
	FailBudgetExhausted     = "budget_exhausted"
	FailBudgetUnavailable   = "budget_unavailable"
	FailTokenLimit          = "token_limit_exceeded"
	FailEnqueue             = "enqueue_failed"
	FailStuck               = "stuck_timeout"
	FailFindingNotAvailable = "finding_not_available"
)

var failureCodes = map[string]bool{
	FailInternal: true, FailPolicyRestricted: true, FailNotConfigured: true, FailRateLimited: true,
	FailAuth: true, FailQuota: true, FailTimeout: true, FailUnavailable: true, FailContentBlocked: true,
	FailInputTooLarge: true, FailInvalidResponse: true, FailEmptyResponse: true, FailBudgetExhausted: true,
	FailBudgetUnavailable: true, FailTokenLimit: true, FailEnqueue: true, FailStuck: true,
	FailFindingNotAvailable: true,
}

// transientFailures are retried by the job queue while attempts are left;
// every other code fails the triage at once.
var transientFailures = map[string]bool{
	FailInternal: true, FailRateLimited: true, FailTimeout: true, FailUnavailable: true,
	FailBudgetUnavailable: true,
}

// PublicFailureCode is the code shown for a stored error. Rows written before
// codes existed may hold raw text; they read as internal_error.
func PublicFailureCode(stored string) string {
	if stored == "" {
		return ""
	}
	if failureCodes[stored] {
		return stored
	}
	return FailInternal
}

// categorizeError maps a provider error to a failure code. The error itself
// is logged by the caller and never stored.
//
//nolint:cyclop // Switch/case for error categorization is naturally branchy.
func categorizeError(err error) string {
	if err == nil {
		return FailInternal
	}
	errLower := strings.ToLower(err.Error())
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(errLower, s) {
				return true
			}
		}
		return false
	}
	switch {
	case errors.Is(err, llm.ErrRateLimited) || has("rate limit", "429"):
		return FailRateLimited
	case has("unauthorized", "401", "invalid api key", "authentication"):
		return FailAuth
	case has("quota", "billing", "insufficient", "exceeded"):
		return FailQuota
	case errors.Is(err, llm.ErrContextCanceled) || has("context", "timeout", "deadline"):
		return FailTimeout
	case has("content_filter", "safety", "blocked"):
		return FailContentBlocked
	case errors.Is(err, llm.ErrTokenLimitExceeded) || has("token"):
		return FailInputTooLarge
	case has("500", "502", "503", "server error"):
		return FailUnavailable
	case errors.Is(err, llm.ErrInvalidResponse) || has("parse", "invalid response"):
		return FailInvalidResponse
	case errors.Is(err, llm.ErrProviderNotConfigured) || has("not configured"):
		return FailNotConfigured
	default:
		return FailUnavailable
	}
}
