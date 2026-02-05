// Package agent defines domain errors for agent-related operations.
package agent

import (
	"errors"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// Agent Errors
// =============================================================================

var (
	// ErrAgentNotFound is returned when an agent is not found.
	ErrAgentNotFound = fmt.Errorf("%w: agent not found", shared.ErrNotFound)

	// ErrAgentAlreadyExists is returned when an agent with the same name exists.
	ErrAgentAlreadyExists = fmt.Errorf("%w: agent already exists", shared.ErrAlreadyExists)

	// ErrAgentDisabled is returned when trying to use a disabled agent.
	ErrAgentDisabled = fmt.Errorf("%w: agent is disabled", shared.ErrForbidden)

	// ErrAgentRevoked is returned when trying to use a revoked agent.
	ErrAgentRevoked = fmt.Errorf("%w: agent access has been revoked", shared.ErrForbidden)

	// ErrAgentLimitReached is returned when the agent limit for a tenant is reached.
	ErrAgentLimitReached = fmt.Errorf("%w: agent limit reached for this plan", shared.ErrForbidden)

	// ErrAgentNoCapacity is returned when an agent has no capacity for more jobs.
	ErrAgentNoCapacity = fmt.Errorf("%w: agent has no capacity for more jobs", shared.ErrConflict)

	// ErrInvalidAPIKey is returned when an API key is invalid.
	ErrInvalidAPIKey = fmt.Errorf("%w: invalid API key", shared.ErrUnauthorized)
)

// =============================================================================
// Platform Agent Errors (v3.2)
// =============================================================================

var (
	// ErrPlatformAgentNotFound is returned when a platform agent is not found.
	ErrPlatformAgentNotFound = fmt.Errorf("%w: platform agent not found", shared.ErrNotFound)

	// ErrNoPlatformAgentAvailable is returned when no platform agent is available.
	ErrNoPlatformAgentAvailable = fmt.Errorf("%w: no platform agent available", shared.ErrConflict)

	// ErrAllPlatformAgentsOverloaded is returned when agents exist but all are at capacity.
	ErrAllPlatformAgentsOverloaded = fmt.Errorf("%w: all platform agents are at capacity", shared.ErrConflict)

	// ErrPlatformAgentAccessDenied is returned when tenant doesn't have platform agent access.
	ErrPlatformAgentAccessDenied = fmt.Errorf("%w: platform agent access not included in plan", shared.ErrForbidden)

	// ErrPlatformConcurrentLimitReached is returned when concurrent platform job limit is reached.
	ErrPlatformConcurrentLimitReached = fmt.Errorf("%w: concurrent platform job limit reached", shared.ErrConflict)

	// ErrPlatformQueueLimitReached is returned when queue limit is reached.
	ErrPlatformQueueLimitReached = fmt.Errorf("%w: platform job queue limit reached", shared.ErrConflict)

	// ErrPlatformJobNotFound is returned when a platform job is not found.
	ErrPlatformJobNotFound = fmt.Errorf("%w: platform job not found", shared.ErrNotFound)

	// ErrInvalidAuthToken is returned when the command auth token is invalid.
	ErrInvalidAuthToken = fmt.Errorf("%w: invalid command auth token", shared.ErrUnauthorized)

	// ErrAuthTokenExpired is returned when the command auth token has expired.
	ErrAuthTokenExpired = fmt.Errorf("%w: command auth token has expired", shared.ErrUnauthorized)

	// ErrAgentMismatch is returned when agent ID doesn't match the command's assigned agent.
	ErrAgentMismatch = fmt.Errorf("%w: agent not authorized for this command", shared.ErrForbidden)
)

// =============================================================================
// Bootstrap Token Errors (v3.2)
// =============================================================================

var (
	// ErrBootstrapTokenNotFound is returned when a bootstrap token is not found.
	ErrBootstrapTokenNotFound = fmt.Errorf("%w: bootstrap token not found", shared.ErrNotFound)

	// ErrBootstrapTokenExpired is returned when a bootstrap token has expired.
	ErrBootstrapTokenExpired = fmt.Errorf("%w: bootstrap token has expired", shared.ErrForbidden)

	// ErrBootstrapTokenRevoked is returned when a bootstrap token has been revoked.
	ErrBootstrapTokenRevoked = fmt.Errorf("%w: bootstrap token has been revoked", shared.ErrForbidden)

	// ErrBootstrapTokenExhausted is returned when a bootstrap token has reached its usage limit.
	ErrBootstrapTokenExhausted = fmt.Errorf("%w: bootstrap token usage limit reached", shared.ErrForbidden)

	// ErrBootstrapTokenInvalid is returned when a bootstrap token is invalid.
	ErrBootstrapTokenInvalid = fmt.Errorf("%w: invalid bootstrap token", shared.ErrUnauthorized)

	// ErrAgentConstraintViolation is returned when agent doesn't meet token constraints.
	ErrAgentConstraintViolation = fmt.Errorf("%w: agent does not meet token constraints", shared.ErrValidation)
)

// =============================================================================
// Error Helpers
// =============================================================================

// IsAgentNotFound checks if the error is an agent not found error.
func IsAgentNotFound(err error) bool {
	return errors.Is(err, ErrAgentNotFound)
}

// IsPlatformAgentNotFound checks if the error is a platform agent not found error.
func IsPlatformAgentNotFound(err error) bool {
	return errors.Is(err, ErrPlatformAgentNotFound)
}

// IsNoPlatformAgentAvailable checks if the error indicates no platform agent is available.
func IsNoPlatformAgentAvailable(err error) bool {
	return errors.Is(err, ErrNoPlatformAgentAvailable)
}

// IsAllPlatformAgentsOverloaded checks if all platform agents are at capacity.
func IsAllPlatformAgentsOverloaded(err error) bool {
	return errors.Is(err, ErrAllPlatformAgentsOverloaded)
}

// IsPlatformLimitReached checks if the error is a platform limit error.
func IsPlatformLimitReached(err error) bool {
	return errors.Is(err, ErrPlatformConcurrentLimitReached) ||
		errors.Is(err, ErrPlatformQueueLimitReached)
}

// IsBootstrapTokenError checks if the error is a bootstrap token error.
func IsBootstrapTokenError(err error) bool {
	return errors.Is(err, ErrBootstrapTokenNotFound) ||
		errors.Is(err, ErrBootstrapTokenExpired) ||
		errors.Is(err, ErrBootstrapTokenRevoked) ||
		errors.Is(err, ErrBootstrapTokenExhausted) ||
		errors.Is(err, ErrBootstrapTokenInvalid)
}

// IsAuthTokenError checks if the error is an auth token error.
func IsAuthTokenError(err error) bool {
	return errors.Is(err, ErrInvalidAuthToken) ||
		errors.Is(err, ErrAuthTokenExpired) ||
		errors.Is(err, ErrAgentMismatch)
}
