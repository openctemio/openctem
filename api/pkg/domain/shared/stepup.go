package shared

import (
	"context"
	"time"
)

// StepUpError refuses an action until the acting user re-authenticates
// (docs/architecture/step-up-reauth.md). It is a forbidden error, so a
// handler that does not know it still answers 403.
type StepUpError struct {
	// Unavailable: this credential cannot step up (an API key, a token
	// without a session or without auth_time).
	Unavailable bool
	// Window is how long a re-authentication unlocks such actions.
	Window  time.Duration
	Message string
}

func (e *StepUpError) Error() string { return "forbidden: " + e.Message }

// Unwrap makes errors.Is(err, ErrForbidden) hold.
func (e *StepUpError) Unwrap() error { return ErrForbidden }

// RecentAuthGate requires that actorID, when it is the user making the
// current request, authenticated recently. Services call it for actions that
// need step-up only in some cases; it returns nil or a *StepUpError.
type RecentAuthGate interface {
	RequireRecentAuth(ctx context.Context, actorID string) error
}
