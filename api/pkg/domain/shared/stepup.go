package shared

import "context"

// RecentAuthGate requires that actorID, when it is the user making the
// current request, authenticated recently (step-up re-authentication,
// docs/architecture/step-up-reauth.md). Services call it for actions that
// need step-up only in some cases; the HTTP implementation is
// middleware.RecentAuthGate, whose refusals handlers answer with
// middleware.WriteStepUpError.
type RecentAuthGate interface {
	RequireRecentAuth(ctx context.Context, actorID string) error
}
