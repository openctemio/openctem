package stepup

import (
	"context"
	"sync"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Applied is the rule that admitted an action: what the audit trail records
// next to the action (key step_up).
type Applied struct {
	Tier   Tier   `json:"tier"`
	Mode   Mode   `json:"mode"`
	Window string `json:"window,omitempty"`
}

// RequestState is the step-up state of one request. The authentication
// middleware puts it on the request context; the gates write to it.
//
// One proof may be spent once: when an every_time gate spends the session's
// proof, a later every_time gate in the same request (a route gate followed
// by a service gate) is admitted by the same spend instead of asking again.
type RequestState struct {
	mu      sync.Mutex
	spent   bool
	applied []Applied
}

type requestStateKey struct{}

// WithRequestState returns ctx carrying a new, empty request state.
func WithRequestState(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestStateKey{}, &RequestState{})
}

// StateFrom returns the request state of ctx, or nil.
func StateFrom(ctx context.Context) *RequestState {
	s, _ := ctx.Value(requestStateKey{}).(*RequestState)
	return s
}

// Spent reports whether this request already spent a proof.
func (s *RequestState) Spent() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spent
}

// MarkSpent records that this request spent a proof.
func (s *RequestState) MarkSpent() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.spent = true
	s.mu.Unlock()
}

// Record notes the rule that admitted an action.
func (s *RequestState) Record(a Applied) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.applied = append(s.applied, a)
	s.mu.Unlock()
}

// Strictest returns the most demanding rule that admitted something in this
// request, and false when no gate ran.
func (s *RequestState) Strictest() (Applied, bool) {
	if s == nil {
		return Applied{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.applied) == 0 {
		return Applied{}, false
	}
	best := s.applied[0]
	for _, a := range s.applied[1:] {
		if tierRank(a.Tier) > tierRank(best.Tier) {
			best = a
		}
	}
	return best, true
}

func tierRank(t Tier) int {
	switch t {
	case TierCritical:
		return 2
	case TierSensitive:
		return 1
	default:
		return 0
	}
}

// TieredGate is a shared.RecentAuthGate that also checks a tier other than
// critical (middleware.RecentAuthGate).
type TieredGate interface {
	RequireRecentAuthTier(ctx context.Context, actorID string, tier Tier) error
}

// Require asks gate for actorID's recent re-authentication under tier. A
// gate that does not know tiers checks as critical (never looser).
func Require(ctx context.Context, gate shared.RecentAuthGate, actorID string, tier Tier) error {
	if t, ok := gate.(TieredGate); ok {
		return t.RequireRecentAuthTier(ctx, actorID, tier)
	}
	return gate.RequireRecentAuth(ctx, actorID)
}
