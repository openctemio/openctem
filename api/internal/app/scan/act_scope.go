package scan

// Scan targets limited to the actor's data scope (research/15 L-06, owner
// decision D9). Architecture: docs/architecture/active-probe-gate.md.

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ActScopeChecker decides which targets and assets an actor may scan
// (*actscope.Checker).
type ActScopeChecker interface {
	Check(ctx context.Context, in actscope.Input) (*actscope.Decision, error)
}

// ErrActScopeUnavailable is returned when a dispatch asks for the act-scope
// check and none is wired. Nothing is dispatched then.
var ErrActScopeUnavailable = errors.New("act-scope check is not configured; nothing dispatched")

// WithActScope limits scan targets to what the actor may act on: scan
// create, update, quick scan and POST /commands refuse a target outside it,
// and a run skips such targets and group members.
func WithActScope(c ActScopeChecker) ServiceOption {
	return func(s *Service) {
		s.actScope = c
	}
}

// maxListedRefusals bounds the targets named in a refusal message.
const maxListedRefusals = 20

// refuseOutOfActScope refuses a target list (scan create, update, quick scan,
// a scan command) when any target is outside the actor's act scope. The
// actor is the request's caller, else fallbackUser.
func (s *Service) refuseOutOfActScope(ctx context.Context, tenantID shared.ID, fallbackUser *shared.ID, targets []string) error {
	return s.refuseOutOfActScopeAwaiting(ctx, tenantID, fallbackUser, targets, nil)
}

// refuseOutOfActScopeAwaiting is refuseOutOfActScope for a scan saved to
// start when its scope is approved: a target in awaiting (covered only by a
// pending entry) is not refused for having no scope entry yet. Every other
// reason (outside the data scope, not an asset for a restricted member)
// still refuses.
func (s *Service) refuseOutOfActScopeAwaiting(ctx context.Context, tenantID shared.ID, fallbackUser *shared.ID, targets []string, awaiting map[string]bool) error {
	if s.actScope == nil || len(targets) == 0 {
		return nil
	}
	d, err := s.actScope.Check(ctx, actscope.Input{TenantID: tenantID, FallbackUser: fallbackUser, Targets: targets})
	if err != nil {
		return fmt.Errorf("act-scope check failed, nothing saved or dispatched: %w", err)
	}
	refusals := make([]scopedom.Refusal, 0, len(d.RefusedTargets))
	for t, reason := range d.RefusedTargets {
		if awaiting[t] && reason == actscope.ReasonNoScopeTarget {
			continue
		}
		r := scopedom.NewRefusal(t, RefusalCodeForActReason(reason), nil, 0)
		r.Message = reason
		refusals = append(refusals, r)
	}
	if len(refusals) == 0 {
		return nil
	}
	return refusalError(refusals)
}

// userIDPtr parses an optional user id.
func userIDPtr(s string) *shared.ID {
	if s == "" {
		return nil
	}
	id, err := shared.IDFromString(s)
	if err != nil {
		return nil
	}
	return &id
}
