package scan

// Scan targets limited to the actor's data scope (research/15 L-06, owner
// decision D9). Architecture: docs/architecture/active-probe-gate.md.

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
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
	if s.actScope == nil || len(targets) == 0 {
		return nil
	}
	d, err := s.actScope.Check(ctx, actscope.Input{TenantID: tenantID, FallbackUser: fallbackUser, Targets: targets})
	if err != nil {
		return fmt.Errorf("act-scope check failed, nothing saved or dispatched: %w", err)
	}
	if len(d.RefusedTargets) == 0 {
		return nil
	}
	refusals := make([]scopedom.Refusal, 0, len(d.RefusedTargets))
	for t, reason := range d.RefusedTargets {
		r := scopedom.NewRefusal(t, RefusalCodeForActReason(reason), nil, 0)
		r.Message = reason
		refusals = append(refusals, r)
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

// runActScopeSkips returns the candidates of a run that the actor may not
// scan: direct targets outside the act scope (or, for an unrestricted actor,
// free text matching no scope target) and group members outside the data
// scope. The actor is whoever triggers the run, else the scan owner (a
// scheduled run). Excluded and unconfirmed candidates are already out and are
// not looked up. A failed check stops the run (fail closed).
func (s *Service) runActScopeSkips(ctx context.Context, sc *scan.Scan, candidates []scope.ExclusionCandidate,
	names map[shared.ID]string, memberIDs map[shared.ID]bool, excluded map[shared.ID]bool, blocked map[string]attribution.State,
) (map[shared.ID]bool, error) {
	if s.actScope == nil || len(candidates) == 0 {
		return nil, nil
	}
	in := actscope.Input{TenantID: sc.TenantID, FallbackUser: sc.CreatedBy}
	for _, c := range candidates {
		if excluded[c.ID] {
			continue
		}
		if _, no := blocked[c.ID.String()]; no {
			continue
		}
		if memberIDs[c.ID] {
			in.AssetIDs = append(in.AssetIDs, c.ID)
			continue
		}
		in.Targets = append(in.Targets, names[c.ID])
	}
	if len(in.Targets) == 0 && len(in.AssetIDs) == 0 {
		return nil, nil
	}
	d, err := s.actScope.Check(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("act-scope check failed, scan not dispatched: %w", err)
	}
	out := map[shared.ID]bool{}
	for _, c := range candidates {
		if memberIDs[c.ID] {
			if d.RefusedAssets[c.ID] {
				out[c.ID] = true
			}
			continue
		}
		if _, no := d.RefusedTargets[names[c.ID]]; no {
			out[c.ID] = true
		}
	}
	return out, nil
}
