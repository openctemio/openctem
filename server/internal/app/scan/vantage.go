package scan

// Vantage resolution: zone routing reads the sensors' own DNS answers as
// well as the platform's (split-horizon DNS). Design:
// docs/architecture/scan-zones.md "Vantage resolution".

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/internal/app/scope"
	freshdom "github.com/openctemio/openctem/server/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/server/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// WithVantageAnswers wires the sensors' stored answers into zone routing.
// Without it a name routes by the platform's resolver only.
func WithVantageAnswers(r scanzone.VantageReader) ServiceOption {
	return func(s *Service) { s.vantage = r }
}

// maxVantageLookup bounds the names one routing reads answers for.
const maxVantageLookup = 10000

// zoneRouter is the router over zones for targets: the platform's resolver
// and the tenant's fresh sensor answers (within freshdom.ResolveTTL). A
// failed read is logged and routing goes on with the platform's answers
// only: the answers only add routes, so leaving them out never sends a
// target anywhere it would not have gone.
func (s *Service) zoneRouter(ctx context.Context, tenantID shared.ID, zones []*scanzone.Zone, targets []string) *scanzone.Router {
	r := scanzone.NewRouter(zones, s.zoneResolver)
	if s.vantage == nil || tenantID.IsZero() {
		return r
	}
	names := scanzone.HostNames(targets, maxVantageLookup)
	if len(names) == 0 {
		return r
	}
	answers, err := s.vantage.VantageAnswers(ctx, tenantID, names, time.Now().Add(-freshdom.ResolveTTL))
	if err != nil {
		s.logger.Warn("zone routing: the sensors' answers could not be read; routing by the platform's answers",
			"tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return r
	}
	return r.WithVantage(answers)
}

// ReasonVantageOutOfScope is the reason a name is refused when the private
// address a sensor resolves it to is excluded or rejected.
const ReasonVantageOutOfScope = "a sensor resolves this name to a private address the organization excluded or rejected; it is not scanned"

// vantageScopeRefusals checks the private addresses a sensor's answer
// routed each name by: an answer is never a scope grant. Private space is
// in scope only inside the tenant's scan zones (the router already placed
// each address inside the observing sensor's own zone); here each address
// must also not be excluded nor rejected by the ownership gate. It returns the refused targets with their reason. Any failed
// lookup refuses every such target (fail closed).
func (s *Service) vantageScopeRefusals(ctx context.Context, tenantID shared.ID, routes []scanzone.Route) (map[string]string, error) {
	addrsOf := map[string][]string{}
	var all []string
	seen := map[string]bool{}
	for _, rt := range routes {
		if rt.Vantage == nil || rt.Zone == nil {
			continue
		}
		for _, a := range rt.Addrs {
			if !scanzone.IsPrivate(a) {
				continue
			}
			v := a.String()
			addrsOf[rt.Target] = append(addrsOf[rt.Target], v)
			if !seen[v] {
				seen[v] = true
				all = append(all, v)
			}
		}
	}
	if len(all) == 0 {
		return nil, nil
	}
	if s.attributionGate == nil || s.scopeExclusions == nil {
		return nil, ErrAttributionGateUnavailable
	}
	bad := map[string]bool{}
	blocked, err := s.attributionGate.BlockedTargets(ctx, tenantID, all)
	if err != nil {
		return nil, fmt.Errorf("ownership check of the sensors' answers failed: %w", err)
	}
	for a := range blocked {
		bad[a] = true
	}
	cands := make([]scope.ExclusionCandidate, 0, len(all))
	byID := map[shared.ID]string{}
	for _, a := range all {
		id := shared.NewID()
		byID[id] = a
		cands = append(cands, scope.ExclusionCandidate{ID: id, Values: []string{a}})
	}
	excluded, err := s.scopeExclusions.ExcludedTargets(ctx, tenantID.String(), cands)
	if err != nil {
		return nil, fmt.Errorf("exclusion check of the sensors' answers failed: %w", err)
	}
	for id, yes := range excluded {
		if yes {
			bad[byID[id]] = true
		}
	}
	out := map[string]string{}
	for t, addrs := range addrsOf {
		for _, a := range addrs {
			if bad[a] {
				out[t] = ReasonVantageOutOfScope
				break
			}
		}
	}
	return out, nil
}

// vantageRefusal is the refused-target entry of a name vantageScopeRefusals
// refused.
func vantageRefusal(target, reason string) RefusedTarget {
	return RefusedTarget{Target: target, Reason: reason, Code: scopedom.RefusalVantageOutOfScope}
}

// vantageNote is the routing note of a name a sensor's answer placed, for
// logs and the run's routing record: never quotes the private answer.
func vantageNote(rt scanzone.Route) string {
	if rt.Vantage == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("resolved by sensor " + rt.Vantage.Observer.String())
	if rt.Vantage.SplitHorizon {
		b.WriteString("; the platform resolves it to other addresses (split-horizon DNS)")
	}
	return b.String()
}
