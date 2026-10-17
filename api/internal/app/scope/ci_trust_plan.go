package scope

// The dry run of the CI trust scope backfill (ci_trust.go).

import (
	"context"
	"fmt"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PlanCITrust answers what SyncCITrust would do for the trust, without
// writing anything (the backfill's dry run).
func (s *Service) PlanCITrust(ctx context.Context, tenantID shared.ID, in CITrustScope) ([]scopedom.CITrustSyncOutcome, error) {
	if s.ciTrustLinks == nil {
		return nil, ErrCITrustLinksNotWired
	}
	links, err := s.ciTrustLinks.ListByTrust(ctx, tenantID, in.TrustID)
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	var want []string
	for _, p := range in.Patterns {
		if p = scopedom.NormalizeRepositoryPattern(p); p != "" && !wanted[p] {
			wanted[p] = true
			want = append(want, p)
		}
	}
	out := make([]scopedom.CITrustSyncOutcome, 0, len(want)+len(links))
	have := map[string]scopedom.CITrustLink{}
	for _, l := range links {
		if wanted[l.Pattern] {
			have[l.Pattern] = l
		} else {
			out = append(out, scopedom.CITrustSyncOutcome{Pattern: l.Pattern, Action: scopedom.CITrustRetired, TargetID: l.TargetID})
		}
	}
	g := scopedom.DefaultGuardrails()
	if s.guardrails != nil {
		g = *s.guardrails
	}
	for _, p := range want {
		if l, ok := have[p]; ok {
			action := scopedom.CITrustKept
			if l.TargetID == nil {
				action = scopedom.CITrustRemoved
			}
			out = append(out, scopedom.CITrustSyncOutcome{Pattern: p, Action: action, TargetID: l.TargetID})
			continue
		}
		existing, err := s.targetRepo.FindByPattern(ctx, tenantID, scopedom.TargetTypeRepository, p)
		if err != nil {
			return out, fmt.Errorf("find scope entry: %w", err)
		}
		if existing != nil {
			id := existing.ID
			out = append(out, scopedom.CITrustSyncOutcome{Pattern: p, Action: scopedom.CITrustLinked, TargetID: &id})
			continue
		}
		if err := scopedom.ValidatePattern(scopedom.TargetTypeRepository, p); err != nil {
			out = append(out, scopedom.CITrustSyncOutcome{Pattern: p, Action: scopedom.CITrustRefused, Err: err})
			continue
		}
		if err := g.CheckPattern(scopedom.TargetTypeRepository, p); err != nil {
			out = append(out, scopedom.CITrustSyncOutcome{Pattern: p, Action: scopedom.CITrustRefused, Err: err})
			continue
		}
		out = append(out, scopedom.CITrustSyncOutcome{Pattern: p, Action: scopedom.CITrustCreated})
	}
	return out, nil
}
