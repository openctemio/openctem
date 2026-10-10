package bountyprogram

// The rules a job carries (RFC-065 §12): the programs whose in-effect
// entries cover the job's targets decide the identification headers, the
// User-Agent and the rate cap. Command delivery asks here for every job
// before a sensor gets it. When testing is allowed (the programs' testing
// windows) is decided by the scan window hold (RFC-067).

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SetRuleScope wires the tenant's scope entries and program exclusions
// (*scope.Service) the rules are matched with.
func (s *Service) SetRuleScope(t scopeauth.Targets) { s.ruleScope = t }

// noProof: matching rules needs coverage, not proof of ownership.
type noProof struct{}

func (noProof) VerifiedDomainNames(context.Context, shared.ID) ([]string, error) { return nil, nil }

// JobRules answers the rules a job on targets carries now: nil when no
// program covers them; bp.ErrRulesConflict when the programs' rules cannot be
// honored together. Any lookup error is returned (the caller withholds the
// job: fail closed).
func (s *Service) JobRules(ctx context.Context, tenantID shared.ID, targets []string, now time.Time) (*bp.JobRules, error) {
	if s.ruleScope == nil {
		return nil, fmt.Errorf("program rules are not configured")
	}
	auth, err := scopeauth.Load(ctx, tenantID, s.ruleScope, noProof{})
	if err != nil {
		return nil, err
	}
	ids := map[shared.ID]bool{}
	var order []shared.ID
	for _, t := range targets {
		for _, id := range auth.ProgramsCovering(t) {
			if !ids[id] {
				ids[id] = true
				order = append(order, id)
			}
		}
	}
	if len(order) == 0 {
		return nil, nil
	}
	programs := make([]*bp.Program, 0, len(order))
	for _, id := range order {
		p, err := s.repo.GetByID(ctx, tenantID, id)
		if err != nil {
			return nil, fmt.Errorf("program %s: %w", id, err)
		}
		programs = append(programs, p)
	}
	return bp.MergeJobRules(programs)
}
