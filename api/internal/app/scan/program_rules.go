package scan

// Bug-bounty program rules at trigger (RFC-065 §12). Command delivery
// enforces them for every job; the trigger refuses up front a run whose
// targets belong to programs whose rules conflict, so the person sees why
// instead of a failed job. Program testing windows are scan windows
// (windows.go).

import (
	"context"
	"errors"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ProgramRuleChecker answers the rules a job on targets carries
// (*bountyprogram.Service).
type ProgramRuleChecker interface {
	JobRules(ctx context.Context, tenantID shared.ID, targets []string, now time.Time) (*bp.JobRules, error)
}

// SetProgramRules makes the trigger refuse runs the programs' rules forbid.
func (s *Service) SetProgramRules(c ProgramRuleChecker) { s.programRules = c }

// refuseProgramRules returns bp.ErrRulesConflict for targets whose
// programs' rules conflict. A lookup error is returned too (fail closed: the
// run is not started).
func (s *Service) refuseProgramRules(ctx context.Context, tenantID shared.ID, targets []string) error {
	if s.programRules == nil || len(targets) == 0 {
		return nil
	}
	_, err := s.programRules.JobRules(ctx, tenantID, targets, time.Now())
	if err == nil || errors.Is(err, bp.ErrRulesConflict) {
		return err
	}
	return shared.NewDomainError("PROGRAM_RULES_UNAVAILABLE",
		"the rules of the programs these targets belong to could not be read; try again", shared.ErrValidation)
}
