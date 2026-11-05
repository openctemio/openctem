package scan

// Bug-bounty program rules at trigger (RFC-065 §12). Command delivery
// enforces them for every job; the trigger refuses up front a run whose
// targets belong to programs whose rules conflict, so the person sees why
// instead of a failed job. Program testing windows are scan windows
// (windows.go).

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ProgramRuleChecker answers the rules a job on targets carries
// (*bountyprogram.Service).
type ProgramRuleChecker interface {
	JobRules(ctx context.Context, tenantID shared.ID, targets []string, now time.Time) (*bp.JobRules, error)
}

// CodeProgramForbidsEnumeration refuses an enumeration run on targets a bug
// bounty program forbids brute force or automated scanning on.
const CodeProgramForbidsEnumeration = "PROGRAM_FORBIDS_ENUMERATION"

// SetProgramRules makes the trigger refuse runs the programs' rules forbid.
func (s *Service) SetProgramRules(c ProgramRuleChecker) { s.programRules = c }

// refuseProgramRules returns bp.ErrRulesConflict for targets whose
// programs' rules conflict. A lookup error is returned too (fail closed: the
// run is not started).
func (s *Service) refuseProgramRules(ctx context.Context, tenantID shared.ID, targets []string) error {
	return s.refuseProgramRulesFor(ctx, tenantID, targets, false)
}

// refuseProgramRulesFor is refuseProgramRules for a run that enumerates
// (enumerate.*, a brute force): it is also refused when a covering program
// forbids brute force or automated scanning, with the reason.
func (s *Service) refuseProgramRulesFor(ctx context.Context, tenantID shared.ID, targets []string, enumerates bool) error {
	if s.programRules == nil || len(targets) == 0 {
		return nil
	}
	r, err := s.programRules.JobRules(ctx, tenantID, targets, time.Now())
	if err == nil {
		if why := r.EnumerationRefusal(); enumerates && why != "" {
			return shared.NewDomainError(CodeProgramForbidsEnumeration, why, shared.ErrValidation)
		}
		return nil
	}
	if errors.Is(err, bp.ErrRulesConflict) {
		return err
	}
	return shared.NewDomainError("PROGRAM_RULES_UNAVAILABLE",
		"the rules of the programs these targets belong to could not be read; try again", shared.ErrValidation)
}

// scanEnumerates reports whether a single-scanner scan's jobs enumerate
// (commanddom.PayloadEnumerates on what its jobs carry). A workflow scan's
// steps are decided per job at claim.
func scanEnumerates(sc *scan.Scan) bool {
	if sc == nil || sc.ScannerName == "" {
		return false
	}
	raw, err := json.Marshal(map[string]any{payloadKeyScanner: sc.ScannerName, payloadKeyScannerConfig: sc.ScannerConfig})
	if err != nil {
		return false
	}
	return commanddom.PayloadEnumerates(raw)
}

// payloadKeyScanner is the payload key of a job's tool.
const payloadKeyScanner = "scanner"

// payloadKeyScannerConfig is the payload key of a job's tool settings.
const payloadKeyScannerConfig = "scanner_config"
