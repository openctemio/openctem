package cirun

import (
	"context"
	"sort"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Known decisions for CI jobs: a finding marked a false positive, a
// duplicate, accepted, or covered by an approved suppression rule is left out
// of the gate (cirun.Decision) and, through KnownFindings, out of the job's
// own output. The platform decides; the job only hides what the platform says
// is decided, and only among the results it uploaded itself.

// SuppressionRules lists a tenant's approved, unexpired suppression rules.
type SuppressionRules interface {
	ListActiveRules(ctx context.Context, tenantID shared.ID) ([]*suppression.Rule, error)
}

// ModuleGuard tells which modules a tenant has turned off.
type ModuleGuard interface {
	TenantDisabledModules(ctx context.Context, tenantID string) map[string]bool
}

// suppressionsModule is the module whose rules the gate applies.
const suppressionsModule = "suppressions"

// SetSuppressionRules makes the gate apply approved suppression rules to the
// findings a run reports, including findings that existed before the rule was
// approved (ingest stamps only new ones). Nil leaves rules to the ingest
// stamp alone.
func (s *Service) SetSuppressionRules(rules SuppressionRules, modules ModuleGuard) {
	s.rules, s.modules = rules, modules
}

// applyActiveRules marks as suppressed every finding an active suppression
// rule of the tenant covers. Rules are matched on the finding's stored tool,
// rule, path and asset; a failure to load them leaves the findings as they
// are (they then count: fail closed).
func (s *Service) applyActiveRules(ctx context.Context, tenantID shared.ID, findings []cirun.RunFinding, assetID shared.ID) {
	if s.rules == nil || len(findings) == 0 {
		return
	}
	if s.modules != nil && s.modules.TenantDisabledModules(ctx, tenantID.String())[suppressionsModule] {
		return
	}
	rules, err := s.rules.ListActiveRules(ctx, tenantID)
	if err != nil {
		s.log.Warn("ci gate: suppression rules not loaded", "error", logger.SanitizeError(err))
		return
	}
	if len(rules) == 0 {
		return
	}
	for i := range findings {
		f := &findings[i]
		if f.Suppressed {
			continue
		}
		m := suppression.FindingMatch{ToolName: f.ToolName, RuleID: f.RuleID, FilePath: f.FilePath, AssetID: assetID}
		for _, r := range rules {
			if r.Matches(m) {
				f.Suppressed = true
				break
			}
		}
	}
}

// KnownFindings returns, for the report a run just uploaded, the results that
// carry a decision the gate honors, by their index in that report, at most
// the configured limit (lowest indexes first), and how many there are in
// all. Only findings on the run's repository are read, so a job learns
// nothing beyond the results it reported. A lookup failure returns none: the
// job then shows every result, which is safe.
func (s *Service) KnownFindings(ctx context.Context, run *cirun.Run, out *ingest.Output) ([]cirun.KnownFinding, int) {
	known := s.allKnownFindings(ctx, run, out)
	total := len(known)
	if limit := s.cfg.knownLimit(); total > limit {
		known = known[:limit]
	}
	return known, total
}

func (s *Service) allKnownFindings(ctx context.Context, run *cirun.Run, out *ingest.Output) []cirun.KnownFinding {
	if run == nil || out == nil || len(out.FingerprintsByIndex) == 0 {
		return nil
	}
	fps := make([]string, 0, len(out.FingerprintsByIndex))
	seen := map[string]bool{}
	for _, list := range out.FingerprintsByIndex {
		for _, fp := range list {
			if !seen[fp] {
				seen[fp] = true
				fps = append(fps, fp)
			}
		}
	}
	findings, err := s.repo.FindingsByFingerprints(ctx, run.TenantID, run.RepositoryAssetID, fps)
	if err != nil {
		s.log.Warn("ci run: known findings not read", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		return nil
	}
	s.applyActiveRules(ctx, run.TenantID, findings, run.RepositoryAssetID)
	now := s.now().UTC()
	byFP := make(map[string]cirun.RunFinding, len(findings))
	for _, f := range findings {
		byFP[f.Fingerprint] = f
	}
	known := []cirun.KnownFinding{}
	for idx, list := range out.FingerprintsByIndex {
		// A result that became several findings is known only when every one
		// of them is decided.
		var k *cirun.KnownFinding
		for _, fp := range list {
			f, ok := byFP[fp]
			d := ""
			if ok {
				d = cirun.Decision(f, now)
			}
			if d == "" {
				k = nil
				break
			}
			if k == nil {
				k = &cirun.KnownFinding{Index: idx, Decision: d, FindingID: f.ID.String()}
				if d == cirun.DecisionAccepted {
					k.ExpiresAt = f.AcceptanceExpiresAt
				}
			}
		}
		if k != nil {
			known = append(known, *k)
		}
	}
	sort.Slice(known, func(a, b int) bool { return known[a].Index < known[b].Index })
	return known
}
