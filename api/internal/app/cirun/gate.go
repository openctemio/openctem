package cirun

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EvaluateInput is what the runner tells the gate about its own run.
type EvaluateInput struct {
	// ScanFailures counts scanners that failed to run or to report. Any
	// failure fails the gate (fail closed).
	ScanFailures int
	ClientIP     string
	UserAgent    string
}

// Verdict is a gate verdict with its links.
type Verdict struct {
	RunID string `json:"run_id"`
	cirun.GateVerdict
	Links VerdictLinks `json:"links"`
}

// VerdictLinks point to the run and its findings in the web console.
type VerdictLinks struct {
	Run      string `json:"run"`
	Findings string `json:"findings"`
}

// ResolvePolicy picks the policy for a repository asset: its own, else the
// strictest of its business units', else the tenant's, else the built-in
// default.
func (s *Service) ResolvePolicy(ctx context.Context, tenantID, assetID shared.ID) (cirun.GatePolicy, string, error) {
	ps, err := s.repo.GatePoliciesFor(ctx, tenantID, assetID)
	if err != nil {
		return cirun.GatePolicy{}, "", fmt.Errorf("load gate policies: %w", err)
	}
	var units []cirun.GatePolicy
	var tenant *cirun.GatePolicy
	for i := range ps {
		switch ps[i].ScopeType {
		case cirun.ScopeRepository:
			return ps[i], cirun.ScopeRepository, nil
		case cirun.ScopeBusinessUnit:
			units = append(units, ps[i])
		case cirun.ScopeTenant:
			tenant = &ps[i]
		}
	}
	switch {
	case len(units) > 0:
		return cirun.Strictest(units), cirun.ScopeBusinessUnit, nil
	case tenant != nil:
		return *tenant, cirun.ScopeTenant, nil
	}
	return cirun.DefaultGatePolicy(), cirun.ScopeDefault, nil
}

// Evaluate judges the run against the policy and stores the verdict.
func (s *Service) Evaluate(ctx context.Context, run *cirun.Run, in EvaluateInput) (*Verdict, error) {
	if in.ScanFailures < 0 {
		in.ScanFailures = 0
	}
	policy, source, err := s.ResolvePolicy(ctx, run.TenantID, run.RepositoryAssetID)
	if err != nil {
		return nil, err
	}
	findings, err := s.repo.RunFindings(ctx, run.TenantID, run.ID, run.RepositoryAssetID)
	if err != nil {
		return nil, fmt.Errorf("load run findings: %w", err)
	}
	newSet, baselineBranch, known, err := s.newFindings(ctx, run, findings)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	// A break-glass is granted per commit; a commit the job reported (its
	// provider signs none) could name any commit, so it never matches one.
	var override *cirun.GateOverride
	if run.CommitVerified {
		if override, err = s.repo.ActiveOverride(ctx, run.TenantID, run.RepositoryAssetID, run.CommitSHA, now); err != nil {
			return nil, fmt.Errorf("load gate override: %w", err)
		}
	}
	gv := cirun.Evaluate(cirun.GateInput{
		Policy: policy, PolicySource: source, Findings: findings, NewFingerprints: newSet,
		BaselineBranch: baselineBranch, BaselineKnown: known, ScanFailures: in.ScanFailures,
		Override: override, Now: now, FindingURL: s.findingURL,
	})
	v := &Verdict{RunID: run.ID.String(), GateVerdict: gv, Links: VerdictLinks{
		Run:      s.webURL("/ci-runners/" + run.ID.String()),
		Findings: s.webURL(gateFindingsPath(run)),
	}}
	detail, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if err := s.repo.RecordRunOutcome(ctx, run.TenantID, run.ID, in.ScanFailures); err != nil {
		return nil, fmt.Errorf("save run outcome: %w", err)
	}
	if err := s.repo.SaveVerdict(ctx, run.TenantID, run.ID, gv.Verdict, detail, now); err != nil {
		return nil, fmt.Errorf("save verdict: %w", err)
	}
	s.refreshPipeline(ctx, run.TenantID, run.PipelineID)
	s.auditVerdict(ctx, run, in, v)
	return v, nil
}

// gateFindingsPath is the findings list the verdict links to: the
// repository's findings, and for a run on a branch that does not count as
// exposure (any non-default run is treated so here) its branch-only findings,
// which the default list leaves out (docs/architecture/branch-only-findings.md).
func gateFindingsPath(run *cirun.Run) string {
	p := "/findings?asset_id=" + run.RepositoryAssetID.String()
	if !run.IsDefaultBranch {
		p += "&branch_only=true"
	}
	return p
}

// newFindings returns the fingerprints the run introduced, the branch it was
// compared with and whether that branch had been scanned. A run on the
// default branch introduced what it detected (or reopened) first; any other
// run introduced what is not open on the default branch.
func (s *Service) newFindings(ctx context.Context, run *cirun.Run, findings []cirun.RunFinding) (map[string]bool, string, bool, error) {
	set := map[string]bool{}
	if run.IsDefaultBranch {
		since := run.CreatedAt.Add(-time.Minute)
		for _, f := range findings {
			if (f.FirstDetectedAt != nil && !f.FirstDetectedAt.Before(since)) ||
				(f.LastReopenedAt != nil && !f.LastReopenedAt.Before(since)) {
				set[f.Fingerprint] = true
			}
		}
		return set, run.Branch, true, nil
	}
	base := run.DefaultBranch
	if s.branches == nil || s.baseline == nil || base == "" {
		return nil, base, false, nil
	}
	br, err := s.branches.GetByName(ctx, run.RepositoryAssetID, base)
	if err != nil || br == nil {
		// The default branch was never scanned: no baseline, everything is
		// new (fail closed).
		return nil, base, false, nil //nolint:nilerr // a missing branch is "no baseline", not a failure
	}
	fps := make([]string, 0, len(findings))
	for _, f := range findings {
		fps = append(fps, f.Fingerprint)
	}
	open, err := s.baseline.FingerprintsOpenOnBranch(ctx, run.TenantID, br.ID(), fps)
	if err != nil {
		return nil, base, false, fmt.Errorf("read baseline: %w", err)
	}
	onBase := make(map[string]bool, len(open))
	for _, fp := range open {
		onBase[fp] = true
	}
	for _, fp := range fps {
		if !onBase[fp] {
			set[fp] = true
		}
	}
	return set, base, true, nil
}

func (s *Service) webURL(path string) string {
	return strings.TrimRight(s.cfg.WebBaseURL, "/") + path
}

func (s *Service) findingURL(id shared.ID) string { return s.webURL("/findings/" + id.String()) }

func (s *Service) auditVerdict(ctx context.Context, run *cirun.Run, in EvaluateInput, v *Verdict) {
	actor := Actor{Email: ciActor(cirun.Claims{Provider: run.Provider, Actor: run.Actor}), IP: in.ClientIP, UserAgent: in.UserAgent}
	ev := auditapp.NewSuccessEvent(auditdom.ActionCIRunEvaluated, auditdom.ResourceTypeCIRun, run.ID.String()).
		WithResourceName(run.Repository).
		WithMessage(fmt.Sprintf("CI gate %s for %s at %s (%d blocking)", v.Verdict, run.Repository, shortSHA(run.CommitSHA), v.Summary.Blocking)).
		WithMetadata("verdict", v.Verdict).
		WithMetadata("would_fail", v.WouldFail).
		WithMetadata("policy_source", v.Policy.Source).
		WithMetadata("blocking", v.Summary.Blocking).
		WithMetadata("new", v.Summary.New).
		WithMetadata("accepted", v.Summary.Accepted).
		WithMetadata("scan_failures", in.ScanFailures).
		WithMetadata("commit_sha", run.CommitSHA).
		WithMetadata("pipeline_run_id", run.ExternalRunID)
	if v.Verdict == cirun.VerdictFail {
		ev = ev.WithSeverity(auditdom.SeverityMedium)
	}
	s.logAudit(ctx, run.TenantID, actor, ev)
	if v.Override != nil {
		s.logAudit(ctx, run.TenantID, actor,
			auditapp.NewSuccessEvent(auditdom.ActionCIGateOverrideUsed, auditdom.ResourceTypeCIGateOverride, v.Override.ID).
				WithResourceName(run.Repository).
				WithMessage(fmt.Sprintf("Break-glass let %s at %s pass the CI gate with %d blocking finding(s)",
					run.Repository, shortSHA(run.CommitSHA), v.Summary.Blocking)).
				WithMetadata("run_id", run.ID.String()).
				WithMetadata("commit_sha", run.CommitSHA).
				WithMetadata("blocking", v.Summary.Blocking))
		var oid *shared.ID
		if id, err := shared.IDFromString(v.Override.ID); err == nil {
			oid = &id
		}
		s.alertAdmins(ctx, run.TenantID, breakGlassAlert(AdminAlert{
			Title: "CI break-glass used: " + run.Repository,
			Body: fmt.Sprintf("Break-glass let %s at %s pass the CI gate with %d blocking finding(s).",
				run.Repository, shortSHA(run.CommitSHA), v.Summary.Blocking),
			URL: "/ci-runners/" + run.ID.String(), Aggregate: "ci_gate_override", AggregateID: oid,
			Metadata: map[string]any{"action": "used", "repository": run.Repository, "commit_sha": run.CommitSHA,
				"run_id": run.ID.String(), "blocking": v.Summary.Blocking},
		}))
	}
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// BaselineDiffOutput splits fingerprints into new and pre-existing.
type BaselineDiffOutput struct {
	New             []string `json:"new"`
	PreExisting     []string `json:"pre_existing"`
	BaseBranch      string   `json:"base_branch"`
	BaseBranchKnown bool     `json:"base_branch_known"`
}

// maxBaselineFingerprints bounds one baseline request.
const maxBaselineFingerprints = 10_000

// BaselineDiff tells the runner which of its fingerprints are already open
// on the default branch (for inline comments on new findings only). The
// repository and branch are the run's, never the request's.
func (s *Service) BaselineDiff(ctx context.Context, run *cirun.Run, fingerprints []string) (*BaselineDiffOutput, error) {
	if len(fingerprints) > maxBaselineFingerprints {
		return nil, fmt.Errorf("%w: at most %d fingerprints", shared.ErrValidation, maxBaselineFingerprints)
	}
	out := &BaselineDiffOutput{New: append([]string{}, fingerprints...), PreExisting: []string{}, BaseBranch: run.DefaultBranch}
	if len(fingerprints) == 0 || s.branches == nil || s.baseline == nil || run.DefaultBranch == "" {
		return out, nil
	}
	br, err := s.branches.GetByName(ctx, run.RepositoryAssetID, run.DefaultBranch)
	if err != nil || br == nil {
		return out, nil //nolint:nilerr // an unscanned default branch means everything is new
	}
	open, err := s.baseline.FingerprintsOpenOnBranch(ctx, run.TenantID, br.ID(), fingerprints)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	pre := make(map[string]bool, len(open))
	for _, fp := range open {
		pre[fp] = true
	}
	out.New = out.New[:0]
	for _, fp := range fingerprints {
		if pre[fp] {
			out.PreExisting = append(out.PreExisting, fp)
		} else {
			out.New = append(out.New, fp)
		}
	}
	out.BaseBranchKnown = true
	return out, nil
}
