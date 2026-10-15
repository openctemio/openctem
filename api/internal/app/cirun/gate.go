package cirun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EvaluateInput is what the runner tells the gate about its own run.
type EvaluateInput struct {
	// ScanFailures counts scanners that failed to run or to report. Any
	// failure fails the gate (fail closed).
	ScanFailures int
	// RepoPolicy is the repository's .openctem.yml (nil without one).
	RepoPolicy *cirun.RepoPolicy
	ClientIP   string
	UserAgent  string
}

// Verdict is a gate verdict with its links.
type Verdict struct {
	RunID string `json:"run_id"`
	cirun.GateVerdict
	// RepoFile says what happened to the repository's .openctem.yml:
	// "applied" (it tightened the policy), "ignored" (the organization's
	// policy does not allow repository files), or empty (none sent).
	RepoFile string       `json:"repo_file,omitempty"`
	Links    VerdictLinks `json:"links"`
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
	p, source := resolveFrom(ps)
	return p, source, nil
}

// resolveFrom picks among enabled policies that may apply to one
// repository: its own, else the strictest business unit's, else the
// tenant's, else the built-in default.
func resolveFrom(ps []cirun.GatePolicy) (cirun.GatePolicy, string) {
	var units []cirun.GatePolicy
	var tenant *cirun.GatePolicy
	for i := range ps {
		switch ps[i].ScopeType {
		case cirun.ScopeRepository:
			return ps[i], cirun.ScopeRepository
		case cirun.ScopeBusinessUnit:
			units = append(units, ps[i])
		case cirun.ScopeTenant:
			tenant = &ps[i]
		}
	}
	switch {
	case len(units) > 0:
		return cirun.Strictest(units), cirun.ScopeBusinessUnit
	case tenant != nil:
		return *tenant, cirun.ScopeTenant
	}
	return cirun.DefaultGatePolicy(), cirun.ScopeDefault
}

// Evaluate judges the run against the policy and stores the verdict.
func (s *Service) Evaluate(ctx context.Context, run *cirun.Run, in EvaluateInput) (*Verdict, error) {
	if in.ScanFailures < 0 {
		in.ScanFailures = 0
	}
	// The first verdict is final: asking again returns it unchanged, so a job
	// cannot turn a stored failure into a pass by evaluating again.
	if run.Status == cirun.StatusEvaluated {
		return s.storedVerdict(ctx, run)
	}
	policy, source, err := s.ResolvePolicy(ctx, run.TenantID, run.RepositoryAssetID)
	if err != nil {
		return nil, err
	}
	repoFile := ""
	if in.RepoPolicy != nil {
		if err := in.RepoPolicy.Validate(s.now().UTC()); err != nil {
			return nil, err
		}
		if policy.AllowRepoPolicy {
			policy = policy.Tighten(in.RepoPolicy)
			repoFile = "applied"
			s.requestRepoExceptions(ctx, run, in.RepoPolicy.Exceptions)
		} else {
			repoFile = "ignored"
		}
	}
	// A report recorded while the verdict is computed would not be in it:
	// SaveVerdict then refuses (ErrRunChanged) and the run is judged again
	// with what it has now.
	for attempt := 1; ; attempt++ {
		v, err := s.judge(ctx, run, in, policy, source, repoFile)
		if errors.Is(err, cirun.ErrRunChanged) && attempt < maxJudgeAttempts {
			fresh, gerr := s.repo.GetRun(ctx, run.TenantID, run.ID)
			if gerr != nil {
				return nil, gerr
			}
			run = fresh
			if run.Status == cirun.StatusEvaluated {
				return s.storedVerdict(ctx, run)
			}
			continue
		}
		return v, err
	}
}

// maxJudgeAttempts bounds how often Evaluate judges a run that keeps
// recording reports; past it the caller gets ErrRunChanged (409) and asks
// again once its uploads are done.
const maxJudgeAttempts = 3

// judge computes the run's verdict and stores it, guarded by the findings
// count the verdict was computed from (run.FindingsCount, read before the
// findings).
func (s *Service) judge(ctx context.Context, run *cirun.Run, in EvaluateInput, policy cirun.GatePolicy, source, repoFile string) (*Verdict, error) {
	findings, err := s.repo.RunFindings(ctx, run.TenantID, run.ID, run.RepositoryAssetID)
	if err != nil {
		return nil, fmt.Errorf("load run findings: %w", err)
	}
	// An approved rule covers findings that existed before it was approved
	// (an exception a repository asked for), not only new ones.
	s.applyActiveRules(ctx, run.TenantID, findings, run.RepositoryAssetID)
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
	// The tools a run reports are self-declared, so this does not prove a
	// scan ran; it stops a pipeline edited to drop a capability the
	// repository is expected to have from passing on silence.
	missing, err := s.repo.MissingExpectedCapabilities(ctx, run.TenantID, run.ID)
	if err != nil {
		return nil, fmt.Errorf("load expected capabilities: %w", err)
	}
	overCap, err := s.repo.RunFindingsOverCap(ctx, run.TenantID, run.ID)
	if err != nil {
		return nil, fmt.Errorf("load run findings cap: %w", err)
	}
	gv := cirun.Evaluate(cirun.GateInput{
		Policy: policy, PolicySource: source, Findings: findings, NewFingerprints: newSet,
		BaselineBranch: baselineBranch, BaselineKnown: known, ScanFailures: in.ScanFailures,
		FindingsOverCap:     overCap,
		MissingCapabilities: missing,
		DefaultBranch:       run.IsDefaultBranch,
		Override:            override, Now: now, FindingURL: s.findingURL,
	})
	v := &Verdict{RunID: run.ID.String(), GateVerdict: gv, RepoFile: repoFile, Links: VerdictLinks{
		Run:      s.webURL(RunPath(run.ID)),
		Findings: s.webURL(gateFindingsPath(run)),
	}}
	detail, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if err := s.repo.SaveVerdict(ctx, run.TenantID, run.ID, gv.Verdict, detail, now, run.FindingsCount); err != nil {
		if errors.Is(err, cirun.ErrRunChanged) {
			return nil, err
		}
		if errors.Is(err, cirun.ErrRunEvaluated) {
			// Another job of the run was judged first.
			return s.storedVerdict(ctx, run)
		}
		return nil, fmt.Errorf("save verdict: %w", err)
	}
	if err := s.repo.RecordRunOutcome(ctx, run.TenantID, run.ID, in.ScanFailures); err != nil {
		return nil, fmt.Errorf("save run outcome: %w", err)
	}
	s.refreshPipeline(ctx, run.TenantID, run.PipelineID)
	s.auditVerdict(ctx, run, in, v)
	return v, nil
}

// RunPath is the console page of a CI run: the runs view of the CI/CD page
// with the run open.
func RunPath(id shared.ID) string { return "/ci-cd?view=runs&run=" + id.String() }

// storedVerdict returns the verdict a run already has.
func (s *Service) storedVerdict(ctx context.Context, run *cirun.Run) (*Verdict, error) {
	stored, err := s.repo.GetRun(ctx, run.TenantID, run.ID)
	if err != nil {
		return nil, fmt.Errorf("load run: %w", err)
	}
	var v Verdict
	if len(stored.VerdictDetail) == 0 || json.Unmarshal(stored.VerdictDetail, &v) != nil {
		return nil, fmt.Errorf("%w: the run's stored verdict cannot be read", cirun.ErrRunEvaluated)
	}
	return &v, nil
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
	brID, base, ok := s.baselineBranch(ctx, run)
	if !ok {
		// The baseline branch was never scanned: no baseline, everything is
		// new (fail closed).
		return nil, base, false, nil
	}
	fps := make([]string, 0, len(findings))
	for _, f := range findings {
		fps = append(fps, f.Fingerprint)
	}
	open, err := s.baseline.FingerprintsOpenOnBranch(ctx, run.TenantID, brID, fps)
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

// baselineBranch picks the branch a run is compared with: the pull or merge
// request's verified base branch when the repository has scanned it and it
// may serve as a baseline (default or protected), else the repository's
// default branch. ok is false when that branch was never scanned. Nothing the
// job reports chooses the baseline (cirun.Hints.BaseRef).
func (s *Service) baselineBranch(ctx context.Context, run *cirun.Run) (shared.ID, string, bool) {
	if s.branches == nil || s.baseline == nil {
		return shared.ID{}, run.DefaultBranch, false
	}
	if base := s.verifiedBaseRef(ctx, run); base != "" && base != run.DefaultBranch {
		if br, err := s.branches.GetByName(ctx, run.RepositoryAssetID, base); err == nil && br != nil {
			if counts, err := s.baseline.BranchCountsAsExposure(ctx, run.TenantID, br.ID()); err == nil && counts {
				return br.ID(), base, true
			}
		}
	}
	if run.DefaultBranch == "" {
		return shared.ID{}, "", false
	}
	br, err := s.branches.GetByName(ctx, run.RepositoryAssetID, run.DefaultBranch)
	if err != nil || br == nil {
		return shared.ID{}, run.DefaultBranch, false
	}
	return br.ID(), run.DefaultBranch, true
}

// verifiedBaseRef is a pull or merge request run's base branch from a
// verified source, "" when there is none:
//   - GitHub: base_ref, signed in the pull request's token (the only claim
//     that fills Run.BaseRef: the job's hint is ignored);
//   - GitLab: the merge request's target branch, read from GitLab through the
//     organization's connection (the token signs none);
//   - other providers: none, so the default branch is the baseline.
func (s *Service) verifiedBaseRef(ctx context.Context, run *cirun.Run) string {
	if run.PullRequest == "" || run.Fork {
		return ""
	}
	switch run.Provider {
	case cirun.ProviderGitHub:
		return run.BaseRef
	case cirun.ProviderGitLab:
		return s.gitlabTargetBranch(ctx, run)
	}
	return ""
}

// gitlabTargetBranch reads a GitLab merge request run's target branch from
// GitLab. Any failure gives "" (compared with the default branch).
func (s *Service) gitlabTargetBranch(ctx context.Context, run *cirun.Run) string {
	if s.gitlab == nil {
		return ""
	}
	host, project, found := strings.Cut(strings.ToLower(run.Repository), "/")
	iid, err := strconv.Atoi(run.PullRequest)
	if !found || host == "" || project == "" || err != nil || iid <= 0 {
		return ""
	}
	api, _, err := s.gitlab.GitLabClientFor(ctx, run.TenantID, host, project)
	if err != nil {
		return ""
	}
	mr, err := api.MergeRequest(ctx, project, iid)
	if err != nil || mr == nil || (mr.IID != 0 && mr.IID != iid) {
		s.log.Debug("ci gate: merge request target not read", "run_id", run.ID.String())
		return ""
	}
	return cirun.CleanBranchName(mr.TargetBranch)
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
			URL: RunPath(run.ID), Aggregate: "ci_gate_override", AggregateID: oid,
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
	if len(fingerprints) == 0 {
		return out, nil
	}
	brID, base, ok := s.baselineBranch(ctx, run)
	out.BaseBranch = base
	if !ok {
		return out, nil // an unscanned baseline means everything is new
	}
	open, err := s.baseline.FingerprintsOpenOnBranch(ctx, run.TenantID, brID, fingerprints)
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

// requestRepoExceptions turns a repository file's exceptions into pending
// suppression requests on the run's repository, from a non-fork
// default-branch run of a verified commit only (the file there was reviewed
// and merged). Duplicates of an open request are skipped. Audited; best
// effort: a failure is logged and never changes the verdict.
func (s *Service) requestRepoExceptions(ctx context.Context, run *cirun.Run, exceptions []cirun.RepoException) {
	if len(exceptions) == 0 || !run.IsDefaultBranch || run.Fork || !run.CommitVerified {
		return
	}
	actor := Actor{Email: ciActor(cirun.Claims{Provider: run.Provider, Actor: run.Actor})}
	created, err := s.repo.RequestRepoExceptions(ctx, run.TenantID, run.RepositoryAssetID, run.Repository, actor.Email, exceptions)
	if err != nil {
		s.log.Warn("repository exceptions not requested", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		return
	}
	if created == 0 {
		return
	}
	from := ".openctem.yml"
	switch exceptions[0].Source {
	case cirun.ExceptionSourceInline:
		from = "inline ignore comments"
	case cirun.ExceptionSourceIgnoreFile:
		from = "a scanner ignore file"
	}
	s.logAudit(ctx, run.TenantID, actor, auditapp.NewSuccessEvent(auditdom.ActionCIRepoExceptionsRequested, auditdom.ResourceTypeCIRun, run.ID.String()).
		WithResourceName(run.Repository).
		WithMessage(fmt.Sprintf("%s requested %d suppression(s) from %s at %s (pending approval)", run.Repository, created, from, shortSHA(run.CommitSHA))).
		WithMetadata("requested", created).
		WithMetadata("source", nonEmptyPrefix("", exceptions[0].Source)).
		WithMetadata("commit_sha", run.CommitSHA))
}
