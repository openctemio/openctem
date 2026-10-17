package cirun

// Posting a run's verdict to GitHub: the "OpenCTEM gate" check run on the
// commit and one summary comment on the pull request
// (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md, section 3).
//
// The check is what branch protection can require: it is posted by the
// platform with the organization's GitHub App installation, never by the job,
// so a pull request cannot skip or forge it by editing its workflow. Branch
// protection must pin the check's source to the OpenCTEM app, or any token
// that may write checks (a workflow's own) could post one with the same
// name.
//
// The check of a commit is judged over every pipeline's latest verdict on
// that commit (CommitVerdicts), not only the run being posted: the code host
// keeps the latest check of a name, so judging one run at a time would let a
// second workflow, added by the pull request, replace a failing check with
// a passing one.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	scmappsvc "github.com/openctemio/openctem/api/internal/app/scmapp"
	"github.com/openctemio/openctem/api/internal/infra/scm/githubapp"
	"github.com/openctemio/openctem/api/internal/infra/scm/gitlabapi"
	"github.com/openctemio/openctem/api/pkg/brand"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/scmapp"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CheckName is the check run branch protection requires.
const CheckName = "OpenCTEM gate"

// Check run conclusions.
const (
	conclusionSuccess = "success"
	conclusionFailure = "failure"
	conclusionNeutral = "neutral"
	// conclusionActionRequired: only a scanner failure fails the gate; the
	// run must be fixed and run again, nothing in the code was judged.
	conclusionActionRequired = "action_required"
)

// GitHubPoster posts to GitHub with an installation (githubapp.App).
type GitHubPoster interface {
	CreateCheckRun(ctx context.Context, installationID int64, owner, repo string, c githubapp.CheckRun) error
	GetPullRequest(ctx context.Context, installationID int64, owner, repo string, number int) (*githubapp.PullRequest, error)
	UpsertIssueComment(ctx context.Context, installationID int64, owner, repo string, number int, marker, body string) error
	PullRequestsForCommit(ctx context.Context, installationID int64, owner, repo, sha string) ([]githubapp.PullRequest, error)
	CommitParents(ctx context.Context, installationID int64, owner, repo, sha string) ([]string, error)
}

// InstallationFinder finds the tenant's installation on an account.
type InstallationFinder interface {
	ActiveForAccount(ctx context.Context, tenantID shared.ID, provider, accountLogin string) (*scmapp.Installation, error)
}

// DecorationRepository queues runs to post.
type DecorationRepository interface {
	ClaimDecorations(ctx context.Context, limit int) ([]cirun.Run, error)
	FinishDecoration(ctx context.Context, tenantID, runID shared.ID, state, detail string) error
	// CommitVerdicts returns the latest evaluated verdict of each pipeline
	// on any of the commits of the repository.
	CommitVerdicts(ctx context.Context, tenantID, assetID shared.ID, shas []string) ([]cirun.CommitVerdict, error)
	// PullRequestPassed reports whether the last evaluated run of a pull
	// request on the repository passed the gate.
	PullRequestPassed(ctx context.Context, tenantID, assetID shared.ID, pullRequest string) (bool, error)
}

// GitLabClients opens the tenant's GitLab connection for a project
// (scmapp.Service).
type GitLabClients interface {
	GitLabClientFor(ctx context.Context, tenantID shared.ID, host, projectPath string) (scmappsvc.GitLabAPI, int64, error)
}

// DecorationJob posts queued verdicts.
type DecorationJob struct {
	notifier Notifier
	gitlab   GitLabClients
	repo     DecorationRepository
	installs InstallationFinder
	github   GitHubPoster
	webBase  string
	log      *logger.Logger
}

// NewDecorationJob creates the job. webBase is the console URL for links.
func NewDecorationJob(repo DecorationRepository, installs InstallationFinder, github GitHubPoster, webBase string, log *logger.Logger) *DecorationJob {
	if log == nil {
		log = logger.NewNop()
	}
	return &DecorationJob{repo: repo, installs: installs, github: github, webBase: strings.TrimRight(webBase, "/"),
		log: log.With("job", "ci-decoration")}
}

// SetNotifier enables the ungated-merge alert.
func (j *DecorationJob) SetNotifier(n Notifier) { j.notifier = n }

// SetGitLab enables posting GitLab commit statuses and merge request notes.
func (j *DecorationJob) SetGitLab(g GitLabClients) { j.gitlab = g }

// decorationBatch bounds one pass.
const decorationBatch = 20

// Run posts up to one batch and returns how many runs it handled.
func (j *DecorationJob) Run(ctx context.Context) (int, error) {
	runs, err := j.repo.ClaimDecorations(ctx, decorationBatch)
	if err != nil {
		return 0, fmt.Errorf("claim CI decorations: %w", err)
	}
	for i := range runs {
		run := &runs[i]
		state, detail := j.decorate(ctx, run)
		if err := j.repo.FinishDecoration(ctx, run.TenantID, run.ID, state, detail); err != nil {
			j.log.Warn("ci decoration state not saved", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		}
	}
	return len(runs), nil
}

// GitHubRepository splits a repository asset name "github.com/owner/name".
func GitHubRepository(name string) (owner, repo string, ok bool) {
	rest, found := strings.CutPrefix(strings.ToLower(name), "github.com/")
	if !found {
		return "", "", false
	}
	owner, repo, found = strings.Cut(rest, "/")
	if !found || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", "", false
	}
	return owner, repo, true
}

func (j *DecorationJob) decorate(ctx context.Context, run *cirun.Run) (string, string) {
	owner, repo, ok := GitHubRepository(run.Repository)
	if !ok {
		if run.Provider == cirun.ProviderGitLab {
			return j.decorateGitLab(ctx, run)
		}
		return cirun.DecorationSkipped, "not a github.com repository"
	}
	if j.github == nil {
		return cirun.DecorationSkipped, "this deployment has no GitHub App"
	}
	inst, err := j.installs.ActiveForAccount(ctx, run.TenantID, scmapp.ProviderGitHub, owner)
	if errors.Is(err, scmapp.ErrNotFound) {
		return cirun.DecorationSkipped, "no GitHub App installation for " + owner
	}
	if err != nil {
		return cirun.DecorationRetry, "installation lookup failed"
	}
	var v Verdict
	if len(run.VerdictDetail) == 0 || json.Unmarshal(run.VerdictDetail, &v) != nil {
		return cirun.DecorationFailed, "the stored verdict cannot be read"
	}

	sha, prNumber := "", 0
	if run.PullRequest != "" {
		n, err := strconv.Atoi(run.PullRequest)
		if err != nil || n <= 0 {
			return cirun.DecorationSkipped, "no pull request number"
		}
		pr, err := j.github.GetPullRequest(ctx, inst.InstallationID, owner, repo, n)
		if err != nil {
			return outcome(err, "read the pull request")
		}
		// The run judged the pull request's merge commit (or its head); a
		// pull request that moved on since gets its check from its next run.
		// This is also what stops a run from putting its verdict on another
		// pull request's commit: the head comes from GitHub, not the job.
		if !strings.EqualFold(pr.MergeCommitSHA, run.CommitSHA) && !strings.EqualFold(pr.Head.SHA, run.CommitSHA) {
			// GitHub recomputes the merge commit when the base branch moves;
			// a run that judged the same head merged into an older base
			// still decides the head (the parents come from GitHub).
			ok, err := j.mergeOfHead(ctx, inst.InstallationID, owner, repo, run.CommitSHA, pr.Head.SHA)
			if err != nil {
				return outcome(err, "read the run's commit")
			}
			if !ok {
				return cirun.DecorationSkipped, "the pull request has newer commits"
			}
		}
		sha, prNumber = pr.Head.SHA, n
	} else {
		if !run.CommitVerified || run.CommitSHA == "" {
			return cirun.DecorationSkipped, "no verified commit"
		}
		// A fork event (pull_request_target, workflow_run) carries the base
		// branch's commit but judged code the fork chose: its verdict never
		// goes on the base commit, where it would satisfy a required check.
		if run.Fork {
			return cirun.DecorationSkipped, "a fork event's verdict is not posted on the base commit"
		}
		sha = run.CommitSHA
	}

	others, err := j.otherFailures(ctx, run, sha)
	if err != nil {
		return cirun.DecorationRetry, "could not read the other verdicts on the commit"
	}
	runURL := j.webBase + RunPath(run.ID)
	if err := j.github.CreateCheckRun(ctx, inst.InstallationID, owner, repo, buildCheckRun(run, &v, sha, runURL, others)); err != nil {
		return outcome(err, "post the check run")
	}
	if prNumber == 0 && run.IsDefaultBranch && !run.Fork {
		j.checkUngatedMerge(ctx, run, inst.InstallationID, owner, repo, sha)
	}
	if prNumber > 0 {
		marker := commentMarker(run)
		if err := j.github.UpsertIssueComment(ctx, inst.InstallationID, owner, repo, prNumber, marker,
			buildComment(run, &v, runURL, marker, others)); err != nil {
			return outcome(err, "post the pull request comment")
		}
	}
	return cirun.DecorationPosted, ""
}

// mergeOfHead reports whether commit is a merge commit with head among its
// parents, as GitHub reports them.
func (j *DecorationJob) mergeOfHead(ctx context.Context, installationID int64, owner, repo, commit, head string) (bool, error) {
	if commit == "" || head == "" {
		return false, nil
	}
	parents, err := j.github.CommitParents(ctx, installationID, owner, repo, commit)
	var se *githubapp.StatusError
	if errors.As(err, &se) && (se.Status == 404 || se.Status == 422) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(parents) < 2 {
		return false, nil
	}
	for _, p := range parents {
		if strings.EqualFold(p, head) {
			return true, nil
		}
	}
	return false, nil
}

// checkUngatedMerge alerts when the default-branch commit came from a merged
// pull request whose last gate verdict was not a pass (or that was never
// judged): the merge did not wait for the gate. Best effort: a lookup error
// is logged and the decoration goes on.
func (j *DecorationJob) checkUngatedMerge(ctx context.Context, run *cirun.Run, installationID int64, owner, repo, sha string) {
	if j.notifier == nil {
		return
	}
	prs, err := j.github.PullRequestsForCommit(ctx, installationID, owner, repo, sha)
	if err != nil {
		j.log.Warn("ungated-merge check skipped", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		return
	}
	for _, pr := range prs {
		if pr.MergedAt == nil || *pr.MergedAt == "" || !strings.EqualFold(pr.Base.Ref, run.Branch) {
			continue
		}
		passed, err := j.repo.PullRequestPassed(ctx, run.TenantID, run.RepositoryAssetID, strconv.Itoa(pr.Number))
		if err != nil {
			j.log.Warn("ungated-merge check failed", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
			return
		}
		if passed {
			continue
		}
		aggID, _ := uuid.Parse(run.ID.String())
		if err := j.notifier.Enqueue(ctx, outbox.EnqueueParams{TenantID: run.TenantID,
			EventType: string(integration.EventTypeCIUngatedMerge), AggregateType: "ci_run", AggregateID: &aggID,
			Title: fmt.Sprintf("Merged without a passing CI gate: %s #%d", run.Repository, pr.Number),
			Body: fmt.Sprintf("Pull request #%d of %s was merged into %s at %s, and its last OpenCTEM gate verdict was not a pass. Require the OpenCTEM gate check in branch protection.",
				pr.Number, run.Repository, plain(run.Branch, 100), shortSHA(sha)),
			Severity: "high", URL: RunPath(run.ID),
			Metadata: map[string]any{"repository": run.Repository, "pull_request": pr.Number, "commit_sha": sha,
				"repository_asset_id": run.RepositoryAssetID.String()}}); err != nil {
			j.log.Warn("ungated-merge alert not enqueued", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		}
	}
}

// decorateGitLab sets the "OpenCTEM gate" commit status and one merge
// request note with the tenant's GitLab connection for the project. For a
// merge request the status goes on the merge request's head as GitLab
// reports it, and only when that is the run's verified commit.
func (j *DecorationJob) decorateGitLab(ctx context.Context, run *cirun.Run) (string, string) {
	host, project, found := strings.Cut(strings.ToLower(run.Repository), "/")
	if !found || host == "" || project == "" || j.gitlab == nil {
		return cirun.DecorationSkipped, "no GitLab connection"
	}
	api, authorID, err := j.gitlab.GitLabClientFor(ctx, run.TenantID, host, project)
	if errors.Is(err, scmapp.ErrNotFound) {
		return cirun.DecorationSkipped, "no GitLab connection for this group"
	}
	if err != nil {
		return cirun.DecorationRetry, "GitLab connection unavailable"
	}
	var v Verdict
	if len(run.VerdictDetail) == 0 || json.Unmarshal(run.VerdictDetail, &v) != nil {
		return cirun.DecorationFailed, "the stored verdict cannot be read"
	}
	if !run.CommitVerified || run.CommitSHA == "" {
		return cirun.DecorationSkipped, "no verified commit"
	}
	mrIID := 0
	var pipelineID int64
	if run.PullRequest != "" {
		n, err := strconv.Atoi(run.PullRequest)
		if err != nil || n <= 0 {
			return cirun.DecorationSkipped, "no merge request number"
		}
		mr, err := api.MergeRequest(ctx, project, n)
		if err != nil {
			return gitlabOutcome(err, "read the merge request")
		}
		current, pid := gitlabRunIsCurrent(run, mr)
		if !current {
			return cirun.DecorationSkipped, "the merge request has newer commits"
		}
		mrIID, pipelineID = n, pid
	}
	others, err := j.otherFailures(ctx, run, run.CommitSHA)
	if err != nil {
		return cirun.DecorationRetry, "could not read the other verdicts on the commit"
	}
	state := "success"
	if c := commitConclusion(&v, others); c == conclusionFailure || c == conclusionActionRequired {
		state = "failed"
	}
	runURL := j.webBase + RunPath(run.ID)
	if err := api.SetCommitStatus(ctx, project, run.CommitSHA, state, CheckName, runURL, plain(commitTitle(&v, others), 250), pipelineID); err != nil {
		return gitlabOutcome(err, "set the commit status")
	}
	if mrIID > 0 {
		marker := commentMarker(run)
		if err := api.UpsertMergeRequestNote(ctx, project, mrIID, authorID, marker, buildComment(run, &v, runURL, marker, others)); err != nil {
			return gitlabOutcome(err, "post the merge request note")
		}
	}
	return cirun.DecorationPosted, ""
}

// gitlabRunIsCurrent reports whether a merge request run judged the merge
// request as it stands, and the pipeline its status attaches to. A
// detached merge request pipeline runs on the merge request's head (mr.SHA).
// A merged results pipeline (refs/merge-requests/<n>/merge) runs on a
// commit GitLab made by merging the head into the target, which is never
// mr.SHA: it is current when it is the merge request's head pipeline (same
// pipeline id as the run's, same commit as the run's verified one). Its
// status goes on that commit, attached to that pipeline, which is what the
// merge request shows. A merge train run (/train) is neither and is skipped.
func gitlabRunIsCurrent(run *cirun.Run, mr *gitlabapi.MergeRequest) (bool, int64) {
	if mr == nil {
		return false, 0
	}
	if strings.EqualFold(mr.SHA, run.CommitSHA) {
		return true, 0
	}
	hp := mr.HeadPipeline
	if !strings.HasSuffix(run.Ref, "/merge") || hp == nil || hp.ID <= 0 ||
		strconv.FormatInt(hp.ID, 10) != run.ExternalRunID || !strings.EqualFold(hp.SHA, run.CommitSHA) {
		return false, 0
	}
	return true, hp.ID
}

func gitlabOutcome(err error, what string) (string, string) {
	var se *gitlabapi.StatusError
	if errors.As(err, &se) && (se.Status == 401 || se.Status == 403 || se.Status == 404 || se.Status == 422) {
		return cirun.DecorationFailed, fmt.Sprintf("could not %s: GitLab answered %d", what, se.Status)
	}
	return cirun.DecorationRetry, "could not " + what
}

// outcome maps a GitHub error: a refusal GitHub will repeat (the app has no
// access to the repository, the commit is unknown) is final; a rate limit
// and anything else is retried.
func outcome(err error, what string) (string, string) {
	var se *githubapp.StatusError
	if errors.As(err, &se) && se.RateLimited {
		return cirun.DecorationRetry, fmt.Sprintf("could not %s: GitHub rate limit", what)
	}
	if errors.As(err, &se) && (se.Status == 401 || se.Status == 403 || se.Status == 404 || se.Status == 422) {
		return cirun.DecorationFailed, fmt.Sprintf("could not %s: GitHub answered %d", what, se.Status)
	}
	return cirun.DecorationRetry, "could not " + what
}

// commitFailures says how the other pipelines on the commit went: how many
// failed the gate and how many passed only in warn mode. The run being
// posted is not counted.
type commitFailures struct {
	Failed, WouldFail int
	// FailedURL opens one of the failing runs in the console.
	FailedURL string
}

// otherFailures reads the latest verdict of every pipeline on the run's
// commit (and on the check's commit when that differs: a pull request run
// judges the merge commit, the check goes on the head).
func (j *DecorationJob) otherFailures(ctx context.Context, run *cirun.Run, checkSHA string) (commitFailures, error) {
	var f commitFailures
	shas := []string{run.CommitSHA}
	if checkSHA != "" && !strings.EqualFold(checkSHA, run.CommitSHA) {
		shas = append(shas, checkSHA)
	}
	vs, err := j.repo.CommitVerdicts(ctx, run.TenantID, run.RepositoryAssetID, shas)
	if err != nil {
		return f, err
	}
	for _, v := range vs {
		if v.RunID == run.ID {
			continue
		}
		switch {
		case v.Verdict == cirun.VerdictFail:
			if f.Failed == 0 {
				f.FailedURL = j.webBase + RunPath(v.RunID)
			}
			f.Failed++
		case v.WouldFail:
			f.WouldFail++
		}
	}
	return f, nil
}

// commitConclusion is the strictest of the run's conclusion and the other
// pipelines' verdicts on the commit.
func commitConclusion(v *Verdict, others commitFailures) string {
	c := conclusion(v)
	switch {
	case c == conclusionFailure || others.Failed > 0:
		return conclusionFailure
	case c == conclusionActionRequired:
		return conclusionActionRequired
	case c == conclusionNeutral || others.WouldFail > 0:
		return conclusionNeutral
	}
	return conclusionSuccess
}

// commitTitle is checkTitle, or why another pipeline decides the check.
func commitTitle(v *Verdict, others commitFailures) string {
	if conclusion(v) != conclusionFailure && others.Failed > 0 {
		return fmt.Sprintf("Failed: %d other pipeline(s) on this commit failed the gate", others.Failed)
	}
	return checkTitle(v)
}

// othersMarkdown explains a check decided by another pipeline.
func (f commitFailures) markdown() string {
	if f.Failed == 0 {
		return ""
	}
	return fmt.Sprintf("%d other pipeline(s) on this commit failed the gate, so the check fails: "+
		"the gate takes the strictest verdict of every pipeline on a commit. [Open a failing run](%s)\n\n",
		f.Failed, f.FailedURL)
}

func commentMarker(run *cirun.Run) string {
	key := "default"
	if run.PipelineID != nil {
		key = run.PipelineID.String()
	}
	return "<!-- openctem-gate:" + key + " -->"
}

func conclusion(v *Verdict) string {
	switch {
	case v.Verdict == cirun.VerdictFail && onlyScanFailures(v):
		return conclusionActionRequired
	case v.Verdict == cirun.VerdictFail:
		return conclusionFailure
	case v.WouldFail:
		return conclusionNeutral
	default:
		return conclusionSuccess
	}
}

// onlyScanFailures reports whether the blocking reasons are scanner
// failures only: no finding blocked.
func onlyScanFailures(v *Verdict) bool {
	scan := false
	for _, r := range v.Reasons {
		switch {
		case r.Code == cirun.ReasonScanFailure:
			scan = true
		case r.Mode == "" && isBlockingCode(r.Code):
			return false
		}
	}
	return scan
}

func checkTitle(v *Verdict) string {
	switch conclusion(v) {
	case conclusionActionRequired:
		return "Action required: a scanner failed, the run could not be judged"
	case conclusionFailure:
		return fmt.Sprintf("Failed: %d blocking finding(s)", v.Summary.Blocking)
	case conclusionNeutral:
		return fmt.Sprintf("Passed in warn mode: %d finding(s) would block", v.Summary.Blocking)
	}
	return "Passed"
}

func buildCheckRun(run *cirun.Run, v *Verdict, sha, runURL string, others commitFailures) githubapp.CheckRun {
	c := githubapp.CheckRun{Name: CheckName, HeadSHA: sha, Conclusion: commitConclusion(v, others), DetailsURL: runURL,
		ExternalID: run.ID.String(), Title: commitTitle(v, others),
		Summary: others.markdown() + summaryMarkdown(v, runURL)}
	level := conclusionFailure
	if c.Conclusion != conclusionFailure {
		level = "warning"
	}
	for _, r := range v.Reasons {
		if r.File == "" || r.Line <= 0 || !isBlockingCode(r.Code) {
			continue
		}
		l := level
		if r.Mode == cirun.FindingModeComment {
			// Listed by the policy without failing the gate.
			l = "notice"
		}
		c.Annotations = append(c.Annotations, githubapp.CheckAnnotation{Path: r.File, StartLine: r.Line, EndLine: r.Line,
			AnnotationLevel: l, Title: plain(r.Title, 200), Message: plain(r.Message, 500)})
	}
	return c
}

func isBlockingCode(code string) bool {
	switch code {
	case cirun.ReasonSecret, cirun.ReasonKEV, cirun.ReasonEPSS, cirun.ReasonSeverity:
		return true
	}
	return false
}

func summaryMarkdown(v *Verdict, runURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d finding(s) judged: %d new, %d already on %s, %d accepted, %d blocking.\n\n",
		v.Summary.Evaluated, v.Summary.New, v.Summary.PreExisting, md(nonEmpty(v.Baseline.Branch, "the default branch"), 100),
		v.Summary.Accepted, v.Summary.Blocking)
	fmt.Fprintf(&b, "Policy: %s (%s).\n\n", md(v.Policy.Mode, 20), md(v.Policy.Source, 20))
	writeReasons(&b, v, 20)
	fmt.Fprintf(&b, "\n[Open the run in %s](%s)\n", brand.Name(), runURL)
	return b.String()
}

func writeReasons(b *strings.Builder, v *Verdict, limit int) {
	n := 0
	for _, r := range v.Reasons {
		if n == limit {
			fmt.Fprintf(b, "- and more: see the run\n")
			break
		}
		line := "- **" + md(reasonLabel(r.Code), 40) + "**"
		if r.Mode == cirun.FindingModeComment {
			line += " (not blocking)"
		}
		if r.Severity != "" {
			line += " (" + md(r.Severity, 20) + ")"
		}
		if r.Title != "" {
			line += ": " + md(r.Title, 200)
		} else {
			line += ": " + md(r.Message, 300)
		}
		if r.File != "" {
			loc := r.File
			if r.Line > 0 {
				loc += ":" + strconv.Itoa(r.Line)
			}
			line += " in `" + code(loc, 200) + "`"
		}
		b.WriteString(line + "\n")
		n++
	}
}

func reasonLabel(code string) string {
	switch code {
	case cirun.ReasonSecret:
		return "Secret"
	case "secret_pre_existing":
		return "Secret already on the default branch (rotate it)"
	case cirun.ReasonKEV:
		return "Known exploited"
	case cirun.ReasonEPSS:
		return "EPSS"
	case cirun.ReasonSeverity:
		return "Severity"
	case cirun.ReasonScanFailure:
		return "Scan failure"
	case cirun.ReasonMissingCapability:
		return "Expected scan missing"
	case cirun.ReasonOverride:
		return "Break-glass"
	case cirun.ReasonNoBaseline:
		return "No baseline"
	}
	return code
}

func buildComment(run *cirun.Run, v *Verdict, runURL, marker string, others commitFailures) string {
	var b strings.Builder
	b.WriteString(marker + "\n")
	icon := map[string]string{conclusionFailure: "Failed", conclusionNeutral: "Passed (warn mode)", conclusionSuccess: "Passed",
		conclusionActionRequired: "Action required (a scanner failed)"}[commitConclusion(v, others)]
	fmt.Fprintf(&b, "### %s: %s\n\n", CheckName, icon)
	fmt.Fprintf(&b, "Commit `%s` compared with `%s`.\n\n", code(shortSHA(run.CommitSHA), 12),
		code(nonEmpty(v.Baseline.Branch, "the default branch"), 100))
	b.WriteString(others.markdown())
	b.WriteString(summaryMarkdown(v, runURL))
	return b.String()
}

// md makes scanner or user text safe inside Markdown: one line, control and
// format characters removed, Markdown and HTML punctuation escaped, capped.
func md(s string, n int) string {
	s = plain(s, n)
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune("\\`*_{}[]()#+-.!|<>~@&", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// code makes text safe inside an inline code span (no backticks).
func code(s string, n int) string {
	return strings.ReplaceAll(plain(s, n), "`", "'")
}

// plain is s on one line without control or format characters, capped at n
// runes.
func plain(s string, n int) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count == n {
			b.WriteString("…")
			break
		}
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			continue
		default:
			b.WriteRune(r)
		}
		count++
	}
	return b.String()
}
