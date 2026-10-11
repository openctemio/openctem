package cirun

// Posting a run's verdict to GitHub: the "OpenCTEM gate" check run on the
// commit and one summary comment on the pull request
// (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md, section 3).
//
// The check is what branch protection can require: it is posted by the
// platform with the organization's GitHub App installation, never by the job,
// so a pull request cannot skip or forge it by editing its workflow.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/openctemio/openctem/api/internal/infra/scm/githubapp"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
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
)

// GitHubPoster posts to GitHub with an installation (githubapp.App).
type GitHubPoster interface {
	CreateCheckRun(ctx context.Context, installationID int64, owner, repo string, c githubapp.CheckRun) error
	GetPullRequest(ctx context.Context, installationID int64, owner, repo string, number int) (*githubapp.PullRequest, error)
	UpsertIssueComment(ctx context.Context, installationID int64, owner, repo string, number int, marker, body string) error
}

// InstallationFinder finds the tenant's installation on an account.
type InstallationFinder interface {
	ActiveForAccount(ctx context.Context, tenantID shared.ID, provider, accountLogin string) (*scmapp.Installation, error)
}

// DecorationRepository queues runs to post.
type DecorationRepository interface {
	ClaimDecorations(ctx context.Context, limit int) ([]cirun.Run, error)
	FinishDecoration(ctx context.Context, tenantID, runID shared.ID, state, detail string) error
}

// DecorationJob posts queued verdicts.
type DecorationJob struct {
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
		return cirun.DecorationSkipped, "not a github.com repository"
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
			return cirun.DecorationSkipped, "the pull request has newer commits"
		}
		sha, prNumber = pr.Head.SHA, n
	} else {
		if !run.CommitVerified || run.CommitSHA == "" {
			return cirun.DecorationSkipped, "no verified commit"
		}
		sha = run.CommitSHA
	}

	runURL := j.webBase + RunPath(run.ID)
	if err := j.github.CreateCheckRun(ctx, inst.InstallationID, owner, repo, buildCheckRun(run, &v, sha, runURL)); err != nil {
		return outcome(err, "post the check run")
	}
	if prNumber > 0 {
		marker := commentMarker(run)
		if err := j.github.UpsertIssueComment(ctx, inst.InstallationID, owner, repo, prNumber, marker,
			buildComment(run, &v, runURL, marker)); err != nil {
			return outcome(err, "post the pull request comment")
		}
	}
	return cirun.DecorationPosted, ""
}

// outcome maps a GitHub error: a refusal GitHub will repeat (the app has no
// access to the repository, the commit is unknown) is final; anything else
// is retried.
func outcome(err error, what string) (string, string) {
	var se *githubapp.StatusError
	if errors.As(err, &se) && (se.Status == 401 || se.Status == 403 || se.Status == 404 || se.Status == 422) {
		return cirun.DecorationFailed, fmt.Sprintf("could not %s: GitHub answered %d", what, se.Status)
	}
	return cirun.DecorationRetry, "could not " + what
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
	case v.Verdict == cirun.VerdictFail:
		return conclusionFailure
	case v.WouldFail:
		return conclusionNeutral
	default:
		return conclusionSuccess
	}
}

func checkTitle(v *Verdict) string {
	switch conclusion(v) {
	case conclusionFailure:
		return fmt.Sprintf("Failed: %d blocking finding(s)", v.Summary.Blocking)
	case conclusionNeutral:
		return fmt.Sprintf("Passed in warn mode: %d finding(s) would block", v.Summary.Blocking)
	}
	return "Passed"
}

func buildCheckRun(run *cirun.Run, v *Verdict, sha, runURL string) githubapp.CheckRun {
	c := githubapp.CheckRun{Name: CheckName, HeadSHA: sha, Conclusion: conclusion(v), DetailsURL: runURL,
		ExternalID: run.ID.String(), Title: checkTitle(v), Summary: summaryMarkdown(v, runURL)}
	level := conclusionFailure
	if c.Conclusion != conclusionFailure {
		level = "warning"
	}
	for _, r := range v.Reasons {
		if r.File == "" || r.Line <= 0 || !isBlockingCode(r.Code) {
			continue
		}
		c.Annotations = append(c.Annotations, githubapp.CheckAnnotation{Path: r.File, StartLine: r.Line, EndLine: r.Line,
			AnnotationLevel: level, Title: plain(r.Title, 200), Message: plain(r.Message, 500)})
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
	fmt.Fprintf(&b, "\n[Open the run in OpenCTEM](%s)\n", runURL)
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
	case cirun.ReasonOverride:
		return "Break-glass"
	case cirun.ReasonNoBaseline:
		return "No baseline"
	}
	return code
}

func buildComment(run *cirun.Run, v *Verdict, runURL, marker string) string {
	var b strings.Builder
	b.WriteString(marker + "\n")
	icon := map[string]string{conclusionFailure: "Failed", conclusionNeutral: "Passed (warn mode)", conclusionSuccess: "Passed"}[conclusion(v)]
	fmt.Fprintf(&b, "### %s: %s\n\n", CheckName, icon)
	fmt.Fprintf(&b, "Commit `%s` compared with `%s`.\n\n", code(shortSHA(run.CommitSHA), 12),
		code(nonEmpty(v.Baseline.Branch, "the default branch"), 100))
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
