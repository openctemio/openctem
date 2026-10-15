package cirun

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	scmappsvc "github.com/openctemio/openctem/api/internal/app/scmapp"
	"github.com/openctemio/openctem/api/internal/infra/scm/githubapp"
	"github.com/openctemio/openctem/api/internal/infra/scm/gitlabapi"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/scmapp"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakePoster struct {
	parents  map[string][]string
	merged   []githubapp.PullRequest
	pr       githubapp.PullRequest
	prErr    error
	checkErr error
	checks   []githubapp.CheckRun
	comments []string
	markers  []string
}

func (f *fakePoster) CreateCheckRun(_ context.Context, _ int64, owner, repo string, c githubapp.CheckRun) error {
	if f.checkErr != nil {
		return f.checkErr
	}
	f.checks = append(f.checks, c)
	return nil
}
func (f *fakePoster) GetPullRequest(context.Context, int64, string, string, int) (*githubapp.PullRequest, error) {
	if f.prErr != nil {
		return nil, f.prErr
	}
	pr := f.pr
	return &pr, nil
}
func (f *fakePoster) UpsertIssueComment(_ context.Context, _ int64, _, _ string, _ int, marker, body string) error {
	f.markers = append(f.markers, marker)
	f.comments = append(f.comments, body)
	return nil
}

func (f *fakePoster) CommitParents(_ context.Context, _ int64, _, _, sha string) ([]string, error) {
	if p, ok := f.parents[sha]; ok {
		return p, nil
	}
	return nil, &githubapp.StatusError{Status: 404}
}

func (f *fakePoster) PullRequestsForCommit(context.Context, int64, string, string, string) ([]githubapp.PullRequest, error) {
	return f.merged, nil
}

type fakeInstalls struct{ tenant shared.ID }

func (f fakeInstalls) ActiveForAccount(_ context.Context, tid shared.ID, _, login string) (*scmapp.Installation, error) {
	if tid != f.tenant || login != "acme" {
		return nil, scmapp.ErrNotFound
	}
	return &scmapp.Installation{InstallationID: 77, Status: scmapp.StatusActive}, nil
}

func failingVerdict(t *testing.T) json.RawMessage {
	t.Helper()
	v := Verdict{GateVerdict: cirun.GateVerdict{Verdict: cirun.VerdictFail,
		Summary:  cirun.GateSummary{Evaluated: 2, New: 1, Blocking: 1},
		Policy:   cirun.GatePolicyView{Mode: "enforce", Source: "default"},
		Baseline: cirun.GateBaselineView{Branch: "main", Known: true},
		Reasons: []cirun.GateReason{{Code: cirun.ReasonSeverity, Severity: "high", Title: "SQLi [click](javascript:alert(1)) <img>",
			Message: "severity high", File: "db.go", Line: 42}}}}
	b, _ := json.Marshal(v)
	return b
}

func TestDecorateGitHub(t *testing.T) {
	tenant := shared.NewID()
	pid := shared.NewID()
	base := cirun.Run{ID: shared.NewID(), TenantID: tenant, Repository: "github.com/acme/api", PullRequest: "7",
		CommitSHA: "merge1", CommitVerified: true, PipelineID: &pid, VerdictDetail: failingVerdict(t)}
	newJob := func(p *fakePoster) *DecorationJob {
		return NewDecorationJob(fakeDecorationRepo{}, fakeInstalls{tenant: tenant}, p, "https://console.example", nil)
	}
	ctx := context.Background()

	// A pull request run: the check goes on the pull request's head (read
	// from GitHub), with an annotation, and one marked comment.
	p := &fakePoster{}
	p.pr.MergeCommitSHA, p.pr.Head.SHA = "merge1", "head1"
	run := base
	if st, detail := newJob(p).decorate(ctx, &run); st != cirun.DecorationPosted {
		t.Fatalf("posted: %s %s", st, detail)
	}
	c := p.checks[0]
	if c.Name != CheckName || c.HeadSHA != "head1" || c.Conclusion != "failure" || len(c.Annotations) != 1 ||
		c.Annotations[0].Path != "db.go" || !strings.HasPrefix(c.DetailsURL, "https://console.example/ci-cd?view=runs&run=") {
		t.Fatalf("check = %+v", c)
	}
	if len(p.comments) != 1 || !strings.Contains(p.comments[0], p.markers[0]) || !strings.Contains(p.markers[0], pid.String()) {
		t.Fatalf("comment = %v %v", p.markers, p.comments)
	}
	// Scanner text cannot inject links or HTML.
	if strings.Contains(p.comments[0], "](javascript:") || strings.Contains(p.comments[0], "<img>") {
		t.Fatalf("unescaped text in comment: %s", p.comments[0])
	}

	// The pull request moved on: nothing is posted (the head is GitHub's, so
	// a run cannot put its verdict on another commit).
	p = &fakePoster{}
	p.pr.MergeCommitSHA, p.pr.Head.SHA = "merge2", "head2"
	run = base
	if st, _ := newJob(p).decorate(ctx, &run); st != cirun.DecorationSkipped || len(p.checks) != 0 {
		t.Fatalf("stale pull request: %s %d", st, len(p.checks))
	}
	// No installation for the owner, or another tenant's: skipped.
	run = base
	run.Repository = "github.com/other/api"
	if st, _ := newJob(&fakePoster{}).decorate(ctx, &run); st != cirun.DecorationSkipped {
		t.Fatalf("no installation: %s", st)
	}
	run = base
	run.TenantID = shared.NewID()
	if st, _ := newJob(&fakePoster{}).decorate(ctx, &run); st != cirun.DecorationSkipped {
		t.Fatalf("other tenant: %s", st)
	}
	// A push run with an unverified commit gets no check.
	run = base
	run.PullRequest, run.CommitVerified = "", false
	if st, _ := newJob(&fakePoster{}).decorate(ctx, &run); st != cirun.DecorationSkipped {
		t.Fatalf("unverified commit: %s", st)
	}
	// A push run: the check on its commit, no comment.
	p = &fakePoster{}
	run = base
	run.PullRequest = ""
	if st, _ := newJob(p).decorate(ctx, &run); st != cirun.DecorationPosted || p.checks[0].HeadSHA != "merge1" || len(p.comments) != 0 {
		t.Fatalf("push run: %s %+v", st, p.checks)
	}
	// A fork event without a pull request (pull_request_target,
	// workflow_run) carries the base commit: no check goes on it.
	p = &fakePoster{}
	run = base
	run.PullRequest, run.Fork, run.Event = "", true, "pull_request_target"
	if st, _ := newJob(p).decorate(ctx, &run); st != cirun.DecorationSkipped || len(p.checks) != 0 {
		t.Fatalf("fork event on the base commit: %s %+v", st, p.checks)
	}
	// GitHub refusing access is final; a server error is retried.
	run = base
	run.PullRequest = ""
	if st, _ := newJob(&fakePoster{checkErr: &githubapp.StatusError{Status: 403}}).decorate(ctx, &run); st != cirun.DecorationFailed {
		t.Fatalf("403: %s", st)
	}
	if st, _ := newJob(&fakePoster{checkErr: &githubapp.StatusError{Status: 502}}).decorate(ctx, &run); st != cirun.DecorationRetry {
		t.Fatalf("502: %s", st)
	}
	// Not a github.com repository.
	run = base
	run.Repository = "gitlab.com/acme/api"
	if st, _ := newJob(&fakePoster{}).decorate(ctx, &run); st != cirun.DecorationSkipped {
		t.Fatalf("gitlab repository: %s", st)
	}
}

func TestGitHubRepository(t *testing.T) {
	if o, r, ok := GitHubRepository("github.com/Acme/API"); !ok || o != "acme" || r != "api" {
		t.Fatalf("%q %q %v", o, r, ok)
	}
	for _, bad := range []string{"github.com/acme", "github.com//x", "github.com/a/b/c", "gitlab.com/a/b"} {
		if _, _, ok := GitHubRepository(bad); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestWarnModeIsNeutral(t *testing.T) {
	v := &Verdict{GateVerdict: cirun.GateVerdict{Verdict: cirun.VerdictPass, WouldFail: true}}
	if conclusion(v) != "neutral" {
		t.Fatal(conclusion(v))
	}
}

type fakeGitLabAPI struct {
	mrSHA    string
	head     *gitlabapi.Pipeline
	statuses []string
	notes    []string
}

func (f *fakeGitLabAPI) Token(context.Context) (*gitlabapi.TokenInfo, error)     { return nil, nil }
func (f *fakeGitLabAPI) CurrentUser(context.Context) (*gitlabapi.User, error)    { return nil, nil }
func (f *fakeGitLabAPI) Group(context.Context, string) (*gitlabapi.Group, error) { return nil, nil }
func (f *fakeGitLabAPI) GroupMember(context.Context, int64, int64) (bool, error) { return true, nil }
func (f *fakeGitLabAPI) MergeRequest(context.Context, string, int) (*gitlabapi.MergeRequest, error) {
	return &gitlabapi.MergeRequest{SHA: f.mrSHA, HeadPipeline: f.head}, nil
}
func (f *fakeGitLabAPI) SetCommitStatus(_ context.Context, project, sha, state, name, _, _ string, pipelineID int64) error {
	s := project + "@" + sha + ":" + state + ":" + name
	if pipelineID > 0 {
		s += fmt.Sprintf("#%d", pipelineID)
	}
	f.statuses = append(f.statuses, s)
	return nil
}
func (f *fakeGitLabAPI) UpsertMergeRequestNote(_ context.Context, _ string, _ int, authorID int64, marker, body string) error {
	f.notes = append(f.notes, marker)
	return nil
}

type fakeGitLabClients struct {
	tenant shared.ID
	api    *fakeGitLabAPI
}

func (f fakeGitLabClients) GitLabClientFor(_ context.Context, tid shared.ID, host, project string) (scmappsvc.GitLabAPI, int64, error) {
	if tid != f.tenant || host != "gitlab.example.com" || !strings.HasPrefix(project, "acme/") {
		return nil, 0, scmapp.ErrNotFound
	}
	return f.api, 9, nil
}

func TestDecorateGitLab(t *testing.T) {
	tenant := shared.NewID()
	run := cirun.Run{ID: shared.NewID(), TenantID: tenant, Provider: cirun.ProviderGitLab, Repository: "gitlab.example.com/acme/api",
		PullRequest: "3", CommitSHA: "abc", CommitVerified: true, VerdictDetail: failingVerdict(t)}
	ctx := context.Background()
	api := &fakeGitLabAPI{mrSHA: "abc"}
	job := NewDecorationJob(fakeDecorationRepo{}, fakeInstalls{}, nil, "https://c", nil)
	job.SetGitLab(fakeGitLabClients{tenant: tenant, api: api})
	if st, d := job.decorate(ctx, &run); st != cirun.DecorationPosted || len(api.statuses) != 1 ||
		api.statuses[0] != "acme/api@abc:failed:"+CheckName || len(api.notes) != 1 {
		t.Fatalf("posted: %s %s %v %v", st, d, api.statuses, api.notes)
	}
	// The merge request moved on: nothing.
	api2 := &fakeGitLabAPI{mrSHA: "def"}
	job.SetGitLab(fakeGitLabClients{tenant: tenant, api: api2})
	if st, _ := job.decorate(ctx, &run); st != cirun.DecorationSkipped || len(api2.statuses) != 0 {
		t.Fatalf("stale merge request: %s", st)
	}
	// No connection for the group, or another tenant: skipped.
	other := run
	other.Repository = "gitlab.example.com/beta/api"
	if st, _ := job.decorate(ctx, &other); st != cirun.DecorationSkipped {
		t.Fatalf("other group: %s", st)
	}
	other = run
	other.TenantID = shared.NewID()
	if st, _ := job.decorate(ctx, &other); st != cirun.DecorationSkipped {
		t.Fatalf("other tenant: %s", st)
	}
	// A merged results pipeline runs on the merge result's commit, never on
	// the merge request's head: it posts when it is the merge request's head
	// pipeline, its status attached to that pipeline.
	merged := run
	merged.Ref, merged.ExternalRunID, merged.CommitSHA = "refs/merge-requests/3/merge", "501", "mrc"
	api3 := &fakeGitLabAPI{mrSHA: "head", head: &gitlabapi.Pipeline{ID: 501, SHA: "mrc"}}
	job.SetGitLab(fakeGitLabClients{tenant: tenant, api: api3})
	if st, d := job.decorate(ctx, &merged); st != cirun.DecorationPosted || len(api3.statuses) != 1 ||
		api3.statuses[0] != "acme/api@mrc:failed:"+CheckName+"#501" || len(api3.notes) != 1 {
		t.Fatalf("merged results: %s %s %v %v", st, d, api3.statuses, api3.notes)
	}
	// Not the head pipeline any more, another commit, a merge train, or a
	// detached run whose head moved: nothing is posted.
	for name, tc := range map[string]struct {
		ref  string
		head *gitlabapi.Pipeline
	}{
		"newer pipeline":   {"refs/merge-requests/3/merge", &gitlabapi.Pipeline{ID: 502, SHA: "mrc2"}},
		"another commit":   {"refs/merge-requests/3/merge", &gitlabapi.Pipeline{ID: 501, SHA: "other"}},
		"no head pipeline": {"refs/merge-requests/3/merge", nil},
		"merge train":      {"refs/merge-requests/3/train", &gitlabapi.Pipeline{ID: 501, SHA: "mrc"}},
		"detached":         {"refs/merge-requests/3/head", &gitlabapi.Pipeline{ID: 501, SHA: "mrc"}},
	} {
		r := merged
		r.Ref = tc.ref
		a := &fakeGitLabAPI{mrSHA: "head", head: tc.head}
		job.SetGitLab(fakeGitLabClients{tenant: tenant, api: a})
		if st, _ := job.decorate(ctx, &r); st != cirun.DecorationSkipped || len(a.statuses) != 0 || len(a.notes) != 0 {
			t.Fatalf("%s: %s %v", name, st, a.statuses)
		}
	}
	job.SetGitLab(fakeGitLabClients{tenant: tenant, api: api})
	// A GitHub run without a GitHub App is skipped, not failed.
	gh := run
	gh.Provider, gh.Repository = cirun.ProviderGitHub, "github.com/acme/api"
	if st, _ := job.decorate(ctx, &gh); st != cirun.DecorationSkipped {
		t.Fatalf("github without app: %s", st)
	}
}

type fakeDecorationRepo struct {
	passed   map[string]bool
	verdicts []cirun.CommitVerdict
	shas     *[]string
}

func (f fakeDecorationRepo) CommitVerdicts(_ context.Context, _, _ shared.ID, shas []string) ([]cirun.CommitVerdict, error) {
	if f.shas != nil {
		*f.shas = append(*f.shas, shas...)
	}
	return f.verdicts, nil
}

func (f fakeDecorationRepo) ClaimDecorations(context.Context, int) ([]cirun.Run, error) {
	return nil, nil
}
func (f fakeDecorationRepo) FinishDecoration(context.Context, shared.ID, shared.ID, string, string) error {
	return nil
}
func (f fakeDecorationRepo) PullRequestPassed(_ context.Context, _, _ shared.ID, pr string) (bool, error) {
	return f.passed[pr], nil
}

type fakeNotifier struct{ titles []string }

func (f *fakeNotifier) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	f.titles = append(f.titles, p.EventType+"|"+p.Title)
	return nil
}

// A default-branch commit from a merged pull request whose last verdict was
// not a pass raises ci.ungated_merge; a passing one, an unmerged one or one
// into another branch does not.
func TestUngatedMergeAlert(t *testing.T) {
	tenant := shared.NewID()
	run := cirun.Run{ID: shared.NewID(), TenantID: tenant, Provider: cirun.ProviderGitHub, Repository: "github.com/acme/api",
		Branch: "main", IsDefaultBranch: true, CommitSHA: "m1", CommitVerified: true, VerdictDetail: failingVerdict(t)}
	merged := "2026-10-11T00:00:00Z"
	pr := func(n int, base string, m *string) githubapp.PullRequest {
		p := githubapp.PullRequest{Number: n, MergedAt: m}
		p.Base.Ref = base
		return p
	}
	p := &fakePoster{merged: []githubapp.PullRequest{pr(1, "main", &merged), pr(2, "main", &merged), pr(3, "main", nil), pr(4, "release", &merged)}}
	n := &fakeNotifier{}
	job := NewDecorationJob(fakeDecorationRepo{passed: map[string]bool{"2": true}}, fakeInstalls{tenant: tenant}, p, "https://c", nil)
	job.SetNotifier(n)
	if st, _ := job.decorate(context.Background(), &run); st != cirun.DecorationPosted {
		t.Fatalf("decorate: %s", st)
	}
	if len(n.titles) != 1 || !strings.HasPrefix(n.titles[0], "ci.ungated_merge|") || !strings.Contains(n.titles[0], "#1") {
		t.Fatalf("alerts = %v", n.titles)
	}
	// Pull request runs never check for ungated merges.
	n.titles = nil
	prRun := run
	prRun.PullRequest, prRun.IsDefaultBranch = "9", false
	p.pr.MergeCommitSHA, p.pr.Head.SHA = "m1", "h1"
	_, _ = job.decorate(context.Background(), &prRun)
	if len(n.titles) != 0 {
		t.Fatalf("pull request run alerted: %v", n.titles)
	}
}

// GitHub recomputes a pull request's merge commit when its base moves: a run
// that judged the same head merged into the older base still posts on the
// head; a run of another head does not.
func TestDecorateAfterTheBaseMoved(t *testing.T) {
	tenant := shared.NewID()
	run := cirun.Run{ID: shared.NewID(), TenantID: tenant, Repository: "github.com/acme/api", PullRequest: "7",
		CommitSHA: "merge1", CommitVerified: true, VerdictDetail: failingVerdict(t)}
	ctx := context.Background()
	for _, tc := range []struct {
		parents map[string][]string
		want    string
	}{
		{map[string][]string{"merge1": {"base1", "head1"}}, cirun.DecorationPosted},
		{map[string][]string{"merge1": {"base1", "head0"}}, cirun.DecorationSkipped},
		{map[string][]string{"merge1": {"head1"}}, cirun.DecorationSkipped}, // not a merge commit
		{nil, cirun.DecorationSkipped},                                      // unknown commit (404)
	} {
		p := &fakePoster{parents: tc.parents}
		p.pr.MergeCommitSHA, p.pr.Head.SHA = "merge2", "head1"
		job := NewDecorationJob(fakeDecorationRepo{}, fakeInstalls{tenant: tenant}, p, "https://c", nil)
		r := run
		st, d := job.decorate(ctx, &r)
		if st != tc.want {
			t.Fatalf("%v: %s %s", tc.parents, st, d)
		}
		if st == cirun.DecorationPosted && p.checks[0].HeadSHA != "head1" {
			t.Fatalf("check on %s", p.checks[0].HeadSHA)
		}
	}
}

// A GitHub rate limit is retried, never final; other refusals stay final.
func TestRateLimitIsRetried(t *testing.T) {
	if st, d := outcome(&githubapp.StatusError{Status: 403, RateLimited: true}, "post"); st != cirun.DecorationRetry {
		t.Fatalf("rate limited 403: %s %s", st, d)
	}
	if st, _ := outcome(&githubapp.StatusError{Status: 429, RateLimited: true}, "post"); st != cirun.DecorationRetry {
		t.Fatalf("429: %s", st)
	}
	if st, _ := outcome(&githubapp.StatusError{Status: 403}, "post"); st != cirun.DecorationFailed {
		t.Fatalf("403: %s", st)
	}
}

// A comment-mode reason is a notice annotation and is marked as not
// blocking in the comment; a run failed only by a scanner failure asks for
// action instead of reporting a failure of the code.
func TestCommentModeAndScanFailure(t *testing.T) {
	v := &Verdict{GateVerdict: cirun.GateVerdict{Verdict: cirun.VerdictFail, Summary: cirun.GateSummary{Blocking: 1},
		Reasons: []cirun.GateReason{
			{Code: cirun.ReasonSeverity, Severity: "high", Title: "SQLi", File: "db.go", Line: 4},
			{Code: cirun.ReasonSeverity, Severity: "medium", Title: "Weak hash", File: "h.go", Line: 9, Mode: cirun.FindingModeComment},
		}}}
	run := &cirun.Run{ID: shared.NewID(), CommitSHA: "abc"}
	c := buildCheckRun(run, v, "abc", "https://c/r", commitFailures{})
	if c.Conclusion != "failure" || len(c.Annotations) != 2 || c.Annotations[0].AnnotationLevel != "failure" ||
		c.Annotations[1].AnnotationLevel != "notice" {
		t.Fatalf("check = %+v", c)
	}
	comment := buildComment(run, v, "https://c/r", "<!-- m -->", commitFailures{})
	if strings.Count(comment, "(not blocking)") != 1 || !strings.Contains(comment, "Weak hash") {
		t.Fatalf("comment = %s", comment)
	}

	scan := &Verdict{GateVerdict: cirun.GateVerdict{Verdict: cirun.VerdictFail, Summary: cirun.GateSummary{Blocking: 1},
		Reasons: []cirun.GateReason{{Code: cirun.ReasonScanFailure, Message: "1 scanner(s) failed"},
			{Code: cirun.ReasonSeverity, Title: "x", File: "a.go", Line: 1, Mode: cirun.FindingModeComment}}}}
	if got := conclusion(scan); got != "action_required" {
		t.Fatalf("scan failure only = %s", got)
	}
	if !strings.Contains(checkTitle(scan), "Action required") || !strings.Contains(buildComment(run, scan, "u", "m", commitFailures{}), "Action required") {
		t.Fatalf("title = %s", checkTitle(scan))
	}
	both := &Verdict{GateVerdict: cirun.GateVerdict{Verdict: cirun.VerdictFail, Reasons: append(scan.Reasons,
		cirun.GateReason{Code: cirun.ReasonSecret, File: "k", Line: 1})}}
	if got := conclusion(both); got != "failure" {
		t.Fatalf("scan failure and a secret = %s", got)
	}
	// GitLab has no "action required" state: the status fails.
	tenant := shared.NewID()
	sv, _ := json.Marshal(scan)
	api := &fakeGitLabAPI{mrSHA: "abc"}
	job := NewDecorationJob(fakeDecorationRepo{}, fakeInstalls{}, nil, "https://c", nil)
	job.SetGitLab(fakeGitLabClients{tenant: tenant, api: api})
	gl := cirun.Run{ID: shared.NewID(), TenantID: tenant, Provider: cirun.ProviderGitLab, Repository: "gitlab.example.com/acme/api",
		CommitSHA: "abc", CommitVerified: true, VerdictDetail: sv}
	if st, _ := job.decorate(context.Background(), &gl); st != cirun.DecorationPosted || !strings.HasSuffix(api.statuses[0], ":failed:"+CheckName) {
		t.Fatalf("gitlab = %s %v", st, api.statuses)
	}
}

// The check of a commit takes the strictest verdict of every pipeline on it:
// a second run (another workflow the pull request added, a later run) that
// passes cannot replace a failing check, and the check of a passing run
// fails while another pipeline on the same commit failed.
func TestCheckJudgedOverEveryPipelineOnTheCommit(t *testing.T) {
	tenant := shared.NewID()
	failed := shared.NewID()
	passing, _ := json.Marshal(Verdict{GateVerdict: cirun.GateVerdict{Verdict: cirun.VerdictPass,
		Policy: cirun.GatePolicyView{Mode: "enforce", Source: "default"}}})
	run := cirun.Run{ID: shared.NewID(), TenantID: tenant, Repository: "github.com/acme/api", PullRequest: "7",
		CommitSHA: "merge1", CommitVerified: true, VerdictDetail: passing}
	ctx := context.Background()
	post := func(verdicts []cirun.CommitVerdict) (*fakePoster, []string) {
		p := &fakePoster{}
		p.pr.MergeCommitSHA, p.pr.Head.SHA = "merge1", "head1"
		var shas []string
		job := NewDecorationJob(fakeDecorationRepo{verdicts: verdicts, shas: &shas}, fakeInstalls{tenant: tenant}, p, "https://c", nil)
		r := run
		if st, d := job.decorate(ctx, &r); st != cirun.DecorationPosted {
			t.Fatalf("posted: %s %s", st, d)
		}
		return p, shas
	}

	// Fail, then a passing run of another pipeline on the same commit: the
	// check stays failed, and says why.
	p, shas := post([]cirun.CommitVerdict{{RunID: failed, Verdict: cirun.VerdictFail}, {RunID: run.ID, Verdict: cirun.VerdictPass}})
	c := p.checks[0]
	if c.Conclusion != "failure" || !strings.Contains(c.Title, "other pipeline") ||
		!strings.Contains(c.Summary, "run="+failed.String()) || !strings.Contains(p.comments[0], "Failed") {
		t.Fatalf("check = %+v\ncomment = %s", c, p.comments[0])
	}
	// Both the judged merge commit and the check's head commit are read.
	if strings.Join(shas, ",") != "merge1,head1" {
		t.Fatalf("shas = %v", shas)
	}
	// Pass and pass: success.
	p, _ = post([]cirun.CommitVerdict{{RunID: shared.NewID(), Verdict: cirun.VerdictPass}, {RunID: run.ID, Verdict: cirun.VerdictPass}})
	if p.checks[0].Conclusion != "success" {
		t.Fatalf("pass+pass = %s", p.checks[0].Conclusion)
	}
	// Another pipeline passed only in warn mode: neutral.
	p, _ = post([]cirun.CommitVerdict{{RunID: shared.NewID(), Verdict: cirun.VerdictPass, WouldFail: true}})
	if p.checks[0].Conclusion != "neutral" {
		t.Fatalf("warn = %s", p.checks[0].Conclusion)
	}
	// The run's own stored row does not count twice, and a failing run stays
	// failed whatever the others say.
	fr := run
	fr.VerdictDetail = failingVerdict(t)
	pp := &fakePoster{}
	pp.pr.MergeCommitSHA, pp.pr.Head.SHA = "merge1", "head1"
	job := NewDecorationJob(fakeDecorationRepo{verdicts: []cirun.CommitVerdict{{RunID: run.ID, Verdict: cirun.VerdictFail}}},
		fakeInstalls{tenant: tenant}, pp, "https://c", nil)
	if st, _ := job.decorate(ctx, &fr); st != cirun.DecorationPosted || pp.checks[0].Conclusion != "failure" ||
		strings.Contains(pp.checks[0].Title, "other pipeline") {
		t.Fatalf("failing run = %+v", pp.checks)
	}

	// GitLab: a passing run's commit status fails while another pipeline
	// on the commit failed.
	api := &fakeGitLabAPI{mrSHA: "abc"}
	gl := cirun.Run{ID: shared.NewID(), TenantID: tenant, Provider: cirun.ProviderGitLab, Repository: "gitlab.example.com/acme/api",
		PullRequest: "3", CommitSHA: "abc", CommitVerified: true, VerdictDetail: passing}
	gjob := NewDecorationJob(fakeDecorationRepo{verdicts: []cirun.CommitVerdict{{RunID: failed, Verdict: cirun.VerdictFail}}},
		fakeInstalls{}, nil, "https://c", nil)
	gjob.SetGitLab(fakeGitLabClients{tenant: tenant, api: api})
	if st, _ := gjob.decorate(ctx, &gl); st != cirun.DecorationPosted || api.statuses[0] != "acme/api@abc:failed:"+CheckName {
		t.Fatalf("gitlab = %s %v", st, api.statuses)
	}
}
