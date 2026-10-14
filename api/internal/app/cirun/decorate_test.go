package cirun

import (
	"context"
	"encoding/json"
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
		return NewDecorationJob(nil, fakeInstalls{tenant: tenant}, p, "https://console.example", nil)
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
	statuses []string
	notes    []string
}

func (f *fakeGitLabAPI) Token(context.Context) (*gitlabapi.TokenInfo, error)     { return nil, nil }
func (f *fakeGitLabAPI) Group(context.Context, string) (*gitlabapi.Group, error) { return nil, nil }
func (f *fakeGitLabAPI) GroupMember(context.Context, int64, int64) (bool, error) { return true, nil }
func (f *fakeGitLabAPI) MergeRequest(context.Context, string, int) (*gitlabapi.MergeRequest, error) {
	return &gitlabapi.MergeRequest{SHA: f.mrSHA}, nil
}
func (f *fakeGitLabAPI) SetCommitStatus(_ context.Context, project, sha, state, name, _, _ string) error {
	f.statuses = append(f.statuses, project+"@"+sha+":"+state+":"+name)
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
	job := NewDecorationJob(nil, fakeInstalls{}, nil, "https://c", nil)
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
	// A GitHub run without a GitHub App is skipped, not failed.
	gh := run
	gh.Provider, gh.Repository = cirun.ProviderGitHub, "github.com/acme/api"
	if st, _ := job.decorate(ctx, &gh); st != cirun.DecorationSkipped {
		t.Fatalf("github without app: %s", st)
	}
}

type fakeDecorationRepo struct{ passed map[string]bool }

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
