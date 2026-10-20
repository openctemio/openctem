package ticketing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/scm"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// repoTracker is a repository that keeps the issues created in it and can
// lose the create response.
type repoTracker struct {
	fakeIssueCreator
	issues    []scm.IssueSummary
	loseReply bool
	listErr   error
}

func (r *repoTracker) CreateIssue(_ context.Context, owner, repo, _, body string, _ []string) (int, string, error) {
	r.calls++
	n := len(r.issues) + 1
	is := scm.IssueSummary{Number: n, HTMLURL: fmt.Sprintf("https://github.com/%s/%s/issues/%d", owner, repo, n), Body: body}
	r.issues = append(r.issues, is)
	if r.loseReply {
		return 0, "", errors.New("context deadline exceeded")
	}
	return is.Number, is.HTMLURL, nil
}

func (r *repoTracker) RecentIssues(_ context.Context, _, _, label string) ([]scm.IssueSummary, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	if label != "openctem" {
		return nil, nil
	}
	out := make([]scm.IssueSummary, 0, len(r.issues))
	for i := len(r.issues) - 1; i >= 0; i-- { // newest first
		out = append(out, r.issues[i])
	}
	return out, nil
}

func ghService(t *testing.T, tenantID shared.ID, f *vulnerability.Finding, rt *repoTracker) (*GitHubTicketService, *fakeFindingRepo) {
	t.Helper()
	fr := &fakeFindingRepo{finding: f}
	ir := &fakeIntegrationRepo{list: []*integration.Integration{connectedGitHubIntegration(t, tenantID)}}
	s := NewGitHubTicketService(fr, ir, nil, logger.NewNop())
	s.clientFactory = func(_, _ string) (issueCreator, error) { return rt, nil }
	return s, fr
}

// The create response is lost (GitHub created the issue): the retry finds it
// by the marker at the end of its body and links it; no second issue.
func TestGitHubTicket_LostResponseIsAdopted(t *testing.T) {
	tenantID := shared.NewID()
	f := newTestFinding(t, vulnerability.FindingSourceSAST)
	rt := &repoTracker{loseReply: true}
	s, fr := ghService(t, tenantID, f, rt)
	in := GitHubTicketInput{TenantID: tenantID.String(), FindingID: f.ID().String(), Owner: "octo", Repo: "repo"}
	if _, err := s.CreateTicketFromFinding(context.Background(), in); err == nil {
		t.Fatal("want the lost response as an error")
	}
	if !strings.HasSuffix(strings.TrimSpace(rt.issues[0].Body), issueMarker(tenantID, f.ID())) || strings.Contains(rt.issues[0].Body, tenantID.String()) {
		t.Fatalf("body does not end with the marker or names the tenant id: %q", rt.issues[0].Body)
	}
	rt.loseReply = false
	info, err := s.CreateTicketFromFinding(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if rt.calls != 1 || info.TicketURL != rt.issues[0].HTMLURL || len(fr.updated) != 1 {
		t.Fatalf("calls %d info %+v uris %v; want the first issue adopted and linked", rt.calls, info, fr.updated)
	}
}

// A marker of another finding or another tenant, or a marker that is not the
// body's last line (finding text quoting it), is never adopted; a failed
// lookup refuses the create.
func TestGitHubTicket_ForeignMarkerNotAdopted(t *testing.T) {
	tenantID := shared.NewID()
	f := newTestFinding(t, vulnerability.FindingSourceSAST)
	rt := &repoTracker{issues: []scm.IssueSummary{
		{Number: 1, HTMLURL: "https://github.com/octo/repo/issues/1", Body: "x\n\n" + issueMarker(shared.NewID(), f.ID())},
		{Number: 2, HTMLURL: "https://github.com/octo/repo/issues/2", Body: "x\n\n" + issueMarker(tenantID, shared.NewID())},
		{Number: 3, HTMLURL: "https://github.com/octo/repo/issues/3", Body: issueMarker(tenantID, f.ID()) + "\n\nmore text"},
	}}
	s, _ := ghService(t, tenantID, f, rt)
	in := GitHubTicketInput{TenantID: tenantID.String(), FindingID: f.ID().String(), Owner: "octo", Repo: "repo"}
	info, err := s.CreateTicketFromFinding(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if rt.calls != 1 || info.TicketURL != "https://github.com/octo/repo/issues/4" {
		t.Fatalf("calls %d info %+v; want a new issue", rt.calls, info)
	}

	g := newTestFinding(t, vulnerability.FindingSourceSAST)
	rt2 := &repoTracker{listErr: errors.New("github 502")}
	s2, _ := ghService(t, tenantID, g, rt2)
	if _, err := s2.CreateTicketFromFinding(context.Background(), GitHubTicketInput{TenantID: tenantID.String(), FindingID: g.ID().String(), Owner: "octo", Repo: "repo"}); err == nil || rt2.calls != 0 {
		t.Fatalf("err %v calls %d; want refused before any create", err, rt2.calls)
	}
}
