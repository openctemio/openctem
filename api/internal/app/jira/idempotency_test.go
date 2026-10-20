package jira

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// trackerIssue is an issue on the fake tracker with its marker property.
type trackerIssue struct {
	id, key string
	marker  IssueMarker
}

// markTracker is a tracker that keeps what was created (with the marker the
// create request carried) and can lose the create response.
type markTracker struct {
	linkClient
	issues    []trackerIssue
	creates   int
	loseReply bool
	findErr   error
}

func (c *markTracker) CreateIssue(_ context.Context, in CreateIssueInput) (*CreateIssueResult, error) {
	c.creates++
	n := len(c.issues) + 1
	is := trackerIssue{id: fmt.Sprintf("%d", 10000+n), key: fmt.Sprintf("%s-%d", in.ProjectKey, n)}
	if in.Marker != nil {
		is.marker = *in.Marker
	}
	c.issues = append(c.issues, is)
	if c.loseReply {
		return nil, errors.New("context deadline exceeded (Client.Timeout exceeded while awaiting headers)")
	}
	return &CreateIssueResult{ID: is.id, Key: is.key, BrowseURL: c.SiteURL() + "/browse/" + is.key}, nil
}

func (c *markTracker) FindIssuesByMarker(_ context.Context, m IssueMarker) ([]MarkedIssue, error) {
	if c.findErr != nil {
		return nil, c.findErr
	}
	var out []MarkedIssue
	for _, is := range c.issues {
		// The label carries only the object id: the property is compared by
		// the caller.
		if is.marker.Object == m.Object {
			out = append(out, MarkedIssue{ID: is.id, Key: is.key, BrowseURL: c.SiteURL() + "/browse/" + is.key, Marker: is.marker})
		}
	}
	return out, nil
}

// passGuard lets every attempt through (the per-task lock expired).
type passGuard struct{}

func (passGuard) FirstDelivery(context.Context, string, time.Duration) (bool, error) {
	return true, nil
}

func markTaskSync(t *testing.T) (*SyncService, *markTracker, *memLinks, *remediation.Task, shared.ID) {
	t.Helper()
	task := newTask(remediation.TaskStateInProgress)
	s, _, links, _ := taskSync(t, task)
	c := &markTracker{linkClient: linkClient{intg: shared.NewID()}}
	s.jiraClient = c
	s.SetRefusalCommentGuard(passGuard{})
	return s, c, links, task, shared.NewID()
}

// The create response is lost (Jira created the issue): the retry finds the
// issue by its marker and records it; no second issue is created.
func TestCreateTaskIssue_LostResponseIsAdopted(t *testing.T) {
	s, c, links, task, tid := markTaskSync(t)
	c.loseReply = true
	if _, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: tid, TaskID: task.ID}); err == nil {
		t.Fatal("want the lost response as an error")
	}
	if c.creates != 1 || len(links.rows) != 0 {
		t.Fatalf("creates %d links %d", c.creates, len(links.rows))
	}
	if m := c.issues[0].marker; m.Object != task.ID.String() || m.Kind != MarkerKindTask || m.Integration != c.intg.String() {
		t.Fatalf("the create carried marker %+v", m)
	}
	c.loseReply = false
	l, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: tid, TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	if c.creates != 1 || l.ExternalKey != c.issues[0].key || l.ExternalID != c.issues[0].id {
		t.Fatalf("retry: creates %d, link %+v; want the first issue adopted", c.creates, l)
	}
}

// The issue was created but its link could not be recorded: the next
// attempt adopts it (no orphan, no duplicate).
func TestCreateTaskIssue_UnrecordedLinkIsAdopted(t *testing.T) {
	s, c, links, task, tid := markTaskSync(t)
	links.createErr = errors.New("db down")
	if _, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: tid, TaskID: task.ID}); err == nil {
		t.Fatal("want the record error")
	}
	links.createErr = nil
	l, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: tid, TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	if c.creates != 1 || l.ExternalKey != c.issues[0].key {
		t.Fatalf("creates %d link %+v", c.creates, l)
	}
}

// An issue carrying the label but a marker of another object, kind or
// integration (another tenant's integration on the same site, a copied
// label), or an issue outside the configured projects, is never adopted.
func TestCreateTaskIssue_ForeignMarkerNotAdopted(t *testing.T) {
	s, c, _, task, tid := markTaskSync(t)
	obj := task.ID.String()
	c.issues = []trackerIssue{
		{id: "1", key: "SEC-1", marker: IssueMarker{Object: obj, Kind: MarkerKindTask, Integration: shared.NewID().String()}},
		{id: "2", key: "SEC-2", marker: IssueMarker{Object: obj, Kind: MarkerKindFinding, Integration: c.intg.String()}},
		{id: "3", key: "SEC-3", marker: IssueMarker{Object: obj}},
		{id: "4", key: "HR-4", marker: IssueMarker{Object: obj, Kind: MarkerKindTask, Integration: c.intg.String()}},
	}
	l, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: tid, TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	if c.creates != 1 || l.ExternalKey == "SEC-1" || l.ExternalKey == "SEC-2" || l.ExternalKey == "SEC-3" || l.ExternalKey == "HR-4" {
		t.Fatalf("adopted a foreign issue: creates %d link %s", c.creates, l.ExternalKey)
	}
}

// Without the lookup a retry could duplicate the issue: the create is
// refused instead.
func TestCreateTaskIssue_LookupFailureRefuses(t *testing.T) {
	s, c, _, task, tid := markTaskSync(t)
	c.findErr = errors.New("jira 503")
	if _, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: tid, TaskID: task.ID}); err == nil || c.creates != 0 {
		t.Fatalf("err %v creates %d; want refused before any create", err, c.creates)
	}
}

// A finding's ticket: a lost response is adopted on retry, in the same
// project only; the link and the ticket URL are recorded.
func TestCreateTicketFromFinding_LostResponseIsAdopted(t *testing.T) {
	f := buildFinding(t)
	repo := &stubFindingRepo{finding: f}
	c := &markTracker{linkClient: linkClient{intg: shared.NewID()}, loseReply: true}
	s := newSync(repo, c)
	links := &memLinks{}
	s.SetLinkStore(links)
	tid := f.TenantID()
	in := CreateTicketInput{TenantID: tid.String(), FindingID: f.ID().String(), ProjectKey: "SEC"}
	if _, err := s.CreateTicketFromFinding(context.Background(), in); err == nil {
		t.Fatal("want the lost response as an error")
	}
	c.loseReply = false
	info, err := s.CreateTicketFromFinding(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if c.creates != 1 || info.TicketKey != c.issues[0].key {
		t.Fatalf("creates %d ticket %+v", c.creates, info)
	}
	if len(links.rows) != 1 || links.rows[0].ExternalKey != c.issues[0].key || len(repo.updatedURIs) != 1 {
		t.Fatalf("links %+v uris %v", links.rows, repo.updatedURIs)
	}
	// Another project: the SEC issue is not adopted, a new one is created.
	in.ProjectKey = "OPS"
	if _, err := s.CreateTicketFromFinding(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if c.creates != 2 {
		t.Fatalf("creates %d, want a new issue in OPS", c.creates)
	}
}
