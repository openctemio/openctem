package jira

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// recordingClient captures outbound transition/comment calls and serves a
// configurable current status for the echo-guard check.
type recordingClient struct {
	stubCreateClient // CreateIssue/TestConnection
	curStatus        string
	transitionErr    error
	transitions      []string
	comments         []string
}

func (c *recordingClient) GetIssueStatus(_ context.Context, _ string) (string, error) {
	return c.curStatus, nil
}
func (c *recordingClient) TransitionToStatus(_ context.Context, _, target, _ string) error {
	if c.transitionErr != nil {
		return c.transitionErr
	}
	c.transitions = append(c.transitions, target)
	return nil
}
func (c *recordingClient) AddComment(_ context.Context, _, body string) error {
	c.comments = append(c.comments, body)
	return nil
}

func enabledMapping() MappingConfig {
	m := DefaultMappingConfig()
	m.SyncEnabled = true
	return m
}

// findingInProgress returns a finding moved to in_progress (→ Jira "In Progress")
// linked to the given Jira issue URL.
func findingInProgress(t *testing.T, ticketURL string) *vulnerability.Finding {
	t.Helper()
	f := buildFinding(t, ticketURL)
	if err := f.TransitionStatus(vulnerability.FindingStatusConfirmed, "", nil); err != nil {
		t.Fatalf("→confirmed: %v", err)
	}
	if err := f.TransitionStatus(vulnerability.FindingStatusInProgress, "", nil); err != nil {
		t.Fatalf("→in_progress: %v", err)
	}
	return f
}

func TestSyncFindingStatusToTicket_TransitionsWhenEnabled(t *testing.T) {
	c := &recordingClient{curStatus: "To Do"}
	repo := &stubFindingRepo{finding: findingInProgress(t, "https://x.atlassian.net/browse/SEC-1")}
	s := newSync(repo, c)

	if err := s.SyncFindingStatusToTicket(context.Background(), shared.NewID(), shared.NewID(), enabledMapping()); err != nil {
		t.Fatalf("SyncFindingStatusToTicket: %v", err)
	}
	if len(c.transitions) != 1 || c.transitions[0] != "In Progress" {
		t.Fatalf("expected one transition to 'In Progress', got %v", c.transitions)
	}
}

func TestSyncFindingStatusToTicket_DisabledIsNoop(t *testing.T) {
	c := &recordingClient{}
	repo := &stubFindingRepo{finding: findingInProgress(t, "https://x.atlassian.net/browse/SEC-1")}
	s := newSync(repo, c)

	m := DefaultMappingConfig() // SyncEnabled defaults to false
	if err := s.SyncFindingStatusToTicket(context.Background(), shared.NewID(), shared.NewID(), m); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(c.transitions) != 0 || len(c.comments) != 0 {
		t.Fatalf("disabled sync must do nothing; got transitions=%v comments=%v", c.transitions, c.comments)
	}
}

func TestSyncFindingStatusToTicket_SkipsWhenAlreadyAtTarget(t *testing.T) {
	c := &recordingClient{curStatus: "In Progress"} // already there
	repo := &stubFindingRepo{finding: findingInProgress(t, "https://x.atlassian.net/browse/SEC-1")}
	s := newSync(repo, c)

	if err := s.SyncFindingStatusToTicket(context.Background(), shared.NewID(), shared.NewID(), enabledMapping()); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(c.transitions) != 0 {
		t.Fatalf("must skip when Jira already at target (echo-guard); got %v", c.transitions)
	}
}

func TestSyncFindingStatusToTicket_CommentFallbackOnNoTransition(t *testing.T) {
	c := &recordingClient{curStatus: "To Do", transitionErr: ErrNoMatchingTransition}
	repo := &stubFindingRepo{finding: findingInProgress(t, "https://x.atlassian.net/browse/SEC-1")}
	s := newSync(repo, c)

	if err := s.SyncFindingStatusToTicket(context.Background(), shared.NewID(), shared.NewID(), enabledMapping()); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(c.comments) != 1 {
		t.Fatalf("no-transition must fall back to a comment; got comments=%v", c.comments)
	}
}

func TestSyncFindingStatusToTicket_NoopWhenUnlinked(t *testing.T) {
	c := &recordingClient{curStatus: "To Do"}
	repo := &stubFindingRepo{finding: findingInProgress(t, "")} // no Jira URL
	s := newSync(repo, c)

	if err := s.SyncFindingStatusToTicket(context.Background(), shared.NewID(), shared.NewID(), enabledMapping()); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(c.transitions) != 0 || len(c.comments) != 0 {
		t.Fatalf("unlinked finding must be a no-op; got transitions=%v comments=%v", c.transitions, c.comments)
	}
}

func TestFirstJiraIssueKey(t *testing.T) {
	cases := map[string]string{
		"https://org.atlassian.net/browse/SEC-123": "SEC-123",
		"https://org.atlassian.net/browse/ABC-1":   "ABC-1",
		"https://github.com/x/y/issues/4":          "",
		"":                                         "",
	}
	for url, want := range cases {
		if got := firstJiraIssueKey([]string{url}); got != want {
			t.Errorf("firstJiraIssueKey(%q) = %q, want %q", url, got, want)
		}
	}
}

type stubMappingResolver struct {
	mapping MappingConfig
	err     error
}

func (r stubMappingResolver) ResolveMapping(_ context.Context, _ shared.ID) (MappingConfig, error) {
	return r.mapping, r.err
}

func TestSyncFindingStatus_NoResolverIsNoop(t *testing.T) {
	c := &recordingClient{curStatus: "To Do"}
	repo := &stubFindingRepo{finding: findingInProgress(t, "https://x.atlassian.net/browse/SEC-1")}
	s := newSync(repo, c) // no mapping resolver wired

	if err := s.SyncFindingStatus(context.Background(), shared.NewID(), shared.NewID()); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(c.transitions) != 0 {
		t.Fatalf("no mapping resolver must be a no-op; got %v", c.transitions)
	}
}

func TestSyncFindingStatus_NoIntegrationIsNoop(t *testing.T) {
	c := &recordingClient{curStatus: "To Do"}
	repo := &stubFindingRepo{finding: findingInProgress(t, "https://x.atlassian.net/browse/SEC-1")}
	s := newSync(repo, c)
	s.SetMappingResolver(stubMappingResolver{err: ErrNoTicketingIntegration})

	if err := s.SyncFindingStatus(context.Background(), shared.NewID(), shared.NewID()); err != nil {
		t.Fatalf("ErrNoTicketingIntegration must be swallowed as no-op; got %v", err)
	}
	if len(c.transitions) != 0 {
		t.Fatalf("no integration must be a no-op; got %v", c.transitions)
	}
}

func TestSyncFindingStatus_ResolvesAndPushes(t *testing.T) {
	c := &recordingClient{curStatus: "To Do"}
	repo := &stubFindingRepo{finding: findingInProgress(t, "https://x.atlassian.net/browse/SEC-1")}
	s := newSync(repo, c)
	s.SetMappingResolver(stubMappingResolver{mapping: enabledMapping()})

	if err := s.SyncFindingStatus(context.Background(), shared.NewID(), shared.NewID()); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(c.transitions) != 1 || c.transitions[0] != "In Progress" {
		t.Fatalf("expected resolved mapping to drive a transition to 'In Progress', got %v", c.transitions)
	}
}
