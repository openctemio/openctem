package jira

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func externalLink(t *testing.T, tenant, intg shared.ID, key, issueID string) *ticketlink.Link {
	t.Helper()
	l, err := ticketlink.New(tenant, intg, ticketlink.ForFinding(shared.NewID()), key, issueID, "https://acme.atlassian.net",
		"https://acme.atlassian.net/browse/"+key, ticketlink.RoleOwn, ticketlink.SourcePlatform, nil)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func assigned(id, key, accountID, name string, at time.Time) WebhookPayload {
	return WebhookPayload{
		WebhookEvent: "jira:issue_updated",
		Timestamp:    at.UnixMilli(),
		Issue: WebhookIssue{ID: id, Key: key, Fields: map[string]any{
			"assignee": map[string]any{"accountId": accountID, "displayName": name},
			"status":   map[string]any{"id": "3", "statusCategory": map[string]any{"key": "indeterminate"}},
		}},
		Changelog: &Changelog{Items: []ChangeItem{{Field: "assignee", To: accountID, ToString: name}}},
	}
}

// An assignee change with no status change is stored on the issue's links
// of the delivering integration, sanitized; it moves no finding and writes
// no platform assignee.
func TestRecordExternalChange_AssigneeWithoutStatusChange(t *testing.T) {
	tenant, intgA, intgB := shared.NewID(), shared.NewID(), shared.NewID()
	la := externalLink(t, tenant, intgA, "SEC-1", "100")
	lb := externalLink(t, tenant, intgB, "SEC-1", "200")
	links := &memLinks{rows: []*ticketlink.Link{la, lb}}
	repo := &inboundRepo{finding: inProgressFinding(t)}
	s := NewSyncService(repo, nil, logger.NewNop())
	s.SetLinkStore(links)
	app := &applierStub{}
	s.SetInboundApplier(app)
	s.SetMappingResolver(stubMappingResolver{mapping: DefaultMappingConfig()})

	now := time.Now()
	p := assigned("200", "SEC-1", "5b10ac8d82e05b22cc7d4ef5", "<b>Dana</b> ‮K.\x00 <script>x</script>", now)
	if err := s.RecordExternalChange(context.Background(), tenant, intgB, p); err != nil {
		t.Fatal(err)
	}
	if err := s.HandleJiraWebhook(context.Background(), tenant, p); err != nil {
		t.Fatal(err)
	}
	if lb.External.AssigneeID != "5b10ac8d82e05b22cc7d4ef5" || lb.External.AssigneeName != "Dana K. x" || lb.External.StatusCategory != ticketlink.StatusCategoryInProgress {
		t.Fatalf("link B external = %+v", lb.External)
	}
	if la.External.AssigneeID != "" || la.External.UpdatedAt != nil {
		t.Fatalf("integration A's link with the same key changed: %+v", la.External)
	}
	if len(app.ids) != 0 || repo.updates != 0 {
		t.Fatalf("an assignee change moved findings (%v) or wrote a finding (%d)", app.ids, repo.updates)
	}

	// Another tenant naming B's integration changes nothing.
	if err := s.RecordExternalChange(context.Background(), shared.NewID(), intgB, assigned("200", "SEC-1", "evil", "Mallory", now.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	if lb.External.AssigneeID != "5b10ac8d82e05b22cc7d4ef5" {
		t.Fatalf("a delivery for another tenant changed the link: %+v", lb.External)
	}

	// An older delivery (a late retry) never rolls the assignee back.
	if err := s.RecordExternalChange(context.Background(), tenant, intgB, assigned("200", "SEC-1", "old", "Old", now.Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}
	if lb.External.AssigneeID != "5b10ac8d82e05b22cc7d4ef5" {
		t.Fatalf("an older delivery rolled the assignee back: %+v", lb.External)
	}

	// Unassigned in Jira: the label is cleared.
	un := assigned("200", "SEC-1", "", "", now.Add(time.Minute))
	un.Issue.Fields["assignee"] = nil
	if err := s.RecordExternalChange(context.Background(), tenant, intgB, un); err != nil {
		t.Fatal(err)
	}
	if lb.External.AssigneeID != "" || lb.External.AssigneeName != "" {
		t.Fatalf("unassign left %+v", lb.External)
	}
}

// A moved issue (new key) is matched by its id; a delivery with nothing
// about the assignee or the status category writes nothing.
func TestRecordExternalChange_MatchByIDAndNoop(t *testing.T) {
	tenant, intg := shared.NewID(), shared.NewID()
	l := externalLink(t, tenant, intg, "OLD-1", "300")
	s := NewSyncService(&inboundRepo{finding: inProgressFinding(t)}, nil, logger.NewNop())
	s.SetLinkStore(&memLinks{rows: []*ticketlink.Link{l}})

	if err := s.RecordExternalChange(context.Background(), tenant, intg, assigned("300", "NEW-9", "acc-1", "Dana", time.Now())); err != nil {
		t.Fatal(err)
	}
	if l.External.AssigneeID != "acc-1" {
		t.Fatalf("moved issue not matched by id: %+v", l.External)
	}
	before := *l.External.UpdatedAt
	noop := WebhookPayload{Issue: WebhookIssue{ID: "300", Key: "NEW-9"}, Changelog: &Changelog{Items: []ChangeItem{{Field: "labels"}}}}
	if err := s.RecordExternalChange(context.Background(), tenant, intg, noop); err != nil {
		t.Fatal(err)
	}
	if !l.External.UpdatedAt.Equal(before) {
		t.Fatal("a delivery with no assignee or status category wrote the link")
	}
	// No integration: nothing.
	if err := s.RecordExternalChange(context.Background(), tenant, shared.ID{}, assigned("300", "NEW-9", "x", "X", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if l.External.AssigneeID != "acc-1" {
		t.Fatal("a delivery without an integration wrote the link")
	}
}
