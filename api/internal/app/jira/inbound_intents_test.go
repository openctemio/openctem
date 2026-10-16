package jira

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A profile in the style of the design: Done = fix claim, Done with the
// resolution "Won't Do" = risk-acceptance request, "Not a bug" = FP request,
// In Progress = work started, Duplicate = a suggestion for a person.
func designProfile() *ticketmap.StatusMap {
	return &ticketmap.StatusMap{Inbound: []ticketmap.InboundRule{
		{StatusID: "3", Intent: ticketmap.IntentInProgress},
		{StatusID: "10", Intent: ticketmap.IntentSuggestDuplicate},
		{Category: ticketmap.CategoryDone, Resolution: "Won't Do", Intent: ticketmap.IntentRequestAccept},
		{Category: ticketmap.CategoryDone, Resolution: "Not a bug", Intent: ticketmap.IntentRequestFP},
		{Category: ticketmap.CategoryDone, Intent: ticketmap.IntentFixClaim},
	}}
}

func moved(statusID, category, resolution string) WebhookPayload {
	fields := map[string]any{"status": map[string]any{"id": statusID, "statusCategory": map[string]any{"key": category}}}
	if resolution != "" {
		fields["resolution"] = map[string]any{"name": resolution}
	}
	return WebhookPayload{
		User:      WebhookUser{AccountID: "acct-7"},
		Issue:     WebhookIssue{Key: "SEC-1", Self: "https://x.atlassian.net/rest/api/2/issue/10001", Fields: fields},
		Changelog: &Changelog{Items: []ChangeItem{{Field: "status", To: statusID, ToString: "Whatever"}}},
	}
}

func intentSync(t *testing.T, sm *ticketmap.StatusMap) (*SyncService, *applierStub, *profileClient, *inboundRepo) {
	t.Helper()
	repo := &inboundRepo{finding: inProgressFinding(t)}
	c := &profileClient{integration: shared.NewID()}
	s := NewSyncService(repo, c, logger.NewNop())
	s.SetProfileSource(&stubProfiles{inbound: sm})
	app := &applierStub{}
	s.SetInboundApplier(app)
	return s, app, c, repo
}

func TestProfileIntents(t *testing.T) {
	cases := []struct {
		name         string
		ev           WebhookPayload
		wantTarget   vulnerability.FindingStatus
		wantRequest  vulnerability.FindingStatus
		wantComment  string
		wantNoAction bool
	}{
		{name: "Done is a fix claim", ev: moved("5", "done", "Done"), wantTarget: vulnerability.FindingStatusFixApplied},
		{name: "Won't Do is a risk-acceptance request", ev: moved("5", "done", "Won't Do"), wantRequest: vulnerability.FindingStatusAccepted, wantComment: "pending risk acceptance request"},
		{name: "Not a bug is a false-positive request", ev: moved("5", "done", "Not a bug"), wantRequest: vulnerability.FindingStatusFalsePositive, wantComment: "pending false positive request"},
		{name: "In Progress starts work", ev: moved("3", "indeterminate", ""), wantTarget: vulnerability.FindingStatusInProgress},
		{name: "Duplicate only tells a person", ev: moved("10", "done", ""), wantComment: "a person reviews and marks duplicates", wantNoAction: true},
		{name: "an unmapped status does nothing", ev: moved("77", "new", ""), wantNoAction: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, app, c, repo := intentSync(t, designProfile())
			if err := s.HandleJiraWebhook(context.Background(), shared.NewID(), tc.ev); err != nil {
				t.Fatal(err)
			}
			if app.target != tc.wantTarget || app.request != tc.wantRequest {
				t.Fatalf("applied %q, requested %q; want %q / %q", app.target, app.request, tc.wantTarget, tc.wantRequest)
			}
			if tc.wantNoAction && len(app.ids) != 0 {
				t.Fatalf("acted on %v", app.ids)
			}
			if repo.updates != 0 {
				t.Fatal("the sync service wrote the finding row itself")
			}
			got := strings.Join(c.comments, "\n")
			if tc.wantComment == "" && got != "" {
				t.Fatalf("unexpected comment %q", got)
			}
			if tc.wantComment != "" && !strings.Contains(got, tc.wantComment) {
				t.Fatalf("comment %q, want it to say %q", got, tc.wantComment)
			}
		})
	}
}

// A request a finding cannot take is reported on the ticket with the reason.
func TestProfileIntents_RequestRefusalsCommented(t *testing.T) {
	s, app, c, _ := intentSync(t, designProfile())
	app.refuse = []InboundRefusal{{FindingID: "f2", Reason: "the finding is resolved; a request for accepted cannot be made for it"}}
	if err := s.HandleJiraWebhook(context.Background(), shared.NewID(), moved("5", "done", "Won't Do")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.comments, "\n"); !strings.Contains(got, "f2") || !strings.Contains(got, "cannot be made") {
		t.Fatalf("comment %q", got)
	}
}

// Without a profile for the project the built-in map applies (Done → fix
// claim); "Won't Do" there is not a request.
func TestProfileIntents_NoProfileKeepsTheBuiltInMap(t *testing.T) {
	s, app, _, _ := intentSync(t, nil)
	if err := s.HandleJiraWebhook(context.Background(), shared.NewID(), doneWebhook()); err != nil {
		t.Fatal(err)
	}
	if app.target != vulnerability.FindingStatusFixApplied || app.request != "" {
		t.Fatalf("applied %q, requested %q", app.target, app.request)
	}
}

// A profile that cannot be read never falls back to the built-in map: the
// delivery fails and Jira retries it.
func TestProfileIntents_UnreadableProfileFailsClosed(t *testing.T) {
	s, app, _, _ := intentSync(t, nil)
	s.SetProfileSource(&stubProfiles{inErr: errors.New("db down")})
	if err := s.HandleJiraWebhook(context.Background(), shared.NewID(), doneWebhook()); err == nil {
		t.Fatal("want an error")
	}
	if len(app.ids) != 0 {
		t.Fatal("applied the built-in map in place of the profile")
	}
}

func TestStatusEvent_ChangeWinsOverSnapshot(t *testing.T) {
	p := moved("5", "done", "Won't Do")
	p.Changelog.Items[0].To = "6" // the snapshot can lag the change
	ev := statusEvent(p)
	if ev.StatusID != "6" || ev.Category != "done" || ev.Resolution != "Won't Do" || ev.AuthorID != "acct-7" {
		t.Fatalf("%+v", ev)
	}
	p = WebhookPayload{Changelog: &Changelog{Items: []ChangeItem{{Field: "status", To: "9"}, {Field: "resolution", ToString: "Won't Fix"}}}}
	if ev := statusEvent(p); ev.StatusID != "9" || ev.Resolution != "Won't Fix" {
		t.Fatalf("%+v", ev)
	}
}

// An issue outside the projects configured for ticketing moves nothing, even
// when a finding still names it by URL; a configured project's issue does.
func TestInbound_OnlyConfiguredProjects(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want bool
	}{{"HR-7", false}, {"SEC-1", true}} {
		repo := &inboundRepo{finding: inProgressFinding(t)}
		c := &linkClient{intg: shared.NewID()}
		s := NewSyncService(repo, c, logger.NewNop())
		configured(s)
		app := &applierStub{}
		s.SetInboundApplier(app)
		p := doneWebhook()
		p.Issue.Key = tc.key
		if err := s.HandleJiraWebhook(context.Background(), shared.NewID(), p); err != nil {
			t.Fatal(err)
		}
		if got := len(app.ids) > 0; got != tc.want {
			t.Errorf("%s: applied=%v, want %v", tc.key, got, tc.want)
		}
	}
}
