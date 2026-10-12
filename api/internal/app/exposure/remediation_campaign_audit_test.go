package exposure

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// recordingAudit captures every audit event the campaign service writes.
type recordingAudit struct {
	events []auditapp.AuditEvent
	ctxs   []auditapp.AuditContext
	err    error
}

func (a *recordingAudit) LogEvent(_ context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.events = append(a.events, ev)
	a.ctxs = append(a.ctxs, actx)
	return a.err
}

func (a *recordingAudit) only(t *testing.T, action auditdom.Action) (auditapp.AuditEvent, auditapp.AuditContext) {
	t.Helper()
	var found []int
	for i, ev := range a.events {
		if ev.Action == action {
			found = append(found, i)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s event, got %d (all: %v)", action, len(found), a.actions())
	}
	return a.events[found[0]], a.ctxs[found[0]]
}

func (a *recordingAudit) actions() []auditdom.Action {
	out := make([]auditdom.Action, 0, len(a.events))
	for _, ev := range a.events {
		out = append(out, ev.Action)
	}
	return out
}

func newAuditedService(t *testing.T, counter FindingCounter) (*RemediationCampaignService, *recordingAudit, *remediation.Campaign) {
	t.Helper()
	repo := newFakeCampaignRepo()
	svc := newService(repo, counter)
	rec := &recordingAudit{}
	svc.SetAuditLogger(rec)
	tid := shared.NewID().String()
	c, err := svc.CreateCampaign(context.Background(), CreateRemediationCampaignInput{
		TenantID:      tid,
		Name:          "Patch log4j",
		Priority:      "high",
		FindingFilter: map[string]any{"finding_ids": []any{shared.NewID().String()}},
	}, auditapp.AuditContext{ActorEmail: "owner@example.com"})
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	return svc, rec, c
}

var actor = auditapp.AuditContext{
	ActorID:    "00000000-0000-0000-0000-0000000000aa",
	ActorEmail: "owner@example.com",
	// A tenant id in the request context that is not the campaign's must
	// never be what the audit row is filed under.
	TenantID: "00000000-0000-0000-0000-0000000000ff",
}

func TestCampaignAudit_Create(t *testing.T) {
	_, rec, c := newAuditedService(t, &fakeCounter{total: 4})
	ev, actx := rec.only(t, auditdom.ActionRemediationCampaignCreated)
	if ev.ResourceType != auditdom.ResourceTypeRemediationCampaign || ev.ResourceID != c.ID().String() {
		t.Fatalf("resource = %s/%s, want remediation_campaign/%s", ev.ResourceType, ev.ResourceID, c.ID())
	}
	if ev.ResourceName != "Patch log4j" {
		t.Errorf("resource name = %q", ev.ResourceName)
	}
	if actx.TenantID != c.TenantID().String() {
		t.Errorf("tenant = %q, want the campaign's %q", actx.TenantID, c.TenantID())
	}
}

func TestCampaignAudit_UpdateRecordsOnlyChangedFields(t *testing.T) {
	svc, rec, c := newAuditedService(t, &fakeCounter{total: 4})
	name, prio := "Patch log4j everywhere", "urgent"
	if _, err := svc.UpdateCampaign(context.Background(), c.TenantID().String(), c.ID().String(),
		UpdateRemediationCampaignInput{Name: &name, Priority: &prio}, actor); err != nil {
		t.Fatalf("UpdateCampaign: %v", err)
	}
	ev, actx := rec.only(t, auditdom.ActionRemediationCampaignUpdated)
	if ev.Changes == nil {
		t.Fatal("update event has no changes")
	}
	if ev.Changes.Before["name"] != "Patch log4j" || ev.Changes.After["name"] != name {
		t.Errorf("name change = %v -> %v", ev.Changes.Before["name"], ev.Changes.After["name"])
	}
	if ev.Changes.Before["priority"] != "high" || ev.Changes.After["priority"] != "urgent" {
		t.Errorf("priority change = %v -> %v", ev.Changes.Before["priority"], ev.Changes.After["priority"])
	}
	if _, ok := ev.Changes.After["description"]; ok {
		t.Error("description did not change but is in the audit diff")
	}
	if actx.ActorID != actor.ActorID || actx.ActorEmail != actor.ActorEmail {
		t.Errorf("actor = %q/%q, want the caller", actx.ActorID, actx.ActorEmail)
	}
	if actx.TenantID != c.TenantID().String() {
		t.Errorf("tenant = %q, want the campaign's %q, not the request's", actx.TenantID, c.TenantID())
	}
}

func TestCampaignAudit_NoOpUpdateWritesNothing(t *testing.T) {
	svc, rec, c := newAuditedService(t, &fakeCounter{total: 4})
	name := c.Name()
	if _, err := svc.UpdateCampaign(context.Background(), c.TenantID().String(), c.ID().String(),
		UpdateRemediationCampaignInput{Name: &name}, actor); err != nil {
		t.Fatalf("UpdateCampaign: %v", err)
	}
	for _, a := range rec.actions() {
		if a == auditdom.ActionRemediationCampaignUpdated {
			t.Fatal("an update that changed nothing wrote an audit row")
		}
	}
}

func TestCampaignAudit_StatusChange(t *testing.T) {
	svc, rec, c := newAuditedService(t, &fakeCounter{total: 4})
	if _, err := svc.UpdateCampaignStatus(context.Background(), c.TenantID().String(), c.ID().String(), "active", actor); err != nil {
		t.Fatalf("activate: %v", err)
	}
	ev, actx := rec.only(t, auditdom.ActionRemediationCampaignStatusChanged)
	if ev.Changes.Before["status"] != "draft" || ev.Changes.After["status"] != "active" {
		t.Errorf("status change = %v -> %v, want draft -> active", ev.Changes.Before["status"], ev.Changes.After["status"])
	}
	if ev.Metadata["trigger"] != "manual" {
		t.Errorf("trigger = %v, want manual", ev.Metadata["trigger"])
	}
	if actx.ActorID != actor.ActorID {
		t.Errorf("actor = %q", actx.ActorID)
	}
}

// Completing a campaign while findings are still open is allowed (the UI
// confirms it first), but the audit row must say how many were left, and the
// counts it uses must be live rather than the last persisted ones.
func TestCampaignAudit_CompleteWithOpenFindingsRecordsLiveOpenCount(t *testing.T) {
	counter := &fakeCounter{total: 4, resolved: 0}
	svc, rec, c := newAuditedService(t, counter)
	ctx := context.Background()
	tid, cid := c.TenantID().String(), c.ID().String()
	if _, err := svc.UpdateCampaignStatus(ctx, tid, cid, "active", actor); err != nil {
		t.Fatalf("activate: %v", err)
	}
	// One finding closed since the last refresh: completion must see it.
	counter.resolved = 1
	got, err := svc.UpdateCampaignStatus(ctx, tid, cid, "completed", actor)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if got.ResolvedCount() != 1 || got.FindingCount() != 4 {
		t.Fatalf("counts at completion = %d/%d, want the live 1/4", got.ResolvedCount(), got.FindingCount())
	}
	if got.Progress() != 25 {
		t.Errorf("progress = %v, want 25", got.Progress())
	}

	var completed *auditapp.AuditEvent
	for i := range rec.events {
		ev := rec.events[i]
		if ev.Action == auditdom.ActionRemediationCampaignStatusChanged && ev.Changes.After["status"] == "completed" {
			completed = &ev
		}
	}
	if completed == nil {
		t.Fatalf("no completion audit event; got %v", rec.actions())
	}
	if completed.Metadata["open_findings"] != 3 {
		t.Errorf("open_findings = %v, want 3", completed.Metadata["open_findings"])
	}
	if completed.Severity != auditdom.SeverityMedium {
		t.Errorf("severity = %s, want medium for a completion with open findings", completed.Severity)
	}
}

func TestCampaignAudit_RejectedTransitionWritesNothing(t *testing.T) {
	svc, rec, c := newAuditedService(t, &fakeCounter{total: 4})
	// draft -> completed is not a legal move.
	if _, err := svc.UpdateCampaignStatus(context.Background(), c.TenantID().String(), c.ID().String(), "completed", actor); err == nil {
		t.Fatal("draft -> completed was accepted")
	}
	for _, a := range rec.actions() {
		if a == auditdom.ActionRemediationCampaignStatusChanged {
			t.Fatal("a rejected transition wrote a status_changed row")
		}
	}
}

func TestCampaignAudit_AutoCompleteIsAttributedToSystem(t *testing.T) {
	counter := &fakeCounter{total: 2, resolved: 0}
	svc, rec, c := newAuditedService(t, counter)
	if _, err := svc.UpdateCampaignStatus(context.Background(), c.TenantID().String(), c.ID().String(), "active", actor); err != nil {
		t.Fatalf("activate: %v", err)
	}
	counter.resolved = 2
	if _, err := svc.ReconcileProgress(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var found bool
	for i, ev := range rec.events {
		if ev.Action != auditdom.ActionRemediationCampaignStatusChanged || ev.Changes.After["status"] != "completed" {
			continue
		}
		found = true
		if ev.Metadata["trigger"] != "auto_complete" {
			t.Errorf("trigger = %v, want auto_complete", ev.Metadata["trigger"])
		}
		if got := rec.ctxs[i]; got.ActorEmail != "system" || got.ActorID != "" || got.TenantID != c.TenantID().String() {
			t.Errorf("auto-complete actor = %+v, want system in the campaign's tenant", got)
		}
	}
	if !found {
		t.Fatalf("auto-complete wrote no status_changed row; got %v", rec.actions())
	}
}

func TestCampaignAudit_Delete(t *testing.T) {
	svc, rec, c := newAuditedService(t, &fakeCounter{total: 4})
	if err := svc.DeleteCampaign(context.Background(), c.TenantID().String(), c.ID().String(), actor); err != nil {
		t.Fatalf("DeleteCampaign: %v", err)
	}
	ev, _ := rec.only(t, auditdom.ActionRemediationCampaignDeleted)
	if ev.ResourceName != "Patch log4j" {
		t.Errorf("resource name = %q", ev.ResourceName)
	}
}

// An audit write failure is logged, never turned into a failed request.
func TestCampaignAudit_FailureDoesNotFailTheChange(t *testing.T) {
	svc, rec, c := newAuditedService(t, &fakeCounter{total: 4})
	rec.err = errors.New("audit store down")
	if _, err := svc.UpdateCampaignStatus(context.Background(), c.TenantID().String(), c.ID().String(), "active", actor); err != nil {
		t.Fatalf("status change failed because the audit write failed: %v", err)
	}
}

func TestCampaignAudit_ActionsAreValid(t *testing.T) {
	for _, a := range []auditdom.Action{
		auditdom.ActionRemediationCampaignCreated, auditdom.ActionRemediationCampaignUpdated,
		auditdom.ActionRemediationCampaignStatusChanged, auditdom.ActionRemediationCampaignDeleted,
	} {
		if !a.IsValid() {
			t.Errorf("%s is not a valid action: its rows would be dropped", a)
		}
		if a.Category() != "remediation_campaign" {
			t.Errorf("%s category = %q", a, a.Category())
		}
	}
	if !auditdom.ResourceTypeRemediationCampaign.IsValid() {
		t.Error("resource type remediation_campaign is not valid")
	}
}
