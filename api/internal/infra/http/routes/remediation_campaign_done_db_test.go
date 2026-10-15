package routes

// A remediation campaign is done only when its findings say so (research 156
// B13, owner decision D3): every finding closed AND at least one verified
// fixed (resolved). Completing anything less needs an explicit, audited
// override; a closed Jira epic never completes an unfinished campaign. A
// completed campaign can be reopened, and a failed validation returns it to
// active. A campaign deadline only tightens.

import (
	"context"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestRemediationCampaign_DoneMeansFixed_DB(t *testing.T) {
	e := newCampaignSaveEnv(t)
	ctx := context.Background()
	setStatuses := func(a, b string) {
		e.h.exec(`UPDATE findings SET status = $2 WHERE tenant_id = $1 AND id = $3`, e.h.tenant.String(), a, e.h.findingA.String())
		e.h.exec(`UPDATE findings SET status = $2 WHERE tenant_id = $1 AND id = $3`, e.h.tenant.String(), b, e.h.findingB.String())
	}
	id := e.campaign("active")
	path := "/api/v1/remediation/campaigns/" + id.String()

	// Every finding closed, none fixed (accepted + false positive).
	setStatuses("accepted", "false_positive")
	if _, err := e.svc.ReconcileProgress(ctx); err != nil {
		t.Fatal(err)
	}
	if r := e.row(t, id); r.status != "active" {
		t.Fatalf("auto-complete with nothing fixed: status %s", r.status)
	}
	code, got := e.call(t, http.MethodGet, path, nil)
	if code != http.StatusOK || got["verified_count"] != float64(0) {
		t.Fatalf("GET = %d verified_count %v, want 0", code, got["verified_count"])
	}
	if code, _ := e.call(t, http.MethodPatch, path+"/status", map[string]any{"status": "completed"}); code != http.StatusBadRequest {
		t.Fatalf("manual complete of an unfinished campaign = %d, want 400", code)
	}

	// A closed Jira epic is a claim, not evidence.
	e.svc.SetTicketing(postgres.NewRemediationCampaignTicketRepository(&postgres.DB{DB: e.h.db}), nil)
	e.h.exec(`INSERT INTO remediation_campaign_tickets (id, tenant_id, campaign_id, provider, issue_key, issue_url)
		VALUES ($1, $2, $3, 'jira', 'SEC-1', 'https://jira.example.test/browse/SEC-1')`, shared.NewID().String(), e.h.tenant.String(), id.String())
	if err := e.svc.HandleEpicStatusChange(ctx, e.h.tenant, "SEC-1", "Done"); err != nil {
		t.Fatal(err)
	}
	if r := e.row(t, id); r.status != "active" {
		t.Fatalf("epic Done completed an unfinished campaign: %s", r.status)
	}

	// The explicit override completes it (and is audited as such).
	if code, got := e.call(t, http.MethodPatch, path+"/status", map[string]any{"status": "completed", "close_with_open_members": true}); code != http.StatusOK || got["status"] != "completed" {
		t.Fatalf("complete with the override = %d %v", code, got["status"])
	}

	// Reopen: completed -> active, completion time cleared.
	code, got = e.call(t, http.MethodPatch, path+"/status", map[string]any{"status": "active"})
	if code != http.StatusOK || got["status"] != "active" || got["completed_at"] != nil {
		t.Fatalf("reopen = %d status %v completed_at %v", code, got["status"], got["completed_at"])
	}

	// Validation failed: validating -> active.
	if code, _ := e.call(t, http.MethodPatch, path+"/status", map[string]any{"status": "validating"}); code != http.StatusOK {
		t.Fatalf("start validation = %d", code)
	}
	if code, got := e.call(t, http.MethodPatch, path+"/status", map[string]any{"status": "active"}); code != http.StatusOK || got["status"] != "active" {
		t.Fatalf("validating -> active = %d %v", code, got["status"])
	}

	// One verified fix and everything closed: done, the reconciler and the
	// epic both complete it.
	setStatuses("resolved", "false_positive")
	if err := e.svc.HandleEpicStatusChange(ctx, e.h.tenant, "SEC-1", "Done"); err != nil {
		t.Fatal(err)
	}
	if r := e.row(t, id); r.status != "completed" {
		t.Fatalf("epic Done on a finished campaign: status %s", r.status)
	}
	other := e.campaign("active")
	if _, err := e.svc.ReconcileProgress(ctx); err != nil {
		t.Fatal(err)
	}
	if r := e.row(t, other); r.status != "completed" {
		t.Fatalf("auto-complete with a verified fix: status %s", r.status)
	}
}

func TestRemediationCampaign_DeadlineOnlyTightens_DB(t *testing.T) {
	e := newCampaignSaveEnv(t)
	id := e.campaign("active")
	path := "/api/v1/remediation/campaigns/" + id.String()
	if code, _ := e.call(t, http.MethodPatch, path, map[string]any{"due_date": "2026-11-30"}); code != http.StatusOK {
		t.Fatalf("first due date = %d", code)
	}
	for _, later := range []any{"2026-12-01", nil} {
		if code, _ := e.call(t, http.MethodPatch, path, map[string]any{"due_date": later}); code != http.StatusBadRequest {
			t.Fatalf("due date %v = %d, want 400", later, code)
		}
	}
	if code, _ := e.call(t, http.MethodPatch, path, map[string]any{"due_date": "2026-11-20"}); code != http.StatusOK {
		t.Fatalf("earlier due date = %d", code)
	}
	var due string
	if err := e.h.db.QueryRowContext(context.Background(), `SELECT due_date::text FROM remediation_campaigns WHERE tenant_id = $1 AND id = $2`,
		e.h.tenant.String(), id.String()).Scan(&due); err != nil || due != "2026-11-20" {
		t.Fatalf("stored due date = %q (%v), want 2026-11-20", due, err)
	}
}
