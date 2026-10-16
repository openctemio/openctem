package routes

// An inbound Jira status change over a migrated database goes through the
// finding service rules for EVERY finding linked to the issue (not one
// arbitrary finding, not a direct row write): "Done" is a fix claim (legal
// steps to fix_applied, proof of fix queued per finding), never a close;
// closed findings and another tenant's finding with the same issue URL are
// left alone; each refusal is commented back on the issue, once.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/jira"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type commentClient struct {
	jira.Client
	mu       sync.Mutex
	comments []string
}

func (c *commentClient) AddComment(_ context.Context, _ string, body string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.comments = append(c.comments, body)
	return nil
}

type onceGuard struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (g *onceGuard) FirstDelivery(_ context.Context, key string, _ time.Duration) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen[key] {
		return false, nil
	}
	g.seen[key] = true
	return true, nil
}

// testTicketApplier is the composition-root adapter (cmd/server) for the test.
type testTicketApplier struct{ vuln *finding.VulnerabilityService }

func (a testTicketApplier) ApplyTicketStatus(ctx context.Context, tenantID shared.ID, ids []shared.ID,
	target vulnerability.FindingStatus, integration, ref, externalActor string,
) ([]shared.ID, []jira.InboundRefusal, error) {
	out, err := a.vuln.ApplyTicketStatus(ctx, tenantID, ids, target, integration, ref, externalActor)
	if err != nil {
		return nil, nil, err
	}
	refused := make([]jira.InboundRefusal, 0, len(out.Refused))
	for _, r := range out.Refused {
		refused = append(refused, jira.InboundRefusal{FindingID: r.FindingID, Reason: r.Reason})
	}
	return out.Applied, refused, nil
}

func TestJiraInbound_ServicePathForEveryLinkedFinding(t *testing.T) {
	h := newGroupScopeHarness(t)
	db := &postgres.DB{DB: h.db}
	findingRepo := postgres.NewFindingRepository(db)
	var queued []shared.ID
	h.vuln.SetProofOfFixQueuer(func(_ context.Context, _ shared.ID, ids []shared.ID) int {
		queued = append(queued, ids...)
		return len(ids)
	})

	issue := "SEC-" + shared.NewID().String()[:8]
	url := "https://acme.atlassian.net/browse/" + issue
	add := func(tenant, asset shared.ID, status string) shared.ID {
		id := shared.NewID()
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, work_item_uris)
			VALUES ($1::uuid, $2, $3, 'sast', 'jira-inbound', 'linked to one issue', 'high', $1::text, $4, ARRAY[$5]::text[])`,
			id.String(), tenant.String(), asset.String(), status, url)
		return id
	}
	fNew := add(h.tenant, h.assetA, "new")
	fConfirmed := add(h.tenant, h.assetA, "confirmed")
	fInProgress := add(h.tenant, h.assetB, "in_progress")
	fResolved := add(h.tenant, h.assetA, "resolved")

	other, otherAsset := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "jira-inbound-"+other.String())
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'other-tenant.example.com', 'domain', 'public', 'high')`,
		otherAsset.String(), other.String())
	fOther := add(other, otherAsset, "in_progress")

	client := &commentClient{}
	sync := jira.NewSyncService(findingRepo, client, logger.NewNop())
	sync.SetInboundApplier(testTicketApplier{vuln: h.vuln})
	sync.SetWorkItemFindingLister(findingRepo)
	sync.SetRefusalCommentGuard(&onceGuard{seen: map[string]bool{}})

	payload := func(status string) jira.WebhookPayload {
		return jira.WebhookPayload{
			WebhookEvent: "jira:issue_updated",
			User:         jira.WebhookUser{AccountID: "5b10ac8d82e05b22cc7d4ef5"},
			Issue:        jira.WebhookIssue{Key: issue, Self: "https://acme.atlassian.net/rest/api/2/issue/10001"},
			Changelog:    &jira.Changelog{Items: []jira.ChangeItem{{Field: "status", ToString: status}}},
		}
	}
	// The browse URL is derived from the key; make sure it matches ours.
	if err := sync.HandleJiraWebhook(context.Background(), h.tenant, payload("Done")); err != nil {
		t.Fatal(err)
	}
	for _, id := range []shared.ID{fNew, fConfirmed, fInProgress} {
		if st, res, _ := h.findingRow(id); st != "fix_applied" || !strings.Contains(res, issue) {
			t.Errorf("linked finding %s = %s (%q), want fix_applied with the ticket in the note", id, st, res)
		}
	}
	if st, _, _ := h.findingRow(fResolved); st != "resolved" {
		t.Errorf("a resolved finding was moved to %s by a ticket", st)
	}
	var otherStatus string
	if err := h.db.QueryRow(`SELECT status FROM findings WHERE id = $1`, fOther.String()).Scan(&otherStatus); err != nil {
		t.Fatal(err)
	}
	if otherStatus != "in_progress" {
		t.Errorf("another tenant's finding with the same issue URL moved to %s", otherStatus)
	}
	if len(queued) != 3 {
		t.Errorf("proof of fix queued for %d findings, want 3", len(queued))
	}

	// The integration is the recorded actor of each step (new took three).
	var steps int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'status_changed'`,
		fNew.String()).Scan(&steps); err != nil {
		t.Fatal(err)
	}
	if steps < 3 {
		t.Errorf("the new finding's legal steps recorded %d status changes, want 3", steps)
	}

	// The Jira account that moved the issue is in the note and the timeline.
	if _, res, _ := h.findingRow(fConfirmed); !strings.Contains(res, "5b10ac8d82e05b22cc7d4ef5") {
		t.Errorf("note %q does not name the Jira account", res)
	}
	var withAccount int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND changes::text LIKE '%5b10ac8d82e05b22cc7d4ef5%'`,
		fNew.String()).Scan(&withAccount); err != nil {
		t.Fatal(err)
	}
	if withAccount == 0 {
		t.Error("no timeline entry records the Jira account")
	}

	// The resolved finding's refusal is commented back, with its reason.
	if len(client.comments) != 1 || !strings.Contains(client.comments[0], strings.ReplaceAll(fResolved.String(), "-", `\-`)) {
		t.Fatalf("refusal comments = %q, want one naming the resolved finding", client.comments)
	}

	// A repeated delivery does not comment again.
	if err := sync.HandleJiraWebhook(context.Background(), h.tenant, payload("Done")); err != nil {
		t.Fatal(err)
	}
	if len(client.comments) != 1 {
		t.Errorf("a repeated Done commented %d times, want once", len(client.comments))
	}

	// Reopened in Jira: fix_applied findings go back to in_progress, legally.
	if err := sync.HandleJiraWebhook(context.Background(), h.tenant, payload("In Progress")); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := h.findingRow(fNew); st != "in_progress" {
		t.Errorf("In Progress after Done = %s, want in_progress", st)
	}
}

func TestTicketPath_OnlyOpenLegalSteps(t *testing.T) {
	cases := []struct {
		from, to vulnerability.FindingStatus
		want     string
		ok       bool
	}{
		{vulnerability.FindingStatusNew, vulnerability.FindingStatusInProgress, "confirmed,in_progress", true},
		{vulnerability.FindingStatusNew, vulnerability.FindingStatusFixApplied, "confirmed,in_progress,fix_applied", true},
		{vulnerability.FindingStatusFixApplied, vulnerability.FindingStatusConfirmed, "in_progress,confirmed", true},
		{vulnerability.FindingStatusResolved, vulnerability.FindingStatusInProgress, "", false},
		{vulnerability.FindingStatusConfirmed, vulnerability.FindingStatusResolved, "", false},
	}
	for _, c := range cases {
		path, ok := finding.TicketPath(c.from, c.to)
		got := make([]string, len(path))
		for i, p := range path {
			got[i] = p.String()
		}
		if ok != c.ok || strings.Join(got, ",") != c.want {
			t.Errorf("TicketPath(%s, %s) = %v %v, want %q %v", c.from, c.to, got, ok, c.want, c.ok)
		}
	}
}
