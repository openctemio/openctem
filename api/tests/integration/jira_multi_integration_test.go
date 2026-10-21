package integration

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	appjira "github.com/openctemio/openctem/api/internal/app/jira"
	infrajira "github.com/openctemio/openctem/api/internal/infra/jira"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// recordingApplier records the findings an inbound delivery would move.
type recordingApplier struct{ ids []shared.ID }

func (a *recordingApplier) ApplyTicketStatus(_ context.Context, _ shared.ID, ids []shared.ID,
	_ vulnerability.FindingStatus, _, _, _ string,
) ([]shared.ID, []appjira.InboundRefusal, error) {
	a.ids = append(a.ids, ids...)
	return ids, nil, nil
}

func (a *recordingApplier) RequestTicketDisposition(_ context.Context, _ shared.ID, ids []shared.ID,
	_ vulnerability.FindingStatus, _, _, _ string,
) ([]shared.ID, []shared.ID, []appjira.InboundRefusal, error) {
	return ids, nil, nil, nil
}

// An organization with two Jira integrations (two sites) that both have an
// issue SEC-1: a delivery verified for one integration moves only the links
// of that integration, matched by the issue's id first; another tenant's
// integration id moves nothing; a moved issue is still matched by its id; a
// key now worn by another issue matches no link that recorded an id.
func TestJiraInbound_ScopedToTheDeliveringIntegration(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping jira multi-integration DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		testdb.Skipf(t, "database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}

	const cfg = `{"ticketing":{"project_key":"SEC"}}`
	tenant := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'JM', $2)`, id.String(), "jm-"+strings.ReplaceAll(uuid.NewString()[:13], "-", ""))
		t.Cleanup(func() {
			bg := context.Background()
			for _, q := range []string{
				`DELETE FROM ticket_links WHERE tenant_id = $1`, `DELETE FROM findings WHERE tenant_id = $1`,
				`DELETE FROM assets WHERE tenant_id = $1`, `DELETE FROM integrations WHERE tenant_id = $1`,
				`DELETE FROM tenants WHERE id = $1`,
			} {
				_, _ = db.ExecContext(bg, q, id.String())
			}
		})
		return id
	}
	integration := func(tenantID shared.ID, site string) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO integrations (id, tenant_id, name, category, provider, status, base_url, config)
			VALUES ($1, $2, $3, 'ticketing', 'jira', 'connected', $4, $5::jsonb)`, id.String(), tenantID.String(), "j-"+id.String(), site, cfg)
		return id
	}
	finding := func(tenantID shared.ID, urls ...string) shared.ID {
		asset, id := shared.NewID(), shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`, asset.String(), tenantID.String(), "a-"+asset.String())
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, work_item_uris)
			VALUES ($1, $2, $3, 'manual', 'm', 'x', 'high', $4, 'in_progress', $5::text[])`,
			id.String(), tenantID.String(), asset.String(), uuid.NewString(), "{"+strings.Join(urls, ",")+"}")
		return id
	}
	links := postgres.NewTicketLinkRepository(&postgres.DB{DB: db})
	link := func(tenantID, intg, findingID shared.ID, site, key, issueID string) {
		l, err := ticketlink.New(tenantID, intg, ticketlink.ForFinding(findingID), key, issueID, site, ticketlink.BrowseURL(site, key),
			ticketlink.RoleOwn, ticketlink.SourcePlatform, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := links.Create(ctx, l); err != nil {
			t.Fatal(err)
		}
	}

	const siteA, siteB = "https://site-a.atlassian.net", "https://site-b.atlassian.net"
	org, other := tenant(), tenant()
	intgA, intgB := integration(org, siteA), integration(org, siteB)
	intgOther := integration(other, siteB)

	fA := finding(org)
	fB := finding(org)
	fLegacyA := finding(org, siteA+"/browse/SEC-1") // a URL-only link on site A
	fOther := finding(other)
	link(org, intgA, fA, siteA, "SEC-1", "100")
	link(org, intgB, fB, siteB, "SEC-1", "200")
	link(other, intgOther, fOther, siteB, "SEC-1", "200")

	findingRepo := postgres.NewFindingRepository(&postgres.DB{DB: db})
	resolver := infrajira.NewIntegrationClientResolver(postgres.NewIntegrationRepository(&postgres.DB{DB: db}), nil, logger.NewNop())
	deliver := func(tenantID, integrationID shared.ID, key, issueID string) []string {
		t.Helper()
		svc := appjira.NewSyncService(findingRepo, nil, logger.NewNop())
		svc.SetClientResolver(resolver)
		svc.SetMappingResolver(resolver)
		svc.SetLinkStore(links)
		svc.SetWorkItemFindingLister(findingRepo)
		app := &recordingApplier{}
		svc.SetInboundApplier(app)
		err := svc.HandleJiraWebhook(ctx, tenantID, integrationID, appjira.WebhookPayload{
			WebhookEvent: "jira:issue_updated",
			Issue:        appjira.WebhookIssue{ID: issueID, Key: key},
			Changelog:    &appjira.Changelog{Items: []appjira.ChangeItem{{Field: "status", ToString: "Done"}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(app.ids))
		for _, id := range app.ids {
			out = append(out, id.String())
		}
		sort.Strings(out)
		return out
	}
	want := func(ids ...shared.ID) []string {
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			out = append(out, id.String())
		}
		sort.Strings(out)
		return out
	}
	eq := func(name string, got, exp []string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(exp, ",") {
			t.Errorf("%s: moved %v, want %v", name, got, exp)
		}
	}

	eq("delivery for B", deliver(org, intgB, "SEC-1", "200"), want(fB))
	eq("delivery for A", deliver(org, intgA, "SEC-1", "100"), want(fA, fLegacyA))
	eq("another tenant's integration id", deliver(org, intgOther, "SEC-1", "200"), nil)
	eq("the other tenant's own delivery", deliver(other, intgOther, "SEC-1", "200"), want(fOther))
	eq("moved issue matched by id", deliver(org, intgB, "SEC-77", "200"), want(fB))
	eq("key worn by another issue", deliver(org, intgB, "SEC-1", "999"), nil)

	// The repository lookup by issue id is tenant- and integration-scoped.
	if ls, _ := links.FindByIssueID(ctx, org, intgOther, "200"); len(ls) != 0 {
		t.Error("issue-id lookup crossed tenants")
	}
	if ls, _ := links.FindByIssueID(ctx, org, intgA, "200"); len(ls) != 0 {
		t.Error("issue-id lookup crossed integrations")
	}
	if ls, _ := links.FindByIssueID(ctx, org, intgB, ""); len(ls) != 0 {
		t.Error("an empty issue id matched links")
	}
}
