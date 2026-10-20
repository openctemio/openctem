package integration

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
)

// Migration ticket_links_external_assignee: down drops the columns, up adds
// them back on a populated table with the defaults (unassigned, no
// category), and up again after down works.
func TestMigrationTicketLinksExternalAssignee_UpDownUp(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migtlext", dir)
	v := testdb.MigrationVersion(t, dir, "ticket_links_external_assignee")
	testdb.Migrate(t, db, dir, v, v, true)

	tenant, intg, asset, finding := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants (id, name, slug) VALUES ($1, 'T', 'mig-tlext')`, []any{tenant}},
		{`INSERT INTO integrations (id, tenant_id, name, category, provider, status, base_url) VALUES ($1, $2, 'j', 'ticketing', 'jira', 'connected', 'https://acme.atlassian.net')`, []any{intg, tenant}},
		{`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'a', 'repository')`, []any{asset, tenant}},
		{`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint) VALUES ($1::uuid, $2, $3, 'manual', 'm', 'x', 'high', $1::text)`, []any{finding, tenant, asset}},
		{`INSERT INTO ticket_links (tenant_id, integration_id, finding_id, external_key, url, source) VALUES ($1, $2, $3, 'SEC-1', 'https://acme.atlassian.net/browse/SEC-1', 'platform')`, []any{tenant, intg, finding}},
	} {
		if _, err := db.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}

	testdb.Migrate(t, db, dir, v, v, false)
	var id, name, cat string
	var at sql.NullTime
	if err := db.QueryRow(`SELECT external_assignee_id, external_assignee_name, external_status_category, external_updated_at FROM ticket_links WHERE tenant_id = $1`, tenant).
		Scan(&id, &name, &cat, &at); err != nil {
		t.Fatal(err)
	}
	if id != "" || name != "" || cat != "" || at.Valid {
		t.Fatalf("existing link after up: %q %q %q %v, want defaults", id, name, cat, at)
	}
	if _, err := db.Exec(`UPDATE ticket_links SET external_status_category = 'blocked' WHERE tenant_id = $1`, tenant); err == nil {
		t.Fatal("an unknown status category was accepted")
	}

	testdb.Migrate(t, db, dir, v, v, true)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'ticket_links' AND column_name LIKE 'external_assignee%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("down left %d external columns", n)
	}
	testdb.Migrate(t, db, dir, v, v, false)
}

// RecordExternal updates only the active links of the issue in the named
// tenant and integration (by id, or by key for links without an id),
// sanitizes the display name, and ignores an older change.
func TestTicketLinks_RecordExternal(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping ticket link DB test")
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

	type ten struct{ id, intgA, intgB, finding shared.ID }
	mk := func() ten {
		x := ten{shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()}
		asset := shared.NewID()
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO tenants (id, name, slug) VALUES ($1, 'TX', $2)`, []any{x.id.String(), "tx-" + strings.ReplaceAll(uuid.NewString()[:13], "-", "")}},
			{`INSERT INTO integrations (id, tenant_id, name, category, provider, status, base_url) VALUES ($1, $2, $3, 'ticketing', 'jira', 'connected', 'https://a.atlassian.net')`, []any{x.intgA.String(), x.id.String(), "a-" + x.intgA.String()}},
			{`INSERT INTO integrations (id, tenant_id, name, category, provider, status, base_url) VALUES ($1, $2, $3, 'ticketing', 'jira', 'connected', 'https://b.atlassian.net')`, []any{x.intgB.String(), x.id.String(), "b-" + x.intgB.String()}},
			{`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`, []any{asset.String(), x.id.String(), "a-" + asset.String()}},
			{`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint) VALUES ($1, $2, $3, 'manual', 'm', 'x', 'high', $4)`, []any{x.finding.String(), x.id.String(), asset.String(), uuid.NewString()}},
		} {
			if _, err := db.ExecContext(ctx, q.sql, q.args...); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() {
			bg := context.Background()
			for _, q := range []string{`DELETE FROM ticket_links WHERE tenant_id = $1`, `DELETE FROM findings WHERE tenant_id = $1`,
				`DELETE FROM assets WHERE tenant_id = $1`, `DELETE FROM integrations WHERE tenant_id = $1`, `DELETE FROM tenants WHERE id = $1`} {
				_, _ = db.ExecContext(bg, q, x.id.String())
			}
		})
		return x
	}
	a, b := mk(), mk()
	repo := postgres.NewTicketLinkRepository(&postgres.DB{DB: db})
	link := func(tenant, intg, finding shared.ID, site, key, issueID string) *ticketlink.Link {
		l, err := ticketlink.New(tenant, intg, ticketlink.ForFinding(finding), key, issueID, site, site+"/browse/"+key, ticketlink.RoleOwn, ticketlink.SourcePlatform, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.Create(ctx, l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	la := link(a.id, a.intgA, a.finding, "https://a.atlassian.net", "SEC-1", "100")
	lb := link(a.id, a.intgB, a.finding, "https://b.atlassian.net", "SEC-1", "")
	lOther := link(b.id, b.intgB, b.finding, "https://b.atlassian.net", "SEC-1", "100")

	now := time.Now().UTC().Truncate(time.Millisecond)
	ch := ticketlink.ExternalChange{AssigneeSet: true, AssigneeID: "acc-1", AssigneeName: "<b>Dana</b>‮ K.", StatusCategory: ticketlink.StatusCategoryInProgress, At: now}
	got, err := repo.RecordExternal(ctx, a.id, a.intgA, "100", "SEC-1", ch)
	if err != nil || len(got) != 1 || got[0].ID != la.ID {
		t.Fatalf("record on A: %v %+v", err, got)
	}
	if got[0].External.AssigneeName != "Dana K." || got[0].External.StatusCategory != "in_progress" {
		t.Fatalf("stored %+v", got[0].External)
	}
	read := func(tenant, id shared.ID) ticketlink.External {
		t.Helper()
		l, err := repo.Get(ctx, tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		return l.External
	}
	if e := read(a.id, lb.ID); e.AssigneeID != "" {
		t.Fatalf("integration B's link changed: %+v", e)
	}
	if e := read(b.id, lOther.ID); e.AssigneeID != "" {
		t.Fatalf("another tenant's link changed: %+v", e)
	}
	// Cross-tenant: tenant b naming tenant a's integration matches nothing.
	if got, err := repo.RecordExternal(ctx, b.id, a.intgA, "100", "SEC-1", ch); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant record: %v %d", err, len(got))
	}
	// Older change ignored; unassign later clears.
	old := ch
	old.AssigneeID, old.At = "old", now.Add(-time.Minute)
	if got, _ := repo.RecordExternal(ctx, a.id, a.intgA, "100", "SEC-1", old); len(got) != 0 || read(a.id, la.ID).AssigneeID != "acc-1" {
		t.Fatal("an older change rolled the assignee back")
	}
	un := ticketlink.ExternalChange{AssigneeSet: true, At: now.Add(time.Minute)}
	if got, _ := repo.RecordExternal(ctx, a.id, a.intgA, "100", "", un); len(got) != 1 {
		t.Fatal("unassign by id did not match")
	}
	if e := read(a.id, la.ID); e.AssigneeID != "" || e.AssigneeName != "" || e.StatusCategory != "in_progress" {
		t.Fatalf("after unassign: %+v (the category stays)", e)
	}
	// Unlinking a link clears its tracker account.
	if _, err := repo.RecordExternal(ctx, a.id, a.intgA, "100", "", ticketlink.ExternalChange{AssigneeSet: true, AssigneeID: "acc-2", AssigneeName: "Lee", At: now.Add(2 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetState(ctx, a.id, la.ID, ticketlink.StateUnlinked); err != nil {
		t.Fatal(err)
	}
	if e := read(a.id, la.ID); e.AssigneeID != "" || e.AssigneeName != "" {
		t.Fatalf("unlinked link kept the tracker account: %+v", e)
	}
	// A link without an id is matched by key in its own integration.
	if got, _ := repo.RecordExternal(ctx, a.id, a.intgB, "999", "SEC-1", ch); len(got) != 1 || got[0].ID != lb.ID {
		t.Fatalf("key fallback: %+v", got)
	}
}
