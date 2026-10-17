package integration

import (
	"context"
	"database/sql"
	"errors"
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

// Ticket links (research 157): tenant-scoped reads and writes, one active
// link per object and issue, and the database refusing a link that pairs a
// tenant with another tenant's integration or finding.
func TestTicketLinks_IsolationAndUniqueness(t *testing.T) {
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

	type ten struct{ id, intg, asset, finding shared.ID }
	mk := func() ten {
		x := ten{shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()}
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO tenants (id, name, slug) VALUES ($1, 'TL', $2)`, []any{x.id.String(), "tl-" + strings.ReplaceAll(uuid.NewString()[:13], "-", "")}},
			{`INSERT INTO integrations (id, tenant_id, name, category, provider, status, base_url) VALUES ($1, $2, 'j', 'ticketing', 'jira', 'connected', 'https://acme.atlassian.net')`, []any{x.intg.String(), x.id.String()}},
			{`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'a', 'repository')`, []any{x.asset.String(), x.id.String()}},
			{`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint) VALUES ($1, $2, $3, 'manual', 'm', 'x', 'high', $4)`, []any{x.finding.String(), x.id.String(), x.asset.String(), uuid.NewString()}},
		} {
			if _, err := db.ExecContext(ctx, q.sql, q.args...); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() {
			bg := context.Background()
			_, _ = db.ExecContext(bg, `DELETE FROM ticket_links WHERE tenant_id = $1`, x.id.String())
			_, _ = db.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, x.id.String())
			_, _ = db.ExecContext(bg, `DELETE FROM assets WHERE tenant_id = $1`, x.id.String())
			_, _ = db.ExecContext(bg, `DELETE FROM integrations WHERE tenant_id = $1`, x.id.String())
			_, _ = db.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, x.id.String())
		})
		return x
	}
	a, b := mk(), mk()
	repo := postgres.NewTicketLinkRepository(&postgres.DB{DB: db})

	link := func(tenant, intg, finding shared.ID, key string) *ticketlink.Link {
		l, err := ticketlink.New(tenant, intg, ticketlink.ForFinding(finding), key, "100", "https://acme.atlassian.net", "https://acme.atlassian.net/browse/"+key, ticketlink.RoleOwn, ticketlink.SourcePerson, nil)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	l1 := link(a.id, a.intg, a.finding, "SEC-1")
	if err := repo.Create(ctx, l1); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, link(a.id, a.intg, a.finding, "SEC-1")); !errors.Is(err, ticketlink.ErrAlreadyLinked) {
		t.Fatalf("duplicate active link: %v", err)
	}
	// The database refuses another tenant's integration or finding.
	if err := repo.Create(ctx, link(a.id, b.intg, a.finding, "SEC-2")); err == nil {
		t.Fatal("link with another tenant's integration accepted")
	}
	if err := repo.Create(ctx, link(a.id, a.intg, b.finding, "SEC-3")); err == nil {
		t.Fatal("link with another tenant's finding accepted")
	}
	// Reads are tenant-scoped.
	if _, err := repo.Get(ctx, b.id, l1.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if ls, _ := repo.FindByIssue(ctx, b.id, a.intg, "SEC-1"); len(ls) != 0 {
		t.Fatal("cross-tenant issue lookup")
	}
	if ls, _ := repo.ListForFinding(ctx, b.id, a.finding); len(ls) != 0 {
		t.Fatal("cross-tenant finding lookup")
	}
	if err := repo.SetState(ctx, b.id, l1.ID, ticketlink.StateUnlinked); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant unlink: %v", err)
	}
	ls, err := repo.FindByIssue(ctx, a.id, a.intg, "SEC-1")
	if err != nil || len(ls) != 1 {
		t.Fatalf("issue lookup: %v %d", err, len(ls))
	}
	if err := repo.RecordSync(ctx, a.id, l1.ID, "In Progress", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	// Unlink, then the same issue can be linked again.
	if err := repo.SetState(ctx, a.id, l1.ID, ticketlink.StateUnlinked); err != nil {
		t.Fatal(err)
	}
	if ls, _ := repo.FindByIssue(ctx, a.id, a.intg, "SEC-1"); len(ls) != 0 {
		t.Fatal("unlinked link still active")
	}
	if err := repo.Create(ctx, link(a.id, a.intg, a.finding, "SEC-1")); err != nil {
		t.Fatalf("relink: %v", err)
	}
	// Deleting the finding deletes its links.
	if _, err := db.ExecContext(ctx, `DELETE FROM findings WHERE id = $1`, a.finding.String()); err != nil {
		t.Fatal(err)
	}
	if ls, _ := repo.ListForFinding(ctx, a.id, a.finding); len(ls) != 0 {
		t.Fatal("links outlived their finding")
	}
}

// Task links: one object per link (the database refuses a finding and a task
// together), another tenant's task is refused, reads are tenant-scoped, and
// the reconciler sees a task whose state moved since the last push.
func TestTicketLinks_Tasks(t *testing.T) {
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
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	type ten struct{ id, intg, task, finding shared.ID }
	mk := func() ten {
		x := ten{shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()}
		action := shared.NewID()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'TT', $2)`, x.id.String(), "tt-"+strings.ReplaceAll(uuid.NewString()[:13], "-", ""))
		exec(`INSERT INTO integrations (id, tenant_id, name, category, provider, status, base_url) VALUES ($1, $2, 'j', 'ticketing', 'jira', 'connected', 'https://acme.atlassian.net')`, x.intg.String(), x.id.String())
		exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint) VALUES ($1, $2, 'manual', 'm', 'x', 'high', $3)`, x.finding.String(), x.id.String(), uuid.NewString())
		exec(`INSERT INTO remediation_actions (id, tenant_id, action_key, kind, title, origin) VALUES ($1, $2, $3, 'manual', 'fix', 'manual')`, action.String(), x.id.String(), "manual:"+action.String())
		exec(`INSERT INTO remediation_tasks (id, tenant_id, action_id, title, state) VALUES ($1, $2, $3, 'Upgrade', 'open')`, x.task.String(), x.id.String(), action.String())
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, x.id.String())
		})
		return x
	}
	a, b := mk(), mk()
	repo := postgres.NewTicketLinkRepository(&postgres.DB{DB: db})
	taskLink := func(tenant, intg, task shared.ID, key string) *ticketlink.Link {
		l, err := ticketlink.New(tenant, intg, ticketlink.ForTask(task), key, "1", "https://acme.atlassian.net", "https://acme.atlassian.net/browse/"+key, ticketlink.RoleOwn, ticketlink.SourcePerson, nil)
		if err != nil {
			t.Fatal(err)
		}
		l.LastPushedState = "open"
		return l
	}
	l := taskLink(a.id, a.intg, a.task, "OPS-1")
	if err := repo.Create(ctx, l); err != nil {
		t.Fatal(err)
	}
	got, err := repo.ListForTask(ctx, a.id, a.task)
	if err != nil || len(got) != 1 || got[0].TaskID == nil || *got[0].TaskID != a.task || got[0].LastPushedState != "open" {
		t.Fatalf("list: %v %+v", err, got)
	}
	// Another tenant's task, or a link naming a finding and a task, is refused.
	if err := repo.Create(ctx, taskLink(a.id, a.intg, b.task, "OPS-2")); err == nil {
		t.Fatal("link to another tenant's task accepted")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO ticket_links (tenant_id, integration_id, finding_id, task_id, external_key, url, source)
		VALUES ($1, $2, $3, $4, 'OPS-3', 'https://acme.atlassian.net/browse/OPS-3', 'person')`,
		a.id.String(), a.intg.String(), a.finding.String(), a.task.String()); err == nil {
		t.Fatal("a link naming a finding and a task accepted")
	}
	if ls, _ := repo.ListForTask(ctx, b.id, a.task); len(ls) != 0 {
		t.Fatal("cross-tenant task lookup")
	}

	behind := func() bool {
		t.Helper()
		refs, err := repo.TaskLinksBehindForPlatform(ctx, 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range refs {
			if r.TaskID == a.task {
				if r.TenantID != a.id {
					t.Fatalf("task paired with tenant %s", r.TenantID)
				}
				return true
			}
		}
		return false
	}
	if behind() {
		t.Fatal("an unchanged task is behind")
	}
	exec(`UPDATE remediation_tasks SET state = 'in_progress' WHERE id = $1`, a.task.String())
	if !behind() {
		t.Fatal("a moved task is not behind")
	}
	if err := repo.RecordPush(ctx, a.id, l.ID, "in_progress", "In Progress", time.Now()); err != nil {
		t.Fatal(err)
	}
	if behind() {
		t.Fatal("a pushed task is still behind")
	}
	if err := repo.RecordPush(ctx, b.id, l.ID, "done", "Done", time.Now()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant push record: %v", err)
	}
	// Deleting the task deletes its links.
	exec(`DELETE FROM remediation_tasks WHERE id = $1`, a.task.String())
	if ls, _ := repo.ListForTask(ctx, a.id, a.task); len(ls) != 0 {
		t.Fatal("links outlived their task")
	}
}
