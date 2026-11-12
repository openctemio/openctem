package wordlist

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"sync"
	"testing"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	dom "github.com/openctemio/openctem/api/pkg/domain/wordlist"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordedAudit struct {
	mu     sync.Mutex
	events []auditapp.AuditEvent
}

func (r *recordedAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newTenant(t *testing.T, db *sql.DB) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'wl', $2)`, id.String(), "wl-"+id.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String()) })
	return id
}

// Organization wordlists through Postgres (migration
// tenant_wordlists_and_content_pins): create with a report, edit (the
// version rises only when labels change), the enabled set in creation
// order, unique names, the per-organization cap, audit metadata without
// labels, and tenant isolation: another organization's list is not found
// for read, update or delete, and never in its enabled set. Requires
// DATABASE_URL.
func TestWordlistService_DB(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	repo := postgres.NewTenantWordlistRepository(&postgres.DB{DB: db})
	audit := &recordedAudit{}
	svc := NewService(repo, audit, logger.NewNop())
	a, b := newTenant(t, db), newTenant(t, db)
	actxA := auditapp.AuditContext{TenantID: a.String()}
	actxB := auditapp.AuditContext{TenantID: b.String()}

	first, rep, err := svc.Create(ctx, actxA, CreateInput{Name: "branches", Text: "hn01\nHN01\nhcm02\n*.x\n"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != 1 || first.Lines != 2 || !first.Enabled || rep.Kept != 2 || rep.Duplicates != 1 || rep.Invalid != 1 {
		t.Fatalf("created %+v report %+v", first, rep)
	}
	off := false
	second, _, err := svc.Create(ctx, actxA, CreateInput{Name: "words", Text: "hocvien\n", Enabled: &off})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Create(ctx, actxA, CreateInput{Name: "branches", Text: "x1\n"}); !errors.Is(err, dom.ErrNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}
	// Another organization may use the same name.
	other, _, err := svc.Create(ctx, actxB, CreateInput{Name: "branches", Text: "payroll\n"})
	if err != nil {
		t.Fatal(err)
	}

	// Only enabled lists, in creation order.
	enabled, err := repo.Enabled(ctx, a, dom.PurposeDNSLabels)
	if err != nil || len(enabled) != 1 || enabled[0].ID != first.ID {
		t.Fatalf("enabled %v %v", enabled, err)
	}
	on := true
	if _, _, err := svc.Update(ctx, actxA, second.ID.String(), UpdateInput{Enabled: &on}); err != nil {
		t.Fatal(err)
	}
	enabled, _ = repo.Enabled(ctx, a, dom.PurposeDNSLabels)
	if len(enabled) != 2 || enabled[0].ID != first.ID || enabled[1].ID != second.ID {
		t.Fatalf("enabled order %v", enabled)
	}

	// Same labels: version unchanged; new labels: version 2.
	same := "# same labels\nhn01\nhcm02\n"
	if w, _, err := svc.Update(ctx, actxA, first.ID.String(), UpdateInput{Text: &same}); err != nil || w.Version != 1 || w.SHA256 != first.SHA256 {
		t.Fatalf("same labels changed the version: %+v %v", w, err)
	}
	newText := "hn01\nhcm02\ndn03\n"
	w, rep, err := svc.Update(ctx, actxA, first.ID.String(), UpdateInput{Text: &newText})
	if err != nil {
		t.Fatal(err)
	}
	if w.Lines != 3 || rep.Kept != 3 || w.Version != 2 {
		t.Fatalf("after update %+v", w)
	}
	got, err := svc.Get(ctx, actxA, first.ID.String())
	if err != nil || got.Content != "hn01\nhcm02\ndn03\n" || got.Version != 2 {
		t.Fatalf("get %+v %v", got, err)
	}

	// Tenant isolation: B cannot see, change or delete A's list.
	if _, err := svc.Get(ctx, actxB, first.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	name := "stolen"
	if _, _, err := svc.Update(ctx, actxB, first.ID.String(), UpdateInput{Name: &name}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
	if err := svc.Delete(ctx, actxB, first.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	if err := repo.Update(ctx, &dom.Wordlist{ID: first.ID, TenantID: b, Name: "x", Version: 9, Lines: 1, SHA256: first.SHA256, Content: "x\n"}); !errors.Is(err, dom.ErrNotFound) {
		t.Fatalf("repository update under another tenant: %v", err)
	}
	listB, _ := svc.List(ctx, actxB)
	if len(listB) != 1 || listB[0].ID != other.ID {
		t.Fatalf("B lists %v", listB)
	}
	enabledB, _ := repo.Enabled(ctx, b, dom.PurposeDNSLabels)
	for _, l := range enabledB {
		if l.TenantID != b {
			t.Fatal("another organization's list in B's enabled set")
		}
	}
	if _, err := svc.Get(ctx, actxA, "not-an-id"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("malformed id: %v", err)
	}

	// The per-organization cap.
	for i := 2; i < dom.MaxLists; i++ {
		if _, _, err := svc.Create(ctx, actxA, CreateInput{Name: "l" + strconv.Itoa(i), Text: "w\n"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := svc.Create(ctx, actxA, CreateInput{Name: "one-too-many", Text: "w\n"}); !errors.Is(err, dom.ErrTooMany) {
		t.Fatalf("over the cap: %v", err)
	}

	if err := svc.Delete(ctx, actxA, second.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, actxA, second.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("deleted list still read: %v", err)
	}

	// Audit: every change recorded with metadata, never the labels.
	seen := map[auditdom.Action]int{}
	for _, e := range audit.events {
		seen[e.Action]++
		for k, v := range e.Metadata {
			if s, ok := v.(string); ok && (s == "hn01" || s == "payroll") {
				t.Fatalf("audit metadata %s carries a label", k)
			}
		}
	}
	if seen[auditdom.ActionWordlistCreated] == 0 || seen[auditdom.ActionWordlistUpdated] == 0 || seen[auditdom.ActionWordlistDeleted] != 1 {
		t.Fatalf("audit %v", seen)
	}
}
