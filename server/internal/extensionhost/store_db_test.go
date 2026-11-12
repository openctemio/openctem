package extensionhost

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	ext "github.com/openctemio/openctem/server/pkg/extension"
	"github.com/openctemio/openctem/server/pkg/extension/example"
)

// exampleDB is a private migrated database with the example extension's
// migrations applied in its schema, the way an extension's migration tool
// does it (search_path = the extension schema).
func exampleDB(t *testing.T) *sql.DB {
	t.Helper()
	db := testdb.PrivateDatabase(t, "extstore", filepath.Join("..", "..", "migrations"))
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA example_ext`); err != nil {
		t.Fatal(err)
	}
	m := example.Migrations()
	ups, _ := fs.Glob(m, "*.up.sql")
	sort.Strings(ups)
	for _, f := range ups {
		b, err := fs.ReadFile(m, f)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `SET LOCAL search_path TO example_ext, public`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func newTenant(t *testing.T, db *sql.DB) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(), `INSERT INTO tenants (id, name, slug) VALUES ($1, 'Ext Org', $2)`, id.String(), "ext-"+id.String()); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestStoreScopesTransactions(t *testing.T) {
	db := exampleDB(t)
	ctx := context.Background()
	s := &store{db: db, schema: "example_ext"}
	tenant := newTenant(t, db)

	// The extension schema comes first on the search path, the core schema
	// stays reachable, and the organization mark is set.
	err := s.TenantTx(ctx, tenant, func(ctx context.Context, q ext.Querier) error {
		var path, mark string
		if err := q.QueryRowContext(ctx, `SELECT current_setting('search_path'), current_setting('app.current_tenant_id', true)`).Scan(&path, &mark); err != nil {
			return err
		}
		if !strings.HasPrefix(path, `"example_ext", `) || mark != tenant.String() {
			t.Errorf("search_path %q, tenant mark %q", path, mark)
		}
		_, err := q.ExecContext(ctx, `INSERT INTO example_notes (tenant_id, body) VALUES ($1, 'n')`, tenant.String())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// An installation transaction carries no organization mark.
	_ = s.InstanceTx(ctx, func(ctx context.Context, q ext.Querier) error {
		var mark string
		_ = q.QueryRowContext(ctx, `SELECT current_setting('app.current_tenant_id', true)`).Scan(&mark)
		if mark != "" {
			t.Errorf("instance transaction carried tenant %q", mark)
		}
		return nil
	})

	// fn's error rolls back.
	boom := errors.New("boom")
	if err := s.TenantTx(ctx, tenant, func(ctx context.Context, q ext.Querier) error {
		if _, err := q.ExecContext(ctx, `INSERT INTO example_notes (tenant_id, body) VALUES ($1, 'rolled back')`, tenant.String()); err != nil {
			return err
		}
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM example_ext.example_notes`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows %d (%v): the failed transaction was not rolled back", n, err)
	}

	// The settings do not leak to the next use of a pooled connection.
	var path string
	if err := db.QueryRowContext(ctx, `SELECT current_setting('search_path')`).Scan(&path); err != nil || strings.Contains(path, "example_ext") {
		t.Fatalf("search_path leaked: %q (%v)", path, err)
	}

	if err := s.TenantTx(ctx, shared.ID{}, func(context.Context, ext.Querier) error { return nil }); err == nil {
		t.Fatal("tenant transaction without an organization")
	}
}

// The example extension's routes, served through its Store, never show one
// organization's notes to another (the caller comes from the credential).
func TestExampleRoutesAreTenantScoped(t *testing.T) {
	db := exampleDB(t)
	set, err := New([]ext.Extension{example.Extension()})
	if err != nil {
		t.Fatal(err)
	}
	h := Host{DB: db}
	rs, err := set.Routes(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	var list, add http.Handler
	for _, r := range rs {
		if r.Method == http.MethodGet {
			list = r.Handler
		} else {
			add = r.Handler
		}
	}
	a, b := newTenant(t, db), newTenant(t, db)
	call := func(h http.Handler, tenant shared.ID, method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), method, "/api/v1/example-notes", bytes.NewBufferString(body))
		if !tenant.IsZero() {
			req = req.WithContext(ext.WithCaller(req.Context(), ext.Caller{TenantID: tenant}))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := call(add, a, http.MethodPost, `{"body":"only a"}`); w.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	var got struct {
		Data []example.Note `json:"data"`
	}
	w := call(list, b, http.MethodGet, "")
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got.Data) != 0 {
		t.Fatalf("organization b sees %d notes of a (%v)", len(got.Data), err)
	}
	w = call(list, a, http.MethodGet, "")
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got.Data) != 1 {
		t.Fatalf("organization a sees %d notes (%v)", len(got.Data), err)
	}
	if w := call(list, shared.ID{}, http.MethodGet, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no caller: %d", w.Code)
	}

	// The controller reads installation-wide through the same Store.
	cs, err := set.Controllers(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := cs[0].Reconcile(context.Background()); err != nil || n != 1 {
		t.Fatalf("counter: %d %v", n, err)
	}
}

func TestAdminAuditTrail(t *testing.T) {
	db := testdb.PrivateDatabase(t, "exttrail", filepath.Join("..", "..", "migrations"))
	ctx := context.Background()
	a := &auditTrail{db: db}
	c, err := a.LoadCursor(ctx)
	if err != nil || c.Position != 0 {
		t.Fatalf("fresh cursor %+v %v", c, err)
	}
	if err := a.SaveCursor(ctx, ext.AuditCursor{Position: 5, Hash: "h5"}); err != nil {
		t.Fatal(err)
	}
	// Never backwards.
	if err := a.SaveCursor(ctx, ext.AuditCursor{Position: 3, Hash: "h3"}); err != nil {
		t.Fatal(err)
	}
	if c, _ := a.LoadCursor(ctx); c.Position != 5 || c.Hash != "h5" {
		t.Fatalf("cursor %+v", c)
	}
	if err := a.SaveCursor(ctx, ext.AuditCursor{Position: -1}); err == nil {
		t.Fatal("negative position")
	}
	if _, err := a.ReadChain(ctx, 0, 0); err == nil {
		t.Fatal("limit 0 accepted")
	}

	// What an audit sink reads leaves the box: every admin_audit_logs
	// column is decided (shipped or withheld), so a new column never
	// reaches an extension's sink by accident.
	rows, err := db.QueryContext(ctx, `SELECT column_name FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'admin_audit_logs'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	decided := append(append([]string(nil), postgres.AdminAuditShippedColumns...), postgres.AdminAuditWithheldColumns...)
	sort.Strings(cols)
	sort.Strings(decided)
	if strings.Join(cols, ",") != strings.Join(decided, ",") {
		t.Fatalf("admin_audit_logs columns %v, decided %v: add the new column to postgres.AdminAuditShippedColumns or AdminAuditWithheldColumns", cols, decided)
	}
}
