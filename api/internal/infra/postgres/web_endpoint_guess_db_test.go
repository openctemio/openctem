package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Guessed endpoints against the real schema: the evidence is stored and read
// back, a later crawl sighting keeps it and merges its source, and the
// source=guess list filter keeps to the caller's tenant and data scope.
// Requires DATABASE_URL.

func guessObs(t *testing.T, origin, path string, size int, hash string) webendpoint.Observation {
	t.Helper()
	e := ctis.Endpoint{Origin: origin, Method: "GET", Path: path, StatusCode: 200, ContentType: "application/zip", Source: "probe"}
	e.Extensions.Set(webendpoint.EvidenceNamespace, webendpoint.EvidenceKey, map[string]any{"size": float64(size), "hash": hash})
	o, err := webendpoint.Observe(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := webendpoint.BindSource(&o, "enumerate.web_paths@1", e); err != nil {
		t.Fatal(err)
	}
	return o
}

func listGuessed(t *testing.T, f *webFixture, actor filterspec.Actor) []*webendpoint.Endpoint {
	t.Helper()
	spec := &filterspec.Spec{Root: &filterspec.Node{Leaf: &filterspec.Leaf{
		Field: "source", Op: filterspec.OpIn, Values: []any{webendpoint.SourceGuess}}}}
	w, err := filterspec.Compile(spec, webendpoint.Fields, actor)
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.repo.ListWhere(f.ctx, w, pagination.New(1, 100))
	if err != nil {
		t.Fatal(err)
	}
	return res.Data
}

func TestWebEndpointGuessEvidenceAndIsolation(t *testing.T) {
	f := newWebFixture(t)
	hidden := f.seedOrigin(t, f.tenant, "https://hidden.example.com")
	other := seedTestTenant(f.ctx, t, f.sqlDB)
	otherOrigin := f.seedOrigin(t, other, "https://b.example.com")

	f.record(t, f.tenant, f.origin, guessObs(t, "https://a.example.com", "/site.zip", 48213, "0123456789abcdef"))
	f.record(t, f.tenant, hidden, guessObs(t, "https://hidden.example.com", "/hidden.zip", 10, "aaaaaaaaaaaaaaaa"))
	f.record(t, other, otherOrigin, guessObs(t, "https://b.example.com", "/b-only.zip", 20, "bbbbbbbbbbbbbbbb"))

	admin, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: f.tenant, UserID: shared.NewID(), IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	got := listGuessed(t, f, admin)
	if len(got) != 2 {
		t.Fatalf("tenant A lists %d guessed endpoints, want its own 2", len(got))
	}
	for _, e := range got {
		if e.PathTemplate == "/b-only.zip" {
			t.Fatal("tenant A lists tenant B's guessed endpoint")
		}
		if e.PathTemplate == "/site.zip" && (e.RespSize == nil || *e.RespSize != 48213 || e.RespHash != "0123456789abcdef") {
			t.Fatalf("evidence read back as %v %q", e.RespSize, e.RespHash)
		}
	}

	// A member scoped to one origin sees only that origin's guessed rows.
	userID := shared.NewID()
	if _, err := f.sqlDB.ExecContext(f.ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'guess-scope')`,
		userID.String(), userID.String()+"@guess-scope.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.sqlDB.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, userID.String())
	})
	if _, err := f.sqlDB.ExecContext(f.ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		userID.String(), f.tenant.String(), f.origin.String()); err != nil {
		t.Fatalf("seed access: %v", err)
	}
	member, err := filterspec.UserActor(filterspec.UserActorInput{
		TenantID: f.tenant, UserID: userID, Scope: &shared.DataScope{TenantID: f.tenant, UserID: userID}})
	if err != nil {
		t.Fatal(err)
	}
	got = listGuessed(t, f, member)
	if len(got) != 1 || got[0].PathTemplate != "/site.zip" {
		t.Fatalf("scoped member lists %d guessed endpoints, want only /site.zip", len(got))
	}

	// A by-id read of tenant A's row as tenant B finds nothing.
	if e, err := f.repo.Get(f.ctx, other, got[0].ID); err == nil && e != nil {
		t.Fatal("tenant B read tenant A's guessed endpoint by id")
	}

	// A later crawl sighting merges its source and keeps the evidence.
	if _, err := f.sqlDB.ExecContext(f.ctx, `UPDATE web_endpoints SET last_seen_at = now() - interval '2 hours' WHERE tenant_id = $1`, f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	f.record(t, f.tenant, f.origin, obs(t, ctis.Endpoint{Path: "/site.zip", StatusCode: 200, ContentType: "application/zip"}))
	e, err := f.repo.Get(f.ctx, f.tenant, got[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Sources) != 2 || e.RespSize == nil || *e.RespSize != 48213 || e.RespHash != "0123456789abcdef" {
		t.Fatalf("after a crawl sighting: sources %v evidence %v %q", e.Sources, e.RespSize, e.RespHash)
	}
}

// The evidence migration goes up, down and up again on a populated table:
// rows survive, the columns come back empty, and the CHECKs hold.
func TestWebEndpointResponseEvidenceMigration_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "web_endpoint_evidence", dir)
	ctx := context.Background()
	v := testdb.MigrationVersion(t, dir, "web_endpoint_response_evidence")
	tenant, origin := shared.NewID(), shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant.String(), "mig-"+tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status, exposure) VALUES ($1, $2, 'https://m.example.com', 'service', 'active', 'public')`,
		origin.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	insert := func(path, hash string, size int) error {
		_, err := db.ExecContext(ctx, `INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash, kind, auth_state, resp_size, resp_hash)
			VALUES (gen_random_uuid(), $1, $2, 'GET', $3::text, md5($3::text), md5($3::text), 'page', 'unknown', $4::integer, NULLIF($5::text, ''))`, tenant.String(), origin.String(), path, size, hash)
		return err
	}
	if err := insert("/a.zip", "0123456789abcdef", 10); err != nil {
		t.Fatal(err)
	}
	testdb.Migrate(t, db, dir, v, v, true)
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM web_endpoints WHERE tenant_id = $1`, tenant.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("after down: %d rows (%v)", n, err)
	}
	testdb.Migrate(t, db, dir, v, v, false)
	var size *int
	if err := db.QueryRowContext(ctx, `SELECT resp_size FROM web_endpoints WHERE tenant_id = $1`, tenant.String()).Scan(&size); err != nil || size != nil {
		t.Fatalf("after up again: resp_size %v (%v), want NULL", size, err)
	}
	// The CHECKs are added NOT VALID (no scan under the ALTER's lock) and
	// enforced on new rows from then on; the next migration validates them.
	validated := func() map[string]bool {
		t.Helper()
		out := map[string]bool{}
		rows, err := db.QueryContext(ctx, `SELECT conname, convalidated FROM pg_constraint
			WHERE conrelid = 'web_endpoints'::regclass AND conname IN ('chk_web_endpoints_resp_size', 'chk_web_endpoints_resp_hash')`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var name string
			var ok bool
			if err := rows.Scan(&name, &ok); err != nil {
				t.Fatal(err)
			}
			out[name] = ok
		}
		return out
	}
	if got := validated(); len(got) != 2 || got["chk_web_endpoints_resp_size"] || got["chk_web_endpoints_resp_hash"] {
		t.Fatalf("after the evidence migration the CHECKs are %v, want both present and NOT VALID", got)
	}
	if err := insert("/b.zip", "0123456789ABCDEF", 10); err == nil {
		t.Fatal("an upper-case hash was accepted")
	}
	if err := insert("/c.zip", "0123456789abcdef", -1); err == nil {
		t.Fatal("a negative size was accepted")
	}
	if err := insert("/d.zip", "fedcba9876543210", 20); err != nil {
		t.Fatalf("valid evidence refused: %v", err)
	}
	vv := testdb.MigrationVersion(t, dir, "web_endpoint_response_evidence_validate")
	testdb.Migrate(t, db, dir, vv, vv, false)
	if got := validated(); !got["chk_web_endpoints_resp_size"] || !got["chk_web_endpoints_resp_hash"] {
		t.Fatalf("after the validate migration the CHECKs are %v, want both validated", got)
	}
	testdb.Migrate(t, db, dir, vv, vv, true)
}
