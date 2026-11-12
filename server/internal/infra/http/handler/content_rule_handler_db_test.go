package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	contentruleapp "github.com/openctemio/openctem/api/internal/app/contentrule"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/contentrule"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const testSecretRule = `{"id":"acme-key","name":"Acme key","secret":{"category":"token","severity":"high"},` +
	`"matchers":[{"location":"body","keywords":["acme_"],"pattern":"\\b(?P<secret>acme_[a-z0-9]{24})\\b"}]}`

// The detection rule API end to end (handler, service, Postgres): create,
// read, a version bump on change only, validation refusals (backreference,
// a body matcher without keywords, unknown fields), the masked test, and
// tenant isolation: another organization's rule is 404 for read, update and
// delete, absent from its list, and never in its engine. Route gating is
// covered by the route tests. Requires DATABASE_URL.
func TestContentRuleAPI_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tenant := func() string {
		id := shared.NewID().String()
		if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'crh', $2)`, id, "crh-"+id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id) })
		return id
	}
	a, b := tenant(), tenant()
	repo := postgres.NewTenantContentRuleRepository(&postgres.DB{DB: db})
	engines := contentruleapp.NewService(nil, repo, nil, nil, nil, nil)
	h := NewContentRuleHandler(contentruleapp.NewRulesService(repo, engines, nil, logger.NewNop()), engines, logger.NewNop())
	r := chi.NewRouter()
	r.Get("/content-rules", h.List)
	r.Get("/content-rules/{id}", h.Get)
	r.Post("/content-rules", h.Create)
	r.Post("/content-rules/test", h.Test)
	r.Patch("/content-rules/{id}", h.Update)
	r.Delete("/content-rules/{id}", h.Delete)
	do := func(tenantID, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
		req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, tenantID))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	rec := do(a, http.MethodPost, "/content-rules", `{"kind":"secret-rules","rule":`+testSecretRule+`}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var saved ContentRuleResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &saved)
	if saved.Version != 1 || !saved.Enabled || saved.RuleID != "acme-key" || len(saved.SHA256) != 64 {
		t.Fatalf("saved %+v", saved)
	}
	id := saved.ID

	// The organization's engine holds the rule (as org.acme-key); B's does not.
	ctx := context.Background()
	ta, _ := shared.IDFromString(a)
	tb, _ := shared.IDFromString(b)
	secret := "acme_" + strings.Repeat("q1", 12)
	doc := contentrule.Document{Body: []byte("x " + secret + " y")}
	ea, err := engines.Engine(ctx, ta)
	if err != nil || ea == nil {
		t.Fatalf("engine A: %v", err)
	}
	if res := ea.Scan(ctx, doc, contentrule.DefaultBudget, nil); len(res.Secrets) != 1 || res.Secrets[0].RuleID != "org.acme-key" {
		t.Fatalf("A scan: %+v", res)
	}
	if eb, err := engines.Engine(ctx, tb); err != nil || eb != nil {
		t.Fatalf("B engine holds A's rule: %v %v", eb, err)
	}

	// Enabling again changes nothing; a new pattern raises the version.
	if rec := do(a, http.MethodPatch, "/content-rules/"+id, `{"enabled":true}`); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"version":2`) {
		t.Fatalf("no-op update: %d %s", rec.Code, rec.Body)
	}
	changed := strings.Replace(testSecretRule, "{24}", "{32}", 1)
	if rec := do(a, http.MethodPatch, "/content-rules/"+id, `{"rule":`+changed+`}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"version":2`) {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	// Tenant isolation.
	for _, c := range []struct{ method, body string }{{http.MethodGet, ""}, {http.MethodPatch, `{"enabled":false}`}, {http.MethodDelete, ""}} {
		if rec := do(b, c.method, "/content-rules/"+id, c.body); rec.Code != http.StatusNotFound {
			t.Fatalf("%s as another organization: %d", c.method, rec.Code)
		}
	}
	if rec := do(b, http.MethodGet, "/content-rules", ""); strings.Contains(rec.Body.String(), id) {
		t.Fatal("another organization lists the rule")
	}
	// Refusals.
	bad := map[string]string{
		"backreference": `{"kind":"secret-rules","rule":{"id":"r2","name":"r","secret":{"category":"token","severity":"high"},"matchers":[{"location":"body","keywords":["abc"],"pattern":"(a)\\1"}]}}`,
		"no keywords":   `{"kind":"secret-rules","rule":{"id":"r3","name":"r","secret":{"category":"token","severity":"high"},"matchers":[{"location":"body","pattern":"abc"}]}}`,
		"unknown field": `{"kind":"secret-rules","tenant_id":"` + b + `","rule":` + testSecretRule + `}`,
		"bad kind":      `{"kind":"nuclei-templates","rule":` + testSecretRule + `}`,
	}
	for name, body := range bad {
		if rec := do(a, http.MethodPost, "/content-rules", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := do(a, http.MethodPost, "/content-rules", `{"kind":"secret-rules","rule":`+testSecretRule+`}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate id: %d", rec.Code)
	}
	// The test returns the match masked, never the value.
	rec = do(a, http.MethodPost, "/content-rules/test", `{"kind":"secret-rules","rule":`+testSecretRule+`,"sample":{"body":"line\nk=`+secret+`"}}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"line":2`) || !strings.Contains(rec.Body.String(), `"preview":"acme…q1q1"`) {
		t.Fatalf("test: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("test returned the secret: %s", rec.Body)
	}
	if rec := do(a, http.MethodDelete, "/content-rules/"+id, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if e, err := engines.Engine(ctx, ta); err != nil || e != nil {
		t.Fatalf("engine after delete: %v %v", e, err)
	}
}
