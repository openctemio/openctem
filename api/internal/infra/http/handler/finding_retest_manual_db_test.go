package handler

// A pentest finding has one retest history: GET /findings/{id}/retests lists
// the testers' manual retests next to automated ones, and only campaign
// members (and admins) see it; anyone else, and other tenants, get 404.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/compliance"
	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func TestFindingRetestHistory_IncludesManualRetests_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		testdb.Skipf(t, "DATABASE_URL not set; skipping DB-backed handler test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	ctx := context.Background()
	if err := raw.PingContext(ctx); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	tenant, other := shared.NewID().String(), shared.NewID().String()
	admin, member, outsider := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for _, tn := range []string{tenant, other} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'frm', $2)`, tn, "frm-"+tn)
	}
	for _, u := range []string{admin, member, outsider} {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'frm')`, u, u+"@frm.test")
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tn := range []string{tenant, other} {
			_, _ = raw.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM pentest_campaigns WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		for _, u := range []string{admin, member, outsider} {
			_, _ = raw.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u)
		}
	})

	db := &postgres.DB{DB: raw}
	log := logger.NewNop()
	svc := compliance.NewPentestService(
		postgres.NewPentestCampaignRepository(db), postgres.NewFindingRepository(db),
		postgres.NewPentestRetestRepository(db), postgres.NewPentestTemplateRepository(db),
		postgres.NewPentestReportRepository(db), log,
	)
	svc.SetCampaignMemberRepository(postgres.NewPentestCampaignMemberRepository(db))
	ph := NewPentestHandler(svc, nil, validator.New(), log)
	rh := NewFindingRetestHandler(retestapp.NewService(postgres.NewFindingRetestRepository(db), postgres.NewFindingRepository(db), nil, nil, nil, nil, log), log)
	rh.SetManualRetestSource(svc)

	as := func(tn, user string, isAdmin bool, fn http.HandlerFunc, method, body string, params map[string]string) *httptest.ResponseRecorder {
		r := pentestDBRequest(method, "/", tn, body, params)
		c := context.WithValue(r.Context(), middleware.UserIDKey, user)
		c = context.WithValue(c, middleware.IsAdminKey, isAdmin)
		w := httptest.NewRecorder()
		fn(w, r.WithContext(c))
		return w
	}
	var c, f struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(as(tenant, admin, true, ph.CreateCampaign, http.MethodPost, `{"name":"frm","campaign_type":"web_app","priority":"high"}`, nil).Body.Bytes(), &c)
	_ = json.Unmarshal(as(tenant, admin, true, ph.CreateFinding, http.MethodPost, `{"title":"frm finding","severity":"high","affected_assets":["a.example.test"]}`, map[string]string{"id": c.ID}).Body.Bytes(), &f)
	if w := as(tenant, admin, true, ph.CreateRetest, http.MethodPost, `{"status":"partial","notes":"login fixed, API not"}`, map[string]string{"findingId": f.ID}); w.Code != http.StatusCreated {
		t.Fatalf("create retest = %d %s", w.Code, w.Body.String())
	}
	exec(`INSERT INTO pentest_campaign_members (tenant_id, campaign_id, user_id, role) VALUES ($1, $2, $3, 'observer')`, tenant, c.ID, member)

	get := func(tn, user string, isAdmin bool) *httptest.ResponseRecorder {
		return as(tn, user, isAdmin, rh.List, http.MethodGet, "", map[string]string{"id": f.ID})
	}
	for name, w := range map[string]*httptest.ResponseRecorder{"admin": get(tenant, admin, true), "member": get(tenant, member, false)} {
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d %s", name, w.Code, w.Body.String())
		}
		var out FindingRetestListResponse
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if len(out.Data) != 1 || out.Data[0].Kind != "manual" || out.Data[0].ManualResult != "partial" || out.Data[0].Notes != "login fixed, API not" {
			t.Fatalf("%s: history = %s", name, w.Body.String())
		}
	}
	if w := get(tenant, outsider, false); w.Code != http.StatusNotFound {
		t.Fatalf("non-member: status %d, want 404", w.Code)
	}
	if w := get(other, admin, true); w.Code != http.StatusNotFound {
		t.Fatalf("other tenant: status %d, want 404", w.Code)
	}
}
