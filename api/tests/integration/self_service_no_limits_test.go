package integration

// Self-service organizations get no limits (docs/architecture/limits.md),
// against a real Postgres: neither create-first-team nor POST /tenants
// sets a limit, and one person may create several organizations. Limits
// apply only where an operator sets them for an organization; a self-hosted
// install with self-service sign-up on must never cap new organizations on
// its own.
//
// Requires DATABASE_URL pointing at a fully migrated database.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func TestSelfServiceOrganizationsHaveNoLimits(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()
	log := logger.NewNop()

	svc := orgAuthService(db, config.TenantCreationSelfService)
	email, refresh := orgSelfServiceUser(t, db, svc)
	slug := "ss-" + uuid.NewString()[:8]
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE slug = $1`, slug) })

	res, err := svc.CreateFirstTeam(ctx, authapp.CreateFirstTeamInput{RefreshToken: refresh, TeamName: "First Team", TeamSlug: slug})
	if err != nil {
		t.Fatalf("first organization: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM tenant_limits WHERE tenant_id = $1`, res.Tenant.TenantID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("create-first-team must not set limits: %d %v", n, err)
	}

	// More organizations through POST /tenants: no per-person cap, no plan.
	u, err := postgres.NewUserRepository(db).GetByEmail(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	tenantSvc := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
		tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
	h := handler.NewTenantHandler(tenantSvc, validator.New(), log)
	h.SetSelfServiceTenantCreation(true)
	for i := 0; i < 2; i++ {
		s := "ss" + string(rune('a'+i)) + "-" + uuid.NewString()[:8]
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE slug = $1`, s) })
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(`{"name":"Org `+s+`","slug":"`+s+`"}`))
		rec := httptest.NewRecorder()
		h.Create(rec, req.WithContext(context.WithValue(req.Context(), middleware.LocalUserKey, u)))
		if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
			t.Fatalf("POST /tenants #%d: %d %s", i+1, rec.Code, rec.Body)
		}
		if err := db.QueryRow(`SELECT count(*) FROM tenant_limits l JOIN tenants t ON t.id = l.tenant_id WHERE t.slug = $1`, s).Scan(&n); err != nil || n != 0 {
			t.Fatalf("POST /tenants must not set limits: %d %v", n, err)
		}
	}
}

// fixedDefaults are self-service defaults an operator set, without touching
// the shared platform setting (other tests create organizations
// concurrently). The per-person cap counts real owned organizations.
type fixedDefaults struct {
	d    limits.Limits
	repo *postgres.LimitsRepository
}

func (f fixedDefaults) SelfServiceDefaults(context.Context) (limits.Limits, int, error) {
	return f.d, 1, nil
}

func (f fixedDefaults) CheckOrgsPerUser(ctx context.Context, userID shared.ID) error {
	n, err := f.repo.CountOwnedTenants(ctx, userID)
	if err != nil {
		return err
	}
	if lim := f.d.Get(limits.OrgsPerUser); !limits.AllowAddition(lim, n, 1) {
		return &limits.ErrLimitReached{Key: limits.OrgsPerUser, Limit: lim, Used: n}
	}
	return nil
}

// With self-service defaults set by the operator, a self-service
// organization starts with them (written with the organization) and the
// per-person cap applies on POST /tenants with 403 LIMIT_REACHED; neither the
// membership list nor GET /tenants/{id} carries a plan.
func TestSelfServiceDefaultsApplyWhenSet(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()
	log := logger.NewNop()
	lims := postgres.NewLimitsRepository(db)
	defaults := fixedDefaults{d: limits.Limits{limits.Seats: 5, limits.Assets: 500, limits.OrgsPerUser: 1}, repo: lims}

	svc := orgAuthService(db, config.TenantCreationSelfService)
	svc.SetSelfServiceLimits(defaults)
	email, refresh := orgSelfServiceUser(t, db, svc)
	slug := "ssd-" + uuid.NewString()[:8]
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE slug = $1`, slug) })
	res, err := svc.CreateFirstTeam(ctx, authapp.CreateFirstTeamInput{RefreshToken: refresh, TeamName: "Defaults Team", TeamSlug: slug})
	if err != nil {
		t.Fatalf("first organization: %v", err)
	}
	tid := shared.MustIDFromString(res.Tenant.TenantID)
	got, err := lims.ListLimits(ctx, tid, limits.OriginOperator)
	if err != nil || len(got) != 2 {
		t.Fatalf("self-service limits stored with the organization: %+v %v", got, err)
	}
	for _, l := range got {
		if l.Reason != limits.SelfServiceReason || (l.Key != limits.Seats && l.Key != limits.Assets) {
			t.Fatalf("row: %+v", l)
		}
	}

	u, err := postgres.NewUserRepository(db).GetByEmail(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	tenantRepo := postgres.NewTenantRepository(db)
	tenantSvc := tenantapp.NewTenantService(tenantRepo, log,
		tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
	h := handler.NewTenantHandler(tenantSvc, validator.New(), log)
	h.SetSelfServiceTenantCreation(true)
	h.SetSelfServiceLimits(defaults)
	second := "ssd2-" + uuid.NewString()[:8]
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE slug = $1`, second) })
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(`{"name":"Second Org","slug":"`+second+`"}`))
	rec := httptest.NewRecorder()
	h.Create(rec, req.WithContext(context.WithValue(req.Context(), middleware.LocalUserKey, u)))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "LIMIT_REACHED") {
		t.Fatalf("POST /tenants over the per-person cap: %d %s", rec.Code, rec.Body)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM tenants WHERE slug = $1`, second).Scan(&n); err != nil || n != 0 {
		t.Fatalf("refused organization was created: %d %v", n, err)
	}

	// No plan anywhere in the organization payloads.
	users := handler.NewUserHandler(nil, tenantSvc, nil, validator.New(), log)
	list, err := users.MyTenantsResponse(ctx, u.ID())
	if err != nil || len(list) != 1 {
		t.Fatalf("membership list: %+v %v", list, err)
	}
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), `"plan"`) {
		t.Fatalf("membership list carries a plan: %s", raw)
	}
	raw, _ = json.Marshal(handler.TenantResponse{})
	if strings.Contains(string(raw), `"plan"`) {
		t.Fatalf("GET /tenants/{id} carries a plan: %s", raw)
	}
}
