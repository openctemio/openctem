package handler

// GET /api/v1/agent/suppressions: the sensor-side security gate reads its
// tenant's active suppression rules with the sensor key. Exercised through the
// real AuthenticateSource and real repositories.
//
// Needs DATABASE_URL (CI's Test job provides one); skipped otherwise.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/legacyv1"
)

type sensorSuppressionsEnv struct {
	t       *testing.T
	db      *sql.DB
	sensors *sensor.SensorService
	enabled map[string]bool // tenant -> suppressions module enabled (default true)
	srv     *httptest.Server
}

func newSensorSuppressionsEnv(t *testing.T) *sensorSuppressionsEnv {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping sensor suppressions DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()

	sensorRepo := postgres.NewSensorRepository(db)
	sensorSvc := sensor.NewSensorService(sensorRepo, nil, log)
	sensorSvc.SetAPIKeyRepository(postgres.NewSensorAPIKeyRepository(db))
	ih := NewIngestHandler(nil, sensorSvc, log)
	sh := NewSuppressionHandler(suppression.NewService(postgres.NewSuppressionRepository(db), log), log)

	env := &sensorSuppressionsEnv{t: t, db: sqldb, sensors: sensorSvc, enabled: map[string]bool{}}
	r := chi.NewRouter()
	r.Route(legacyv1.PathPrefix, func(r chi.Router) {
		r.Use(ih.AuthenticateSource)
		r.Get("/suppressions", sh.SensorActiveRules(func(_ context.Context, tenantID string) bool {
			on, set := env.enabled[tenantID]
			return !set || on
		}))
	})
	env.srv = httptest.NewServer(r)
	t.Cleanup(env.srv.Close)
	return env
}

// tenant seeds a tenant with one approved, one pending and one expired rule,
// plus a daemon sensor, and returns (tenantID, sensorID, sensorKey).
func (e *sensorSuppressionsEnv) tenant(label string) (string, string, string) {
	e.t.Helper()
	ctx := context.Background()
	tenantID, userID := shared.NewID().String(), shared.NewID().String()
	exec := func(q string, args ...any) {
		e.t.Helper()
		if _, err := e.db.ExecContext(ctx, q, args...); err != nil {
			e.t.Fatalf("seed %s: %v", label, err)
		}
	}
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`, tenantID, label, "sup-"+tenantID)
	e.t.Cleanup(func() {
		_, _ = e.db.ExecContext(context.Background(), `DELETE FROM suppression_rules WHERE tenant_id = $1`, tenantID)
		_, _ = e.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
		_, _ = e.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})
	exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, userID, "sup-"+userID+"@openctem-test.local", label)
	for _, rule := range []struct{ ruleID, status, expiry string }{
		{label + "-approved", "approved", "NULL"},
		{label + "-pending", "pending", "NULL"},
		{label + "-expired", "approved", "NOW() - interval '1 day'"},
	} {
		exec(`INSERT INTO suppression_rules (tenant_id, rule_id, tool_name, name, status, requested_by, expires_at)
		      VALUES ($1, $2, 'semgrep', $2, $3, $4, `+rule.expiry+`)`, tenantID, rule.ruleID, rule.status, userID)
	}
	out, err := e.sensors.CreateSensor(ctx, sensor.CreateSensorInput{
		TenantID: tenantID, Name: label + "-sensor", Type: "worker",
		Capabilities: []string{"sast"}, Tools: []string{"semgrep"}, ExecutionMode: "daemon",
	})
	if err != nil {
		e.t.Fatalf("create sensor: %v", err)
	}
	return tenantID, out.Sensor.ID.String(), out.APIKey
}

func (e *sensorSuppressionsEnv) get(authorization string) (int, SensorSuppressionsResponse) {
	e.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, e.srv.URL+legacyv1.SuppressionsPath, nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("GET %s: %v", legacyv1.SuppressionsPath, err)
	}
	defer resp.Body.Close()
	var body SensorSuppressionsResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			e.t.Fatalf("decode: %v", err)
		}
	}
	return resp.StatusCode, body
}

func ruleIDs(b SensorSuppressionsResponse) []string {
	out := make([]string, 0, len(b.Rules))
	for _, r := range b.Rules {
		out = append(out, r.RuleID)
	}
	return out
}

func TestSensorSuppressions_OwnTenantActiveRulesOnly(t *testing.T) {
	env := newSensorSuppressionsEnv(t)
	_, _, keyA := env.tenant("tenant-a")
	_, _, keyB := env.tenant("tenant-b")

	code, body := env.get("Bearer " + keyA)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if got := ruleIDs(body); body.Count != 1 || len(got) != 1 || got[0] != "tenant-a-approved" {
		t.Fatalf("tenant A sensor got rules %v (count %d), want only [tenant-a-approved]", got, body.Count)
	}
	if body.Rules[0].ToolName != "semgrep" {
		t.Errorf("tool_name = %q, want semgrep", body.Rules[0].ToolName)
	}

	code, body = env.get("Bearer " + keyB)
	if got := ruleIDs(body); code != http.StatusOK || len(got) != 1 || got[0] != "tenant-b-approved" {
		t.Fatalf("tenant B sensor got %d %v, want 200 [tenant-b-approved]", code, got)
	}
}

func TestSensorSuppressions_RejectsNonSensorCredentials(t *testing.T) {
	env := newSensorSuppressionsEnv(t)
	env.tenant("tenant-c")
	for name, auth := range map[string]string{
		"no credential": "",
		"user JWT":      "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1In0.c2ln",
		"unknown key":   "Bearer rda_0000000000000000000000000000000000000000000000000000000000000000",
	} {
		if code, _ := env.get(auth); code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, code)
		}
	}
}

func TestSensorSuppressions_DisabledOrRevokedSensor(t *testing.T) {
	for _, status := range []string{"disabled", "revoked"} {
		t.Run(status, func(t *testing.T) {
			env := newSensorSuppressionsEnv(t)
			_, sensorID, key := env.tenant("tenant-" + status)
			if code, _ := env.get("Bearer " + key); code != http.StatusOK {
				t.Fatalf("before %s: status = %d, want 200", status, code)
			}
			if _, err := env.db.ExecContext(context.Background(),
				`UPDATE sensors SET status = $1 WHERE id = $2`, status, sensorID); err != nil {
				t.Fatalf("set status: %v", err)
			}
			if code, _ := env.get("Bearer " + key); code != http.StatusUnauthorized {
				t.Errorf("%s sensor: status = %d, want 401", status, code)
			}
		})
	}
}

func TestSensorSuppressions_ModuleDisabledIsEmpty(t *testing.T) {
	env := newSensorSuppressionsEnv(t)
	tenantID, _, key := env.tenant("tenant-nomodule")
	env.enabled[tenantID] = false
	code, body := env.get("Bearer " + key)
	if code != http.StatusOK || body.Count != 0 || len(body.Rules) != 0 {
		t.Fatalf("module disabled: got %d %+v, want 200 with no rules", code, body)
	}
}

// A platform sensor has no tenant (the OSS schema cannot even store one, but
// the identity type allows it): it must never read any tenant's rules. No DB:
// the handler refuses before touching the service.
func TestSensorSuppressions_PlatformSensorRefused(t *testing.T) {
	sh := NewSuppressionHandler(nil, logger.NewNop())
	req := httptest.NewRequest(http.MethodGet, legacyv1.SuppressionsPath, nil)
	req = req.WithContext(context.WithValue(req.Context(), sensorContextKey, &sensordom.Sensor{ID: shared.NewID()}))
	rec := httptest.NewRecorder()
	sh.SensorActiveRules(nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("platform sensor: status = %d, want 403", rec.Code)
	}

	// And without an authenticated sensor at all (route mounted wrongly): 401.
	rec = httptest.NewRecorder()
	sh.SensorActiveRules(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, legacyv1.SuppressionsPath, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no sensor in context: status = %d, want 401", rec.Code)
	}
}
