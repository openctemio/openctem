package routes

// Scanner content (docs/rfcs/RFC-031-managed-sensor-updates.md) over the real
// route registration against a migrated database: who may read and change
// the tenant content policy and request refreshes, tenant isolation, the 409
// for a sensor that manages no content, the refresh dedup, the command a
// refresh queues, and the content view and health reasons on GET /sensors.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	tenantsvc "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func newContentRouteHarness(t *testing.T) *authzPolicyHarness {
	t.Helper()
	base := newAuthzPolicyHarness(t) // skips without a test database; restores the chain on cleanup

	db := &postgres.DB{DB: base.db}
	log := logger.NewNop()
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(db), log)
	sensorRepo := postgres.NewSensorRepository(db)
	sensorSvc := sensorapp.NewSensorService(sensorRepo, auditSvc, log)
	contentSvc := sensorapp.NewContentService(sensorRepo, sensorSvc, postgres.NewSensorContentPolicyRepository(db),
		postgres.NewCommandRepository(db), auditSvc, log)
	sh := handler.NewSensorHandler(sensorSvc, validator.New(), log)
	sh.SetContentPolicySource(contentSvc)

	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	router := infrahttp.NewChiRouter()
	Register(router, Handlers{
		Sensor:        sh,
		SensorContent: handler.NewSensorContentHandler(contentSvc, sh, log),
	}, cfg, log, AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: base.gen},
		postgres.NewTenantRepository(db), tenantsvc.NewUserService(postgres.NewUserRepository(db), log), nil, nil, nil)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	base.srv = srv
	return base
}

// contentSensor inserts a heartbeating sensor whose reported tool inventory
// carries trivy content built updatedAgo ago (managed or not).
func (h *authzPolicyHarness) contentSensor(tenantID, status string, managed bool, updatedAgo time.Duration, errText string) string {
	h.t.Helper()
	id := uuid.NewString()
	tools := []map[string]any{{"name": "trivy", "version": "0.69.3", "installed": true, "content": []map[string]any{{
		"name": "trivy-db", "version": "2026-09-29T01:05:41Z", "updated_at": time.Now().Add(-updatedAgo).UTC().Format(time.RFC3339),
		"source": "mirror.gcr.io/aquasec/trivy-db:2", "digest": "sha256:3b16", "managed": managed, "error": errText,
	}}}}
	raw, _ := json.Marshal(tools)
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix,
	                             last_seen_at, reported_tools, reported_tool_names, reported_at)
	        VALUES ($1, $2, $3, 'worker', $4, 'online', 'daemon', $5, 'rda_test', NOW(), $6::jsonb, ARRAY['trivy'], NOW())`,
		id, tenantID, "content-"+id[:8], status, "hash-"+id, string(raw))
	return id
}

func TestSensorContent_Routes_DB(t *testing.T) {
	h := newContentRouteHarness(t)
	tid, other := h.tenant(), h.tenant()
	t.Cleanup(func() {
		for _, id := range []string{tid, other} {
			_, _ = h.db.ExecContext(context.Background(), `DELETE FROM commands WHERE tenant_id = $1`, id)
		}
	})
	admin, member, viewer := h.member(tid, "admin"), h.member(tid, "member"), h.member(tid, "viewer")
	outsider := h.member(other, "admin")

	stale := h.contentSensor(tid, "active", true, 72*time.Hour, "registry unreachable")
	unmanaged := h.contentSensor(tid, "active", false, time.Hour, "")
	disabled := h.contentSensor(tid, "disabled", true, time.Hour, "")
	plain := h.sensor(tid) // reports nothing

	// Members and viewers read; only administrators change or refresh.
	for _, u := range []policyUser{member, viewer} {
		h.expect(u, http.MethodGet, "/api/v1/sensors/content-policy", "", http.StatusOK)
		h.expect(u, http.MethodPut, "/api/v1/sensors/content-policy", `{"policy":{}}`, http.StatusForbidden)
		h.expect(u, http.MethodPost, "/api/v1/sensors/content/refresh", "", http.StatusForbidden)
		h.expect(u, http.MethodPost, "/api/v1/sensors/"+stale+"/content/refresh", "", http.StatusForbidden)
	}

	// Defaults until the tenant sets a policy.
	var pol handler.ContentPolicyResponse
	mustJSON(t, h.expect(admin, http.MethodGet, "/api/v1/sensors/content-policy", "", http.StatusOK), &pol)
	if pol.UpdatedAt != nil || pol.Policy.Content["trivy-db"].MaxAgeHours != 48 || pol.Policy.RefreshIntervalHours != 6 {
		t.Fatalf("default policy %+v", pol)
	}

	// The content view and the health reason on the sensor read.
	var s handler.SensorResponse
	mustJSON(t, h.expect(member, http.MethodGet, "/api/v1/sensors/"+stale, "", http.StatusOK), &s)
	if len(s.Content) != 1 || !s.Content[0].Stale || s.Content[0].Tool != "trivy" || s.Content[0].MaxAgeHours != 48 ||
		s.Content[0].AgeSeconds == nil || !s.ContentRefreshSupported {
		t.Fatalf("content view %+v supported=%v", s.Content, s.ContentRefreshSupported)
	}
	if s.State != "degraded" || len(s.HealthReasons) == 0 || s.HealthReasons[0].Code != "content_stale" ||
		!strings.Contains(s.HealthReasons[0].Message, "trivy DB is 3d old (limit 2d)") {
		t.Fatalf("health %s %+v", s.State, s.HealthReasons)
	}
	if s.Reported == nil || len(s.Reported.Tools) != 1 || len(s.Reported.Tools[0].Content) != 1 {
		t.Fatalf("reported tools lost the content: %+v", s.Reported)
	}

	// Refresh one sensor: 202, then the same command again.
	var r1, r2 handler.RefreshContentResponse
	mustJSON(t, h.expect(admin, http.MethodPost, "/api/v1/sensors/"+stale+"/content/refresh", `{"content":["trivy-db"]}`, http.StatusAccepted), &r1)
	mustJSON(t, h.expect(admin, http.MethodPost, "/api/v1/sensors/"+stale+"/content/refresh", "", http.StatusAccepted), &r2)
	if r1.CommandID == "" || r1.AlreadyPending || r2.CommandID != r1.CommandID || !r2.AlreadyPending {
		t.Fatalf("refresh %+v then %+v", r1, r2)
	}
	var (
		cmdType, sensorID, status string
		payload                   []byte
		expires                   time.Time
	)
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT type, sensor_id, status, payload, expires_at FROM commands WHERE id = $1 AND tenant_id = $2`,
		r1.CommandID, tid).Scan(&cmdType, &sensorID, &status, &payload, &expires); err != nil {
		t.Fatal(err)
	}
	if cmdType != "refresh_content" || sensorID != stale || status != "pending" || time.Until(expires) < 23*time.Hour {
		t.Fatalf("command %s %s %s %v", cmdType, sensorID, status, expires)
	}
	var p struct {
		Content []string       `json:"content"`
		Force   bool           `json:"force"`
		Policy  map[string]any `json:"policy"`
	}
	mustJSON(t, string(payload), &p)
	if !p.Force || len(p.Content) != 1 || p.Policy == nil {
		t.Fatalf("payload %s", payload)
	}

	// Sensors that cannot take it, and another tenant's sensor.
	for _, id := range []string{unmanaged, disabled, plain} {
		h.expect(admin, http.MethodPost, "/api/v1/sensors/"+id+"/content/refresh", "", http.StatusConflict)
	}
	h.expect(outsider, http.MethodPost, "/api/v1/sensors/"+stale+"/content/refresh", "", http.StatusNotFound)
	h.expect(admin, http.MethodPost, "/api/v1/sensors/"+stale+"/content/refresh", `{"content":["../etc"]}`, http.StatusBadRequest)

	// The fleet: the only eligible sensor already has a refresh queued.
	var fleet handler.FleetRefreshContentResponse
	mustJSON(t, h.expect(admin, http.MethodPost, "/api/v1/sensors/content/refresh", "", http.StatusOK), &fleet)
	if fleet.CommandsCreated != 0 || fleet.Skipped != 4 {
		t.Fatalf("fleet %+v", fleet)
	}
	var outsiderFleet handler.FleetRefreshContentResponse
	mustJSON(t, h.expect(outsider, http.MethodPost, "/api/v1/sensors/content/refresh", "", http.StatusOK), &outsiderFleet)
	if outsiderFleet.CommandsCreated != 0 || outsiderFleet.Skipped != 0 {
		t.Fatalf("other tenant's fleet saw this tenant's sensors: %+v", outsiderFleet)
	}

	// Policy: invalid input is refused; a larger limit clears the reason.
	h.expect(admin, http.MethodPut, "/api/v1/sensors/content-policy", `{"policy":{"content":{"trivy-db":{"version":"--x"}}}}`, http.StatusBadRequest)
	h.expect(admin, http.MethodPut, "/api/v1/sensors/content-policy", `{"policy":{"content":{"bogus":{}}}}`, http.StatusBadRequest)
	mustJSON(t, h.expect(admin, http.MethodPut, "/api/v1/sensors/content-policy",
		`{"policy":{"refresh_interval_hours":12,"content":{"trivy-db":{"max_age_hours":96},"semgrep-rules":{"rulesets":["p/default"]}}},"apply_now":true}`,
		http.StatusOK), &pol)
	if pol.UpdatedAt == nil || pol.UpdatedBy == nil || *pol.UpdatedBy != admin.id || pol.Policy.RefreshIntervalHours != 12 ||
		pol.Policy.Content["trivy-db"].MaxAgeHours != 96 || pol.Policy.Content["nuclei-templates"].MaxAgeHours != 336 ||
		pol.CommandsCreated == nil || *pol.CommandsCreated != 0 {
		t.Fatalf("updated policy %+v", pol)
	}
	mustJSON(t, h.expect(viewer, http.MethodGet, "/api/v1/sensors/"+stale, "", http.StatusOK), &s)
	if s.Content[0].Stale || s.Content[0].MaxAgeHours != 96 || s.State != "degraded" ||
		s.HealthReasons[0].Code != "content_refresh_failed" {
		t.Fatalf("after policy: %+v %s %+v", s.Content, s.State, s.HealthReasons)
	}
	// The other tenant still has the defaults.
	mustJSON(t, h.expect(outsider, http.MethodGet, "/api/v1/sensors/content-policy", "", http.StatusOK), &pol)
	if pol.UpdatedAt != nil || pol.Policy.Content["trivy-db"].MaxAgeHours != 48 {
		t.Fatalf("policy leaked across tenants: %+v", pol)
	}

	// Both writes are audited.
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1
		AND action IN ('sensor.content_refresh_requested', 'sensor.content_policy_updated')`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 3 {
		t.Fatalf("audit events = %d, want at least 3 (refresh, fleet refresh, policy)", n)
	}
}

func mustJSON(t *testing.T, raw string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(raw), v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
}

// The heartbeat (v2) stores each tool's content inside the reported
// inventory, and a queued refresh_content reaches the sensor's command poll.
func TestSensorContent_HeartbeatAndPoll_DB(t *testing.T) {
	h := newCtlHarness(t)
	ctx := context.Background()
	s := h.newLimitedSensor(h.tenantID, "content-hb", nil, nil, 0)
	h.heartbeatV2(s, map[string]any{"status": "running", "tools": []map[string]any{
		{"name": "trivy", "version": "0.69.3", "installed": true, "content": []map[string]any{
			{"name": "trivy-db", "version": "2026-10-02T01:05:41Z", "updated_at": "2026-10-02T01:05:41Z",
				"fetched_at": "2026-10-02T04:59:26Z", "checked_at": "2026-10-02T05:30:00Z", "source": "mirror.gcr.io/aquasec/trivy-db:2",
				"digest": "sha256:3b169afdc4a0862bcd1dd493d9fedb5ba26be377f9d541cb3fdde9e2bebadfab", "managed": true},
			{"name": "NOT valid", "managed": true},
		}},
		{"name": "nuclei", "version": "3.4.1", "installed": true, "content": []map[string]any{
			{"name": "nuclei-templates", "version": "v10.4.9", "digest": "md5:nope", "managed": true, "error": "checksum mismatch"},
		}},
	}})
	got := h.load(s)
	content := got.ReportedContent()
	if len(content) != 2 || content[0].Tool != "trivy" || content[0].Digest == "" || content[0].UpdatedAt == nil || content[0].CheckedAt == nil ||
		content[1].Tool != "nuclei" || content[1].Digest != "" || content[1].Error != "checksum mismatch" {
		t.Fatalf("stored content %+v", content)
	}

	// A heartbeat without tools keeps the stored report.
	h.heartbeatV2(s, map[string]any{"status": "running"})
	if len(h.load(s).ReportedContent()) != 2 {
		t.Fatal("a heartbeat without tools dropped the stored content")
	}

	db := &postgres.DB{DB: h.db}
	svc := sensorapp.NewContentService(h.repo, h.sensors, postgres.NewSensorContentPolicyRepository(db),
		postgres.NewCommandRepository(db), nil, logger.NewNop())
	cmdID, _, err := svc.RefreshSensor(ctx, *got.TenantID, got.ID, nil, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/commands", nil)
	h.want(resp, raw, 200, "")
	if !strings.Contains(string(raw), cmdID.String()) || !strings.Contains(string(raw), `"type":"refresh_content"`) {
		t.Fatalf("poll did not return the refresh: %s", raw)
	}
}
