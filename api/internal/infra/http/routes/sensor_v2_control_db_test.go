package routes

// RFC-029: the protocol v2 control plane (heartbeat, commands, suppressions,
// fingerprint queries, key renewal) over the real route registration, with
// protocol v1 mounted beside it as in production, against a migrated
// database. Asserts the wire of RFC-029 §4, the idempotent transitions, the
// isolation between sensors and tenants, the deprecation headers on v1 and
// the protocol telemetry.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type ctlHarness struct {
	t        *testing.T
	db       *sql.DB
	srv      *httptest.Server
	sensors  *sensor.SensorService
	repo     *postgres.SensorRepository
	cmds     *command.Service
	tenantID string
	jwtToken string
}

type ctlSensor struct {
	id, key string
}

func newCtlHarness(t *testing.T) *ctlHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping protocol v2 control-plane test")
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
	ingestSvc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		sensorRepo, postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), log)
	cmdRepo := postgres.NewCommandRepository(db)
	cmdSvc := command.NewService(cmdRepo, log)
	sensorSvc.SetCancelFinder(cmdRepo)

	ih := handler.NewIngestHandler(ingestSvc, sensorSvc, log)
	ih.SetDoorbell(sensor.NewDoorbell(cmdRepo, sensor.DefaultDoorbellConfig().Normalized(5*time.Minute), log))
	ch := handler.NewCommandHandler(cmdSvc, validator.New(), log)
	sh := handler.NewSuppressionHandler(suppression.NewService(postgres.NewSuppressionRepository(db), log), log)
	ctl := handler.NewSensorControlV2Handler(ih, ch, sh, nil, log)
	receiver := ingest.NewV2Receiver(postgres.NewIngestReportRepository(db), postgres.NewIngestJobRepository(db),
		postgres.NewIngestJobRepository(db), cmdRepo, protov2.DefaultLimits(), 100, log)

	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "v2-control-test-secret-0123456789abcdef", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	userAuth := middleware.UnifiedAuth(middleware.UnifiedAuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen, Logger: log})
	tok, _, err := gen.GenerateAccessToken(shared.NewID().String(), shared.NewID().String(), "admin")
	if err != nil {
		t.Fatal(err)
	}

	router := infrahttp.NewChiRouter()
	registerSensorRoutes(router, ih, ch, nil, nil, sh, nil, nil, nil, log)
	registerSensorV2Routes(router, handler.NewSensorResultsV2Handler(receiver, sensorSvc, log), ctl, nil, log)
	router.Group("/api/v1/probe", func(r Router) {
		r.GET("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) })
	}, userAuth)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	h := &ctlHarness{t: t, db: sqldb, srv: srv, sensors: sensorSvc, repo: sensorRepo, cmds: cmdSvc, jwtToken: tok}
	h.tenantID = h.newTenant()
	return h
}

func (h *ctlHarness) newTenant() string {
	h.t.Helper()
	id := shared.NewID().String()
	if _, err := h.db.ExecContext(context.Background(), `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`,
		id, "v2-control-"+id); err != nil {
		h.t.Fatalf("seed tenant: %v", err)
	}
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM commands WHERE tenant_id = $1`, id)
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id)
	})
	return id
}

func (h *ctlHarness) newSensor(tenantID, name string) ctlSensor {
	h.t.Helper()
	out, err := h.sensors.CreateSensor(context.Background(), sensor.CreateSensorInput{TenantID: tenantID, Name: name,
		Type: "worker", Capabilities: []string{"sast"}, Tools: []string{"semgrep"}, ExecutionMode: "daemon"})
	if err != nil {
		h.t.Fatalf("create sensor: %v", err)
	}
	s := ctlSensor{id: out.Sensor.ID.String(), key: out.APIKey}
	h.verifyTools(s)
	return s
}

// newCommand creates a scan command in tenantID, pinned to sensorID unless
// it is "".
func (h *ctlHarness) newCommand(tenantID, sensorID string) string {
	h.t.Helper()
	c, err := h.cmds.Create(context.Background(), command.CreateInput{TenantID: tenantID, SensorID: sensorID,
		Type: "scan", Priority: "normal", Payload: json.RawMessage(`{"scanner":"semgrep","target":"."}`), ExpiresIn: 3600})
	if err != nil {
		h.t.Fatalf("create command: %v", err)
	}
	return c.ID.String()
}

func (h *ctlHarness) call(key, method, path string, body any, hdr ...string) (*http.Response, []byte) {
	h.t.Helper()
	var rdr io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rdr = bytes.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rdr = bytes.NewReader(raw)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, rdr)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if rdr != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "openctem-sdk-go/0.9.0 (openctemio-sensor/0.5.0)")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// want checks the status, the protocol header on v2 and, when problem is not
// "", the problem type URI (base + name).
func (h *ctlHarness) want(resp *http.Response, raw []byte, status int, problem string) {
	h.t.Helper()
	if resp.StatusCode != status {
		h.t.Fatalf("%s %s: status %d, want %d: %s", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, status, raw)
	}
	if strings.HasPrefix(resp.Request.URL.Path, protov2.PathPrefix) && resp.Header.Get(protov2.HeaderProtocol) != "2" {
		h.t.Fatalf("%s: missing %s header", resp.Request.URL.Path, protov2.HeaderProtocol)
	}
	if problem == "" {
		return
	}
	var p protov2.Problem
	if err := json.Unmarshal(raw, &p); err != nil || p.Type != problem {
		h.t.Fatalf("problem %q, want %q (%s)", p.Type, problem, raw)
	}
}

func sensorProblem(name string) string { return protov2.ProblemTypeBaseSensor + name }
func ingestProblem(name string) string { return protov2.ProblemTypeBase + name }

func decodeAs[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %T: %v (%s)", v, err, raw)
	}
	return v
}

func TestSensorV2Control_HelloListsEveryFeature(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "hello")
	resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/hello", nil)
	h.want(resp, raw, 200, "")
	hello := decodeAs[protov2.Hello](t, raw)
	want := append([]string{protov2.FeatureResults}, protov2.ControlFeatures()...)
	if strings.Join(hello.Features, ",") != strings.Join(want, ",") {
		t.Fatalf("features %v, want %v", hello.Features, want)
	}
	dep, ok := hello.Deprecations[protov2.DeprecationProtocolV1]
	if !ok || !dep.SunsetAt.Equal(time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("deprecations %+v", hello.Deprecations)
	}
	if hello.Limits.MaxFingerprintsPerRequest != protov2.DefaultMaxFingerprintsPerRequest {
		t.Fatalf("limits %+v", hello.Limits)
	}
}

func TestSensorV2Control_HeartbeatAndTelemetry(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "hb")

	resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/heartbeat",
		map[string]any{"status": "running", "version": "0.5.0", "hostname": "ci-01", "unknown_future_field": 1})
	h.want(resp, raw, 200, "")
	hb := decodeAs[protov2.HeartbeatResponse](t, raw)
	if hb.SensorID != s.id || hb.TenantID != h.tenantID || hb.Status != "ok" || hb.Actions == nil ||
		hb.NextHeartbeatSeconds == 0 || len(hb.ConfigVersion) != 16 {
		t.Fatalf("heartbeat %+v (%s)", hb, raw)
	}
	// Every member is always present.
	for _, k := range []string{`"pending_jobs":0`, `"actions":[]`} {
		if !strings.Contains(string(raw), k) {
			t.Fatalf("heartbeat body lacks %s: %s", k, raw)
		}
	}
	got, err := h.repo.GetByID(context.Background(), shared.MustIDFromString(s.id))
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol == nil || got.Protocol.Version != 2 || got.Protocol.UserAgent != "openctem-sdk-go/0.9.0 (openctemio-sensor/0.5.0)" ||
		got.Version != "0.5.0" || got.Hostname != "ci-01" {
		t.Fatalf("stored telemetry %+v version=%q host=%q", got.Protocol, got.Version, got.Hostname)
	}

	// A v1 heartbeat records protocol 1, keeps its v1 body and carries the
	// deprecation headers.
	resp, raw = h.call(s.key, http.MethodPost, "/api/v1/agent/heartbeat", map[string]any{"status": "running"},
		"User-Agent", "openctem-sdk-go/0.8.1\t(\u00e9sensor)")
	h.want(resp, raw, 200, "")
	if !strings.Contains(string(raw), `"agent_id"`) {
		t.Fatalf("v1 body changed: %s", raw)
	}
	if resp.Header.Get("Deprecation") != "@1790812800" || resp.Header.Get("Sunset") != "Thu, 01 Apr 2027 00:00:00 GMT" ||
		resp.Header.Get("Link") != `</api/v2/sensor/heartbeat>; rel="successor-version"` {
		t.Fatalf("v1 deprecation headers %v", resp.Header)
	}
	got, _ = h.repo.GetByID(context.Background(), shared.MustIDFromString(s.id))
	if got.Protocol == nil || got.Protocol.Version != 1 || !got.Protocol.Deprecated() ||
		got.Protocol.UserAgent != "openctem-sdk-go/0.8.1(sensor)" {
		t.Fatalf("v1 telemetry %+v", got.Protocol)
	}
}

func TestSensorV2Control_HeartbeatBodies(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "bodies")
	// Empty body is a valid heartbeat.
	resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/heartbeat", nil)
	h.want(resp, raw, 200, "")
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/heartbeat", []byte(`{"status":`))
	h.want(resp, raw, 400, ingestProblem("invalid-request"))
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/heartbeat", []byte(`status=1`), "Content-Type", "text/plain")
	h.want(resp, raw, 415, ingestProblem("unsupported-media-type"))
	if resp.Header.Get("Accept") != "application/json" {
		t.Fatalf("415 Accept %q", resp.Header.Get("Accept"))
	}
	big := []byte(`{"message":"` + strings.Repeat("a", 1<<20) + `"}`)
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/heartbeat", big)
	h.want(resp, raw, 413, ingestProblem("content-too-large"))
}

func TestSensorV2Control_DisabledAndRevoked(t *testing.T) {
	h := newCtlHarness(t)
	ctx := context.Background()
	s := h.newSensor(h.tenantID, "paused")
	if _, err := h.db.ExecContext(ctx, `UPDATE sensors SET status = 'disabled' WHERE id = $1`, s.id); err != nil {
		t.Fatal(err)
	}
	resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/heartbeat", nil)
	h.want(resp, raw, 200, "")
	hb := decodeAs[protov2.HeartbeatResponse](t, raw)
	if hb.Status != "paused" || len(hb.Actions) != 1 || hb.Actions[0] != "pause" {
		t.Fatalf("paused heartbeat %+v", hb)
	}
	resp, raw = h.call(s.key, http.MethodGet, "/api/v2/sensor/commands", nil)
	h.want(resp, raw, 401, ingestProblem("unauthenticated"))
	// hello stays reachable, so a paused sensor keeps negotiating v2.
	resp, raw = h.call(s.key, http.MethodGet, "/api/v2/sensor/hello", nil)
	h.want(resp, raw, 200, "")
	resp, raw = h.call(s.key, http.MethodGet, "/api/v2/sensor/suppressions", nil)
	h.want(resp, raw, 401, ingestProblem("unauthenticated"))

	r := h.newSensor(h.tenantID, "revoked")
	if _, err := h.db.ExecContext(ctx, `UPDATE sensors SET status = 'revoked' WHERE id = $1`, r.id); err != nil {
		t.Fatal(err)
	}
	resp, raw = h.call(r.key, http.MethodPost, "/api/v2/sensor/heartbeat", nil)
	h.want(resp, raw, 401, ingestProblem("unauthenticated"))
	resp, raw = h.call("rda_not-a-key", http.MethodPost, "/api/v2/sensor/heartbeat", nil)
	h.want(resp, raw, 401, ingestProblem("unauthenticated"))
	// A user token is not a sensor key; a sensor key is not a user token.
	resp, raw = h.call("", http.MethodPost, "/api/v2/sensor/heartbeat", nil, "Authorization", "Bearer "+h.jwtToken)
	h.want(resp, raw, 401, ingestProblem("unauthenticated"))
	ok := h.newSensor(h.tenantID, "ok")
	resp, _ = h.call(ok.key, http.MethodGet, "/api/v1/probe/", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("sensor key on a user route: %d", resp.StatusCode)
	}
}

func TestSensorV2Control_CommandLifecycleIsIdempotent(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "worker")
	id := h.newCommand(h.tenantID, "")
	base := "/api/v2/sensor/commands/" + id

	resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=5", nil)
	h.want(resp, raw, 200, "")
	list := decodeAs[protov2.CommandList](t, raw)
	if len(list.Commands) != 1 || list.Commands[0].ID != id || list.Commands[0].SensorID != nil || list.Commands[0].Status != "pending" {
		t.Fatalf("poll %s", raw)
	}

	// Transitions out of order are refused with the current state.
	resp, raw = h.call(s.key, http.MethodPost, base+"/start", nil)
	h.want(resp, raw, 409, sensorProblem("invalid-transition"))
	if p := decodeAs[protov2.Problem](t, raw); p.State != "pending" {
		t.Fatalf("state %q", p.State)
	}

	for _, step := range []struct {
		action, status string
		body           any
	}{
		{"claim", "acknowledged", nil},
		{"start", "running", nil},
		{"complete", "completed", map[string]any{"result": map[string]any{"findings": 2, "tool": "semgrep"}}},
	} {
		resp, raw = h.call(s.key, http.MethodPost, base+"/"+step.action, step.body)
		h.want(resp, raw, 200, "")
		c := decodeAs[protov2.Command](t, raw)
		if c.Status != step.status || c.SensorID == nil || *c.SensorID != s.id {
			t.Fatalf("%s: %s", step.action, raw)
		}
		// The same request again is a replay: 200, same state.
		resp, raw = h.call(s.key, http.MethodPost, base+"/"+step.action, step.body)
		h.want(resp, raw, 200, "")
		if c := decodeAs[protov2.Command](t, raw); c.Status != step.status {
			t.Fatalf("%s replay: %s", step.action, raw)
		}
	}
	// claim replay after start: no longer the current state.
	resp, raw = h.call(s.key, http.MethodPost, base+"/claim", nil)
	h.want(resp, raw, 409, sensorProblem("invalid-transition"))

	// A replay with keys in another order and other spacing is the same JSON.
	resp, raw = h.call(s.key, http.MethodPost, base+"/complete", []byte(`{ "result" : {"tool":"semgrep", "findings":2} }`))
	h.want(resp, raw, 200, "")
	resp, raw = h.call(s.key, http.MethodPost, base+"/complete", map[string]any{"result": map[string]any{"findings": 3}})
	h.want(resp, raw, 409, sensorProblem("transition-conflict"))
	resp, raw = h.call(s.key, http.MethodPost, base+"/fail", map[string]any{"error_message": "late"})
	h.want(resp, raw, 409, sensorProblem("invalid-transition"))
	if p := decodeAs[protov2.Problem](t, raw); p.State != "completed" {
		t.Fatalf("state %q", p.State)
	}
	// The v1 poll no longer offers it.
	resp, raw = h.call(s.key, http.MethodGet, "/api/v2/sensor/commands", nil)
	h.want(resp, raw, 200, "")
	if l := decodeAs[protov2.CommandList](t, raw); len(l.Commands) != 0 {
		t.Fatalf("finished command still offered: %s", raw)
	}
}

func TestSensorV2Control_FailIsIdempotent(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "failer")
	id := h.newCommand(h.tenantID, s.id) // pinned: may be failed while pending
	base := "/api/v2/sensor/commands/" + id
	resp, raw := h.call(s.key, http.MethodPost, base+"/fail", map[string]any{"error_message": "scanner not installed"})
	h.want(resp, raw, 200, "")
	if c := decodeAs[protov2.Command](t, raw); c.Status != "failed" || c.ErrorMessage != "scanner not installed" {
		t.Fatalf("fail: %s", raw)
	}
	resp, raw = h.call(s.key, http.MethodPost, base+"/fail", map[string]any{"error_message": "scanner not installed"})
	h.want(resp, raw, 200, "")
	resp, raw = h.call(s.key, http.MethodPost, base+"/fail", map[string]any{"error_message": "something else"})
	h.want(resp, raw, 409, sensorProblem("transition-conflict"))
	resp, raw = h.call(s.key, http.MethodPost, base+"/claim", nil)
	h.want(resp, raw, 409, sensorProblem("invalid-transition"))
}

func TestSensorV2Control_CommandIsolation(t *testing.T) {
	h := newCtlHarness(t)
	a := h.newSensor(h.tenantID, "a")
	b := h.newSensor(h.tenantID, "b")
	other := h.newTenant()
	x := h.newSensor(other, "x")

	pinnedToB := h.newCommand(h.tenantID, b.id)
	unassigned := h.newCommand(h.tenantID, "")

	// Another sensor's command, another tenant's command, an unknown id: 404.
	for _, tc := range []struct {
		key, path string
	}{
		{a.key, "/api/v2/sensor/commands/" + pinnedToB + "/claim"},
		{x.key, "/api/v2/sensor/commands/" + unassigned + "/claim"},
		{a.key, "/api/v2/sensor/commands/" + strings.ToLower(shared.NewID().String()) + "/claim"},
	} {
		resp, raw := h.call(tc.key, http.MethodPost, tc.path, nil)
		h.want(resp, raw, 404, ingestProblem("command-not-found"))
	}
	resp, raw := h.call(a.key, http.MethodPost, "/api/v2/sensor/commands/not-a-uuid/claim", nil)
	h.want(resp, raw, 400, ingestProblem("invalid-id"))

	// b claims the unassigned command; it becomes b's and a sees 404.
	resp, raw = h.call(b.key, http.MethodPost, "/api/v2/sensor/commands/"+unassigned+"/claim", nil)
	h.want(resp, raw, 200, "")
	resp, raw = h.call(a.key, http.MethodPost, "/api/v2/sensor/commands/"+unassigned+"/claim", nil)
	h.want(resp, raw, 404, ingestProblem("command-not-found"))
	// The other tenant's sensor is never offered it.
	resp, raw = h.call(x.key, http.MethodGet, "/api/v2/sensor/commands", nil)
	h.want(resp, raw, 200, "")
	if l := decodeAs[protov2.CommandList](t, raw); len(l.Commands) != 0 {
		t.Fatalf("cross-tenant poll: %s", raw)
	}
}

func TestSensorV2Control_ExpiredCommand(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "late")
	id := h.newCommand(h.tenantID, "")
	if _, err := h.db.ExecContext(context.Background(), `UPDATE commands SET expires_at = NOW() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/claim", nil)
	h.want(resp, raw, 409, sensorProblem("invalid-transition"))
	if p := decodeAs[protov2.Problem](t, raw); p.State != "expired" {
		t.Fatalf("state %q", p.State)
	}
}

func TestSensorV2Control_V1CommandRoutesAreDeprecated(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "v1")
	id := h.newCommand(h.tenantID, "")
	resp, raw := h.call(s.key, http.MethodPost, "/api/v1/agent/commands/"+id+"/acknowledge", nil)
	h.want(resp, raw, 200, "")
	if got := resp.Header.Get("Link"); got != `</api/v2/sensor/commands/`+id+`/claim>; rel="successor-version"` {
		t.Fatalf("Link %q", got)
	}
	// Not-yet-replaced v1 routes are counted but not deprecated.
	resp, _ = h.call(s.key, http.MethodGet, "/api/v1/agent/ingest/scanners", nil)
	if resp.Header.Get("Deprecation") != "" {
		t.Fatalf("ingest/scanners deprecated without a successor")
	}
	// Errors carry the headers too.
	resp, _ = h.call(s.key, http.MethodPost, "/api/v1/agent/commands/"+id+"/complete", nil)
	if resp.StatusCode < 400 || resp.Header.Get("Deprecation") == "" {
		t.Fatalf("v1 error: %d %v", resp.StatusCode, resp.Header)
	}
}

func TestSensorV2Control_Suppressions(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "gate")
	resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/suppressions", nil)
	h.want(resp, raw, 200, "")
	if string(bytes.TrimSpace(raw)) != `{"count":0,"rules":[]}` {
		t.Fatalf("suppressions %s", raw)
	}
	etag := resp.Header.Get("ETag")
	if len(etag) != 18 || etag[0] != '"' {
		t.Fatalf("ETag %q", etag)
	}
	resp, raw = h.call(s.key, http.MethodGet, "/api/v2/sensor/suppressions", nil, "If-None-Match", etag)
	if resp.StatusCode != http.StatusNotModified || len(raw) != 0 || resp.Header.Get("ETag") != etag {
		t.Fatalf("revalidation: %d %q", resp.StatusCode, raw)
	}
	resp, _ = h.call(s.key, http.MethodGet, "/api/v2/sensor/suppressions", nil, "If-None-Match", `"0000000000000000"`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stale tag: %d", resp.StatusCode)
	}
}

func TestSensorV2Control_FingerprintQueries(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "fp")
	resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/fingerprints/check", map[string]any{"fingerprints": []string{}})
	h.want(resp, raw, 200, "")
	if string(bytes.TrimSpace(raw)) != `{"existing":[],"missing":[]}` {
		t.Fatalf("empty check %s", raw)
	}
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/fingerprints/check", map[string]any{"fingerprints": []string{"fp-a", "fp-b"}})
	h.want(resp, raw, 200, "")
	if c := decodeAs[protov2.FingerprintsCheckResponse](t, raw); len(c.Missing) != 2 || len(c.Existing) != 0 {
		t.Fatalf("check %s", raw)
	}
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/fingerprints/baseline-diff",
		map[string]any{"repository": "github.com/acme/app", "base_branch": "main", "fingerprints": []string{"fp-a"}})
	h.want(resp, raw, 200, "")
	if d := decodeAs[protov2.BaselineDiffResponse](t, raw); len(d.NewFingerprints) != 1 || d.PreExistingFingerprints == nil {
		t.Fatalf("baseline-diff %s", raw)
	}
	many := make([]string, protov2.DefaultMaxFingerprintsPerRequest+1)
	for i := range many {
		many[i] = "f"
	}
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/fingerprints/check", map[string]any{"fingerprints": many})
	h.want(resp, raw, 422, sensorProblem("too-many-items"))
	if p := decodeAs[protov2.Problem](t, raw); p.Limit == nil || *p.Limit != protov2.DefaultMaxFingerprintsPerRequest {
		t.Fatalf("limit %s", raw)
	}
}

func TestSensorV2Control_KeyRenewal(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "renew")
	resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/keys", nil)
	h.want(resp, raw, 201, "")
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", resp.Header.Get("Cache-Control"))
	}
	k := decodeAs[protov2.KeyResponse](t, raw)
	if k.APIKey == "" || k.APIKey == s.key {
		t.Fatalf("new key %s", raw)
	}
	resp, raw = h.call(k.APIKey, http.MethodPost, "/api/v2/sensor/heartbeat", nil)
	h.want(resp, raw, 200, "")
	// Without a key TTL the presented key is replaced (as v1).
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/heartbeat", nil)
	h.want(resp, raw, 401, ingestProblem("unauthenticated"))
}
