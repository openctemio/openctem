package handler

// Golden wire test for sensor protocol v1 (RFC-023 §9.2 C1/C8).
//
// Deployed sensors and every released SDK speak protocol v1: the
// /api/v1/agent/* routes, the X-API-Key / Bearer key, and the request and
// response JSON below. The agent → sensor rename must not change one byte of
// it. The files under testdata/protocol_v1 were recorded from origin/develop
// BEFORE the rename (same harness, old identifiers) and this test replays the
// same flow against the current handlers and real repositories, comparing the
// responses after masking values that differ per run (ids, timestamps, keys).
//
// Needs DATABASE_URL (CI's Test job provides one); skipped otherwise.
// Re-record with: go test ./internal/infra/http/handler -run ProtocolV1 -update-protocol-v1

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"
	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/scan"
	sensorsvc "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/legacyv1"
	"github.com/openctemio/openctem/api/pkg/validator"
	"github.com/openctemio/openctem/api/tools/lint/openapicontract"
)

var updateProtocolV1 = flag.Bool("update-protocol-v1", false, "re-record testdata/protocol_v1 golden files")

type v1Harness struct {
	t        *testing.T
	db       *sql.DB
	srv      *httptest.Server
	key      string
	masks    []mask
	client   *http.Client
	sensorID string
	tenantID string
	header   http.Header // extra request headers for the next calls
	ingest   *IngestHandler
}

type mask struct{ from, to string }

func newV1Harness(t *testing.T) *v1Harness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping protocol v1 golden test")
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
	sensorSvc := sensorsvc.NewSensorService(sensorRepo, nil, log)
	sensorSvc.SetAPIKeyRepository(postgres.NewSensorAPIKeyRepository(db))
	cmdSvc := command.NewService(postgres.NewCommandRepository(db), log)
	ingestSvc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		sensorRepo, postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), log)
	sessionSvc := scan.NewScanSessionService(postgres.NewScanSessionRepository(db), sensorRepo, log)

	v := validator.New()
	ih := NewIngestHandler(ingestSvc, sensorSvc, log)
	// The doorbell is wired as in production: flow.golden proves an idle
	// heartbeat is still byte-identical with it on.
	// The load back-off is the one input that depends on how fast the test
	// database answers: a doorbell query slower than SlowQuery advises the
	// loaded interval, which a non-doorbell sensor also receives. On a busy CI
	// runner that turned the idle heartbeat into "next_heartbeat_seconds":120
	// and failed the golden for reasons unrelated to the wire. Raise the
	// threshold so the golden pins the wire, not the runner's latency; the
	// back-off itself is covered by the doorbell unit tests.
	golden := sensorsvc.DefaultDoorbellConfig()
	golden.SlowQuery = 30 * time.Second
	golden.QueryTimeout = time.Minute
	ih.SetDoorbell(sensorsvc.NewDoorbell(postgres.NewCommandRepository(db),
		golden.Normalized(5*time.Minute), log))
	// So is the protocol v2 advertisement (RFC-026): flow.golden proves a v1
	// sensor that does not ask for it sees nothing new.
	ih.SetV2Advertised(true)
	ch := NewCommandHandler(cmdSvc, v, log)
	sh := NewScanSessionHandler(sessionSvc, v, log)

	// The v1 routes exactly as routes/scanning.go mounts them; the route table
	// itself is pinned separately by TestProtocolV1_RouteTable.
	r := chi.NewRouter()
	r.Route("/api/v1/agent", func(r chi.Router) {
		r.Use(ih.AuthenticateSource)
		r.Post("/heartbeat", ih.Heartbeat)
		r.Post("/renew", ih.RenewKey)
		r.Post("/ingest", ih.IngestCTIS)
		r.Post("/ingest/check", ih.CheckFingerprints)
		r.Get("/commands", ch.Poll)
		r.Post("/commands/{id}/acknowledge", ch.Acknowledge)
		r.Post("/commands/{id}/start", ch.Start)
		r.Post("/commands/{id}/complete", ch.Complete)
		r.Post("/commands/{id}/fail", ch.Fail)
		r.Post("/scans", sh.RegisterScan)
		r.Patch("/scans/{id}", sh.UpdateScan)
		r.Get("/scans/{id}", sh.GetScan)
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	ctx := context.Background()
	tenantID := shared.NewID()
	if _, err := sqldb.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID.String(), "protocol v1 golden", "v1-golden-"+tenantID.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID.String())
	})

	out, err := sensorSvc.CreateSensor(ctx, sensorsvc.CreateSensorInput{
		TenantID: tenantID.String(), Name: "golden-sensor", Type: "worker",
		Capabilities: []string{"sast"}, Tools: []string{"semgrep"}, ExecutionMode: "daemon",
	})
	if err != nil {
		t.Fatalf("create sensor: %v", err)
	}
	h := &v1Harness{t: t, db: sqldb, srv: srv, key: out.APIKey, client: srv.Client(),
		sensorID: out.Sensor.ID.String(), tenantID: tenantID.String(), ingest: ih}
	h.masks = []mask{
		{tenantID.String(), "<tenant>"},
		{out.Sensor.ID.String(), "<self>"},
	}
	return h
}

// reportTools records that the sensor reported (verified) its declared
// tools, as every supported SDK (v0.10.0 and later) does on its first
// heartbeat. Dispatch only hands a sensor the tools it verified, so the
// golden flows model such a sensor.
func (h *v1Harness) reportTools() {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(),
		`UPDATE sensors SET reported_tool_names = tools, reported_at = now() WHERE id = $1`, h.sensorID); err != nil {
		h.t.Fatalf("record reported tools: %v", err)
	}
}

func (h *v1Harness) seedCommand(label string) string {
	h.t.Helper()
	var tenant string
	for _, m := range h.masks {
		if m.to == "<tenant>" {
			tenant = m.from
		}
	}
	id := shared.NewID().String()
	_, err := h.db.ExecContext(context.Background(),
		`INSERT INTO commands (id, tenant_id, type, priority, payload, status, created_at, expires_at)
		 VALUES ($1, $2, 'scan', 'normal', '{"scanner":"semgrep","target":"."}', 'pending', NOW(), NOW() + interval '1 hour')`,
		id, tenant)
	if err != nil {
		h.t.Fatalf("seed command: %v", err)
	}
	h.masks = append(h.masks, mask{id, "<" + label + ">"})
	return id
}

// do sends one request and returns the masked transcript of the response.
func (h *v1Harness) do(method, path string, body any, auth bool) (string, []byte) {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+h.key)
	}
	for k, vs := range h.header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\nstatus: %d\n", method, h.mask(path), resp.StatusCode)
	for _, k := range []string{"Content-Type", "Location"} {
		if v := resp.Header.Get(k); v != "" {
			fmt.Fprintf(&b, "%s: %s\n", k, h.mask(v))
		}
	}
	fmt.Fprintf(&b, "\n%s", h.mask(string(raw)))
	return b.String(), raw
}

var (
	uuidRe = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	timeRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})`)
	keyRe  = regexp.MustCompile(`"api_key":"[^"]+"`)
	durRe  = regexp.MustCompile(`"duration_ms":\d+`)
	cfgRe  = regexp.MustCompile(`"config_version":"[0-9a-f]{16}"`)
)

func (h *v1Harness) mask(s string) string {
	for _, m := range h.masks {
		s = strings.ReplaceAll(s, m.from, m.to)
	}
	s = uuidRe.ReplaceAllString(s, "<uuid>")
	s = timeRe.ReplaceAllString(s, "<time>")
	s = keyRe.ReplaceAllString(s, `"api_key":"<api-key>"`)
	s = durRe.ReplaceAllString(s, `"duration_ms":<ms>`)
	s = cfgRe.ReplaceAllString(s, `"config_version":"<config-version>"`)
	return s
}

func TestProtocolV1_GoldenWire(t *testing.T) {
	h := newV1Harness(t)
	h.reportTools()
	var transcript []string
	step := func(method, path string, body any) []byte {
		tr, raw := h.do(method, path, body, true)
		transcript = append(transcript, tr)
		return raw
	}

	// Connect + liveness.
	step(http.MethodPost, "/api/v1/agent/heartbeat", map[string]any{
		"name": "golden-sensor", "status": "running", "version": "0.6.0", "hostname": "golden-host",
		"scanners": []string{"semgrep"}, "uptime_seconds": 42, "cpu_percent": 12.5, "memory_percent": 30,
		"active_jobs": 0, "region": "eu",
	})
	// Unauthenticated request: the error body is part of the contract too.
	tr, _ := h.do(http.MethodPost, "/api/v1/agent/heartbeat", map[string]any{"status": "running"}, false)
	transcript = append(transcript, tr)

	// Command lifecycle: poll → acknowledge → start → complete, and a fail.
	ok := h.seedCommand("cmd-ok")
	step(http.MethodGet, "/api/v1/agent/commands?limit=1", nil)
	step(http.MethodPost, "/api/v1/agent/commands/"+ok+"/acknowledge", nil)
	step(http.MethodPost, "/api/v1/agent/commands/"+ok+"/start", nil)
	step(http.MethodPost, "/api/v1/agent/commands/"+ok+"/complete", map[string]any{
		"result": map[string]any{"findings_count": 0},
	})
	bad := h.seedCommand("cmd-fail")
	step(http.MethodPost, "/api/v1/agent/commands/"+bad+"/acknowledge", nil)
	step(http.MethodPost, "/api/v1/agent/commands/"+bad+"/fail", map[string]any{"error_message": "scanner crashed"})

	// Scan session register → update → get.
	raw := step(http.MethodPost, "/api/v1/agent/scans", map[string]any{
		"scanner_name": "semgrep", "scanner_version": "1.0", "scanner_type": "sast",
		"asset_type": "repository", "asset_value": "github.com/openctemio/golden",
		"commit_sha": "abc123", "branch": "main",
	})
	var reg struct {
		ScanID string `json:"scan_id"`
	}
	_ = json.Unmarshal(raw, &reg)
	if reg.ScanID == "" {
		t.Fatalf("scan registration returned no scan_id: %s", raw)
	}
	h.masks = append(h.masks, mask{reg.ScanID, "<scan>"})
	step(http.MethodPatch, "/api/v1/agent/scans/"+reg.ScanID, map[string]any{
		"status": "completed", "findings_total": 0, "findings_new": 0, "findings_fixed": 0,
	})
	step(http.MethodGet, "/api/v1/agent/scans/"+reg.ScanID, nil)

	// Push: fingerprint check and an (empty) CTIS report.
	step(http.MethodPost, "/api/v1/agent/ingest/check", map[string]any{"fingerprints": []string{"fp-1"}})
	step(http.MethodPost, "/api/v1/agent/ingest", map[string]any{
		"version":  "1.0",
		"metadata": map[string]any{"id": "golden-report", "source_type": "scanner", "timestamp": "2026-10-01T00:00:00Z"},
		"tool":     map[string]any{"name": "semgrep", "version": "1.0"},
		"assets":   []any{},
		"findings": []any{},
	})

	// Key renewal last: it retires the key used above.
	step(http.MethodPost, "/api/v1/agent/renew", nil)

	compareGolden(t, "flow.golden", strings.Join(transcript, "\n----\n"))
}

// TestProtocolV1_GoldenDoorbell pins the heartbeat doorbell (RFC-023 §9.2a),
// an ADDITIVE protocol v1 extension: pending_jobs, config_version, actions
// and next_heartbeat_seconds are new optional fields, all omitempty. An idle
// sensor that did not announce the doorbell feature still gets the exact v1
// bytes (first and last heartbeat below, and flow.golden); the other
// transcripts show the fields a deployed v1 sensor that ignores the body
// (sdk-go v0.6.0) never reads.
func TestProtocolV1_GoldenDoorbell(t *testing.T) {
	h := newV1Harness(t)
	h.reportTools()
	var transcript []string
	step := func(note, method, path string) []byte {
		tr, raw := h.do(method, path, nil, true)
		transcript = append(transcript, "# "+note+"\n"+tr)
		return raw
	}
	aware := http.Header{legacyv1.HeaderSensorFeatures: {legacyv1.FeatureDoorbell}}
	ctx := context.Background()

	step("idle, v1 sensor: plain v1 response", http.MethodPost, "/api/v1/agent/heartbeat")

	pool := h.seedCommand("cmd-pool")
	pinned := shared.NewID().String()
	if _, err := h.db.ExecContext(ctx,
		`INSERT INTO commands (id, tenant_id, sensor_id, type, priority, payload, status, created_at)
		 VALUES ($1, $2, $3, 'scan', 'normal', '{"scanner":"semgrep"}', 'pending', NOW())`,
		pinned, h.tenantID, h.sensorID); err != nil {
		t.Fatalf("seed pinned command: %v", err)
	}
	h.masks = append(h.masks, mask{pinned, "<cmd-pinned>"})
	step("work waiting, v1 sensor: pending_jobs and the busy interval only", http.MethodPost, "/api/v1/agent/heartbeat")
	h.header = aware
	step("work waiting, doorbell-aware sensor: plus config_version", http.MethodPost, "/api/v1/agent/heartbeat")

	// The sensor reacts by polling; the doorbell never carries the job.
	step("poll", http.MethodGet, "/api/v1/agent/commands?limit=10")
	step("claim the pool command", http.MethodPost, "/api/v1/agent/commands/"+pool+"/acknowledge")
	step("claim the pinned command", http.MethodPost, "/api/v1/agent/commands/"+pinned+"/acknowledge")
	step("idle, doorbell-aware sensor: config_version and the idle interval", http.MethodPost, "/api/v1/agent/heartbeat")
	h.header = nil
	step("idle again, v1 sensor: plain v1 response", http.MethodPost, "/api/v1/agent/heartbeat")

	if _, err := h.db.ExecContext(ctx, `UPDATE sensors SET status = 'disabled' WHERE id = $1`, h.sensorID); err != nil {
		t.Fatal(err)
	}
	step("disabled, v1 sensor: unchanged v1 401", http.MethodPost, "/api/v1/agent/heartbeat")
	h.header = aware
	step("disabled, doorbell-aware sensor: 200 with pause", http.MethodPost, "/api/v1/agent/heartbeat")
	step("disabled, doorbell-aware sensor, any other route: 401", http.MethodGet, "/api/v1/agent/commands")

	if _, err := h.db.ExecContext(ctx, `UPDATE sensors SET status = 'revoked' WHERE id = $1`, h.sensorID); err != nil {
		t.Fatal(err)
	}
	step("revoked, doorbell-aware sensor: 401", http.MethodPost, "/api/v1/agent/heartbeat")

	compareGolden(t, "doorbell.golden", strings.Join(transcript, "\n----\n"))
}

type failingPendingWork struct{}

func (failingPendingWork) PendingWorkForSensor(context.Context, shared.ID, shared.ID, []string, int) (sensordom.PendingWork, error) {
	return sensordom.PendingWork{}, errors.New("database is down")
}

// A failing doorbell query must not fail the heartbeat: 200, no hints.
func TestProtocolV1_DoorbellQueryFailureKeepsHeartbeat(t *testing.T) {
	h := newV1Harness(t)
	h.ingest.SetDoorbell(sensorsvc.NewDoorbell(failingPendingWork{}, sensorsvc.DefaultDoorbellConfig(), logger.NewNop()))
	h.seedCommand("cmd")
	h.header = http.Header{legacyv1.HeaderSensorFeatures: {"other, Doorbell"}}
	tr, _ := h.do(http.MethodPost, "/api/v1/agent/heartbeat", nil, true)
	want := "POST /api/v1/agent/heartbeat\nstatus: 200\nContent-Type: application/json\n\n" +
		`{"agent_id":"<self>","status":"ok","tenant_id":"<tenant>"}` + "\n"
	if tr != want {
		t.Errorf("heartbeat with a failing doorbell query:\n%s\nwant\n%s", tr, want)
	}
}

// TestProtocolV1_RouteTable pins every route a v1 sensor can call.
func TestProtocolV1_RouteTable(t *testing.T) {
	routes, err := v1Routes(filepath.Join("..", "routes"))
	if err != nil {
		t.Fatal(err)
	}
	compareGolden(t, "routes.golden", strings.Join(routes, "\n")+"\n")
}

func compareGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "protocol_v1", name)
	if *updateProtocolV1 {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // test fixture dir
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // fixed test fixture path
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	if string(want) != got {
		t.Errorf("protocol v1 wire changed (%s). A deployed sensor would see this difference.\n--- want\n%s\n--- got\n%s", name, want, got)
	}
}

// v1Routes lists the registered routes a v1 sensor can call, read from the
// route source the same way the OpenAPI contract gate reads it.
func v1Routes(routesDir string) ([]string, error) {
	ops, err := openapicontract.Routes(routesDir)
	if err != nil {
		return nil, err
	}
	var out []string
	for op := range ops {
		if strings.HasPrefix(op.Path, "/api/v1/agent/") || op.Path == "/api/v1/validation/evidence" {
			out = append(out, op.String())
		}
	}
	sort.Strings(out)
	return out, nil
}
