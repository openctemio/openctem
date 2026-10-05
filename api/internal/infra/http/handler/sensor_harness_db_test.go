package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// sensorHarness is one tenant sensor that heartbeats for real over the
// protocol v2 control handler (POST /api/v2/sensor/heartbeat), against a
// migrated database. The full v2 route chain is covered in the routes
// package; this harness serves handler-level tests of what a heartbeat
// stores and what the management API then shows.
type sensorHarness struct {
	t        *testing.T
	db       *sql.DB
	srv      *httptest.Server
	key      string
	masks    []mask
	client   *http.Client
	sensorID string
	tenantID string
	header   http.Header // extra request headers for the next calls
}

type mask struct{ from, to string }

const heartbeatPath = "/api/v2/sensor/heartbeat"

func newSensorHarness(t *testing.T) *sensorHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping sensor heartbeat test")
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
	sensorSvc := app.NewSensorService(sensorRepo, nil, log)
	sensorSvc.SetAPIKeyRepository(postgres.NewSensorAPIKeyRepository(db))
	cmdRepo := postgres.NewCommandRepository(db)
	ih := NewIngestHandler(nil, sensorSvc, log)
	doorbell := app.DefaultDoorbellConfig()
	doorbell.SlowQuery = 30 * time.Second
	doorbell.QueryTimeout = time.Minute
	ih.SetDoorbell(app.NewDoorbell(cmdRepo, doorbell.Normalized(5*time.Minute), log))
	ch := NewCommandHandler(command.NewService(cmdRepo, log), validator.New(), log)
	ctl := NewSensorControlV2Handler(ih, ch, nil, nil, log)

	r := chi.NewRouter()
	r.With(ih.AuthenticateSource).Post(heartbeatPath, ctl.Heartbeat)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	ctx := context.Background()
	tenantID := shared.NewID()
	if _, err := sqldb.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID.String(), "sensor heartbeat harness", "sensor-hb-"+tenantID.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID.String())
	})

	out, err := sensorSvc.CreateSensor(ctx, app.CreateSensorInput{
		TenantID: tenantID.String(), Name: "harness-sensor", Type: "worker",
		Capabilities: []string{"sast"}, Tools: []string{"semgrep"}, ExecutionMode: "daemon",
	})
	if err != nil {
		t.Fatalf("create sensor: %v", err)
	}
	h := &sensorHarness{t: t, db: sqldb, srv: srv, key: out.APIKey, client: srv.Client(),
		sensorID: out.Sensor.ID.String(), tenantID: tenantID.String()}
	h.masks = []mask{
		{tenantID.String(), "<tenant>"},
		{out.Sensor.ID.String(), "<self>"},
	}
	return h
}

// heartbeat sends one heartbeat and fails unless it was answered 200 for this
// sensor.
func (h *sensorHarness) heartbeat(body any) {
	h.t.Helper()
	code, raw := h.do(http.MethodPost, heartbeatPath, body, true)
	if code != http.StatusOK || !strings.Contains(h.mask(string(raw)), `"sensor_id":"<self>"`) {
		h.t.Fatalf("heartbeat: %d %s", code, h.mask(string(raw)))
	}
}

// do sends one request and returns the status code and the response body.
func (h *sensorHarness) do(method, path string, body any, auth bool) (int, []byte) {
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
	return resp.StatusCode, raw
}

var uuidRe = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

func (h *sensorHarness) mask(s string) string {
	for _, m := range h.masks {
		s = strings.ReplaceAll(s, m.from, m.to)
	}
	return uuidRe.ReplaceAllString(s, "<uuid>")
}
