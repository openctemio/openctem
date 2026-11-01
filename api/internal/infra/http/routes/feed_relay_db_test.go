package routes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/feedrelay"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/sensor"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	dom "github.com/openctemio/openctem/api/pkg/domain/feedrelay"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

type relaySigner struct{}

func (relaySigner) SignJob(context.Context, jobsign.Statement) (json.RawMessage, error) {
	return json.RawMessage(`{"payloadType":"application/vnd.openctem.job.v1+json"}`), nil
}

type relayHeadFeed struct{}

func (relayHeadFeed) Name() string            { return dom.FeedVulnFeed }
func (relayHeadFeed) Origins() []string       { return []string{"https://feeds.example/latest/download"} }
func (relayHeadFeed) Interval() time.Duration { return 20 * time.Minute }
func (relayHeadFeed) Head() feedrelay.Plan {
	return feedrelay.Plan{Phase: dom.PhaseHead, Files: []dom.File{{Name: "keyset.dsse.json", MaxBytes: 1024}}}
}
func (relayHeadFeed) Plan(context.Context, string) (feedrelay.Plan, error) {
	return feedrelay.Plan{}, nil
}
func (relayHeadFeed) Import(context.Context, string) error { return nil }

// TestFeedRelayRoutes: only the designated platform sensor reaches the feed
// relay routes; an organization's sensor and another platform sensor get
// 403; an upload whose bytes do not match is refused and never reaches the
// spool.
func TestFeedRelayRoutes(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping feed relay route test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	ctx := context.Background()
	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	_, _ = sqldb.ExecContext(ctx, `DELETE FROM platform_settings WHERE key IN ('egress.mode.feeds', 'feed_relay.sensor')`)
	t.Cleanup(func() {
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM platform_settings WHERE key IN ('egress.mode.feeds', 'feed_relay.sensor')`)
	})

	sensorRepo := postgres.NewSensorRepository(db)
	sensorSvc := sensor.NewSensorService(sensorRepo, nil, log)
	sensorSvc.SetAPIKeyRepository(postgres.NewSensorAPIKeyRepository(db))
	ingestSvc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		sensorRepo, postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), log)
	ctl := handler.NewSensorControlV2Handler(handler.NewIngestHandler(ingestSvc, sensorSvc, log), nil, nil, nil, log)
	spool := t.TempDir()
	svc := feedrelay.NewService(feedrelay.Config{Spool: spool, Signer: relaySigner{}}, postgres.NewFeedRelayRoundRepository(db),
		sensorRepo, postgres.NewPlatformSettingRepository(db), nil, log)
	svc.AddFeed(relayHeadFeed{})
	ctl.SetFeedRelay(handler.NewFeedRelayHandler(svc, log))
	receiver := ingest.NewV2Receiver(postgres.NewIngestReportRepository(db), postgres.NewIngestJobRepository(db),
		postgres.NewIngestJobRepository(db), postgres.NewCommandRepository(db), protov2.DefaultLimits(), 100, log)
	receiver.SetPayloadSealer(testSegmentSealer(t))
	router := infrahttp.NewChiRouter()
	registerSensorV2Routes(router, handler.NewSensorResultsV2Handler(receiver, sensorSvc, log), ctl, nil, log)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	platformSensor := func() (string, *sensordom.Sensor) {
		key, err := sensorkey.New(sensorkey.PrefixSensorKey)
		if err != nil {
			t.Fatal(err)
		}
		s, err := sensordom.NewSensor(shared.NewID(), "relay-"+shared.NewID().String()[:8], sensordom.SensorTypeWorker, "", []string{feedrelay.Capability}, sensordom.ExecutionModeDaemon)
		if err != nil {
			t.Fatal(err)
		}
		s.Scope, s.TenantID = sensordom.ScopeInstance, nil
		s.SetAPIKey(crypto.HashTokenPeppered(key, ""), sensorkey.DisplayPrefix(key))
		if err := sensorRepo.Create(ctx, s); err != nil {
			t.Fatalf("create platform sensor: %v", err)
		}
		t.Cleanup(func() {
			_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM sensors WHERE id = $1`, s.ID.String())
		})
		return key, s
	}
	relayKey, relay := platformSensor()
	otherKey, _ := platformSensor()
	tenantID := shared.NewID().String()
	if _, err := sqldb.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenantID, "relay-"+tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM sensors WHERE tenant_id = $1`, tenantID)
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})
	org, err := sensorSvc.CreateSensor(ctx, sensor.CreateSensorInput{TenantID: tenantID, Name: "org-relay", Type: "worker",
		Capabilities: []string{feedrelay.Capability}, ExecutionMode: "daemon"})
	if err != nil {
		t.Fatal(err)
	}

	do := func(key, method, path string, body []byte, hdr ...string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, method, srv.URL+protov2.PathPrefix+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("User-Agent", "openctem-sdk-go/0.46.0 (openctemio-sensor/0.34.0)")
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}

	// Direct mode: nobody relays.
	if code, _ := do(relayKey, http.MethodGet, "/feed-relay/next", nil); code != http.StatusForbidden {
		t.Fatalf("direct mode: %d", code)
	}
	actor, _ := admin.NewAdminUser("root@example.com", "Root", admin.AdminRoleSuperAdmin, nil)
	if _, err := svc.Update(ctx, actor, feedrelay.ModeRelay, org.Sensor.ID.String(), 0, "", ""); err == nil {
		t.Fatal("an organization's sensor was designated")
	}
	if _, err := svc.Update(ctx, actor, feedrelay.ModeRelay, relay.ID.String(), 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]string{"organization sensor": org.APIKey, "other platform sensor": otherKey} {
		if code, _ := do(key, http.MethodGet, "/feed-relay/next", nil); code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, code)
		}
	}
	code, raw := do(relayKey, http.MethodGet, "/feed-relay/next", nil)
	if code != http.StatusOK {
		t.Fatalf("designated: %d %s", code, raw)
	}
	var next feedrelay.Next
	if err := json.Unmarshal(raw, &next); err != nil || next.ID == "" {
		t.Fatalf("next %s", raw)
	}
	contentDigest := func(b []byte) string {
		sum := sha256.Sum256(b)
		return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	}
	put := "/feed-relay/" + next.ID + "/files/keyset.dsse.json"
	if code, _ := do(otherKey, http.MethodPut, put, []byte("K"), "Content-Digest", contentDigest([]byte("K"))); code != http.StatusForbidden {
		t.Fatalf("another sensor's upload: %d", code)
	}
	if code, _ := do(relayKey, http.MethodPut, put, []byte("K"), "Content-Digest", contentDigest([]byte("X"))); code == http.StatusNoContent {
		t.Fatal("an upload whose bytes do not match its digest was accepted")
	}
	if _, err := os.Stat(filepath.Join(spool, dom.FeedVulnFeed, "keyset.dsse.json")); err == nil {
		t.Fatal("a refused upload reached the spool")
	}
	if code, raw := do(relayKey, http.MethodPut, put, []byte("K"), "Content-Digest", contentDigest([]byte("K"))); code != http.StatusNoContent {
		t.Fatalf("upload: %d %s", code, raw)
	}
	if b, _ := os.ReadFile(filepath.Join(spool, dom.FeedVulnFeed, "keyset.dsse.json")); string(b) != "K" {
		t.Fatalf("spool %q", b)
	}
	rep, _ := json.Marshal(dom.Report{Files: []dom.Outcome{{Name: "keyset.dsse.json", Status: "ok"}}})
	if code, _ := do(relayKey, http.MethodPost, "/feed-relay/"+next.ID+"/done", rep); code != http.StatusNoContent {
		t.Fatalf("done: %d", code)
	}
	if code, _ := do(relayKey, http.MethodPost, "/feed-relay/"+next.ID+"/done", rep); code != http.StatusNotFound {
		t.Fatalf("done twice: %d", code)
	}
}
