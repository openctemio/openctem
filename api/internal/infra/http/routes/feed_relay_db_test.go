package routes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// relayHeadFeed asks for one file and is ready once its working directory
// holds it; imported records what it read.
type relayHeadFeed struct{ imported *string }

func (relayHeadFeed) Name() string            { return dom.FeedVulnFeed }
func (relayHeadFeed) Origins() []string       { return []string{"https://feeds.example/latest/download"} }
func (relayHeadFeed) Interval() time.Duration { return 20 * time.Minute }
func (relayHeadFeed) Head() feedrelay.Plan {
	return feedrelay.Plan{Phase: dom.PhaseHead, Files: []dom.File{{Name: "keyset.dsse.json", MaxBytes: 1024}}}
}
func (relayHeadFeed) Plan(_ context.Context, dir string) (feedrelay.Plan, error) {
	if _, err := os.Stat(filepath.Join(dir, "keyset.dsse.json")); err != nil {
		return feedrelay.Plan{}, err
	}
	return feedrelay.Plan{Ready: true}, nil
}
func (f relayHeadFeed) Import(_ context.Context, dir string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "keyset.dsse.json"))
	*f.imported = string(b)
	return []string{"keyset.dsse.json"}, err
}
func (relayHeadFeed) Freshness(context.Context) (feedrelay.Freshness, error) {
	return feedrelay.Freshness{}, nil
}

// TestFeedRelayRoutes: only a designated platform sensor is offered rounds
// and may upload; an organization's sensor gets 403 and an eligible
// platform sensor that is not designated gets 204 with a long Retry-After;
// an upload whose bytes do not match is refused and never reaches the spool.
// Two API instances share the database: the upload goes through instance A,
// the plan and import run on instance B (the controller's lease holder) from
// its own working directory.
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
	cleanup := func() {
		for _, q := range relayCleanup {
			_, _ = sqldb.ExecContext(context.Background(), q)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	sensorRepo := postgres.NewSensorRepository(db)
	sensorSvc := sensor.NewSensorService(sensorRepo, nil, log)
	sensorSvc.SetAPIKeyRepository(postgres.NewSensorAPIKeyRepository(db))
	ingestSvc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		sensorRepo, postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), log)
	ctl := handler.NewSensorControlV2Handler(handler.NewIngestHandler(ingestSvc, sensorSvc, log), nil, nil, nil, log)
	repo := postgres.NewFeedRelayRoundRepository(db)
	var importedA, importedB string
	dirA, dirB := t.TempDir(), t.TempDir()
	svc := feedrelay.NewService(feedrelay.Config{WorkDir: dirA, Signer: relaySigner{}}, repo, repo,
		sensorRepo, postgres.NewPlatformSettingRepository(db), nil, log)
	svc.AddFeed(relayHeadFeed{imported: &importedA})
	svcB := feedrelay.NewService(feedrelay.Config{WorkDir: dirB, Signer: relaySigner{}}, repo, repo,
		sensorRepo, postgres.NewPlatformSettingRepository(db), nil, log)
	svcB.AddFeed(relayHeadFeed{imported: &importedB})
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
		s, err := sensordom.NewSensor(shared.NewID(), "relay-"+shared.NewID().String()[24:], sensordom.SensorTypeWorker, "", []string{feedrelay.Capability}, sensordom.ExecutionModeDaemon)
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

	var doH func(key, method, path string, body []byte, hdr ...string) (int, []byte, http.Header)
	do := func(key, method, path string, body []byte, hdr ...string) (int, []byte) {
		code, b, _ := doH(key, method, path, body, hdr...)
		return code, b
	}
	doH = func(key, method, path string, body []byte, hdr ...string) (int, []byte, http.Header) {
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
		return resp.StatusCode, b, resp.Header
	}

	// Direct mode: nobody relays; an eligible sensor is told to come back
	// much later.
	if code, _, h := doH(relayKey, http.MethodGet, "/feed-relay/next", nil); code != http.StatusNoContent || h.Get("Retry-After") != "600" {
		t.Fatalf("direct mode: %d %q", code, h.Get("Retry-After"))
	}
	actor, _ := admin.NewAdminUser("root@example.com", "Root", admin.AdminRoleSuperAdmin, nil)
	if _, err := svc.Update(ctx, actor, feedrelay.ModeRelay, []string{org.Sensor.ID.String()}, 0, "", ""); err == nil {
		t.Fatal("an organization's sensor was designated")
	}
	if _, err := svc.Update(ctx, actor, feedrelay.ModeRelay, []string{relay.ID.String()}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svcB.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if code, _ := do(org.APIKey, http.MethodGet, "/feed-relay/next", nil); code != http.StatusForbidden {
		t.Errorf("organization sensor: %d, want 403", code)
	}
	if code, _, h := doH(otherKey, http.MethodGet, "/feed-relay/next", nil); code != http.StatusNoContent || h.Get("Retry-After") != "600" {
		t.Errorf("other platform sensor: %d %q, want 204 600", code, h.Get("Retry-After"))
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
	inSpool := func() string {
		var data []byte
		_ = sqldb.QueryRowContext(ctx, `SELECT data FROM feed_relay_files WHERE feed = 'vulnfeed' AND name = 'keyset.dsse.json'`).Scan(&data)
		return string(data)
	}
	put := "/feed-relay/" + next.ID + "/files/keyset.dsse.json"
	for name, key := range map[string]string{"another platform sensor": otherKey, "organization sensor": org.APIKey} {
		if code, _ := do(key, http.MethodPut, put, []byte("K"), "Content-Digest", contentDigest([]byte("K"))); code != http.StatusForbidden {
			t.Fatalf("%s upload: %d", name, code)
		}
	}
	if code, _ := do(relayKey, http.MethodPut, put, []byte("K"), "Content-Digest", contentDigest([]byte("X"))); code == http.StatusNoContent {
		t.Fatal("an upload whose bytes do not match its digest was accepted")
	}
	if got := inSpool(); got != "" {
		t.Fatalf("a refused upload reached the spool: %q", got)
	}
	if code, raw := do(relayKey, http.MethodPut, put, []byte("K"), "Content-Digest", contentDigest([]byte("K"))); code != http.StatusNoContent {
		t.Fatalf("upload: %d %s", code, raw)
	}
	// One upload per name per round: other bytes are refused, the same bytes
	// again (a retry) are accepted and not counted twice.
	if code, _ := do(relayKey, http.MethodPut, put, []byte("Z"), "Content-Digest", contentDigest([]byte("Z"))); code == http.StatusNoContent {
		t.Fatal("a second upload with other bytes was accepted")
	}
	if code, _ := do(relayKey, http.MethodPut, put, []byte("K"), "Content-Digest", contentDigest([]byte("K"))); code != http.StatusNoContent {
		t.Fatalf("retried upload: %d", code)
	}
	if got := inSpool(); got != "K" {
		t.Fatalf("spool %q", got)
	}
	var delivered int64
	_ = sqldb.QueryRowContext(ctx, `SELECT delivered_bytes FROM feed_relay_rounds WHERE id = $1`, next.ID).Scan(&delivered)
	if delivered != 1 {
		t.Fatalf("delivered bytes %d", delivered)
	}
	rep, _ := json.Marshal(dom.Report{Files: []dom.Outcome{{Name: "keyset.dsse.json", Status: "ok"}}})
	if code, _ := do(relayKey, http.MethodPost, "/feed-relay/"+next.ID+"/done", rep); code != http.StatusNoContent {
		t.Fatalf("done: %d", code)
	}
	if code, _ := do(relayKey, http.MethodPost, "/feed-relay/"+next.ID+"/done", rep); code != http.StatusNotFound {
		t.Fatalf("done twice: %d", code)
	}
	// While the cycle waits for its next plan the relay is told to come
	// back soon.
	if code, _, h := doH(relayKey, http.MethodGet, "/feed-relay/next", nil); code != http.StatusNoContent || h.Get("Retry-After") != "15" {
		t.Fatalf("in cycle: %d %q", code, h.Get("Retry-After"))
	}
	// Instance B (the lease holder, its own directory) plans and imports.
	if _, err := svcB.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if importedB != "K" || importedA != "" {
		t.Fatalf("imported on B %q, on A %q", importedB, importedA)
	}
	if entries, _ := os.ReadDir(dirA); len(entries) != 0 {
		t.Fatalf("instance A wrote its working directory: %d entries", len(entries))
	}
	last, err := repo.Latest(ctx, dom.FeedVulnFeed)
	if err != nil || last.Phase != dom.PhaseImported {
		t.Fatalf("latest %+v %v", last, err)
	}
	st, err := svc.Status(ctx)
	if err != nil || len(st.Sensors) != 1 || st.Sensors[0].BytesToday != 1 || st.Feeds[0].StaleReason != "" {
		t.Fatalf("status %+v %v", st, err)
	}
}

// relayCleanup empties the feed relay state of the scratch test database.
var relayCleanup = []string{
	"DELETE FROM platform_settings WHERE key = 'egress.mode.feeds'",
	"DELETE FROM feed_relay_rounds",
	"DELETE FROM feed_relay_files",
}

// TestFeedRelaySpoolStore: the Postgres spool enforces the round's budget
// and the spool quota (recorded on the round), one upload per name per
// round, and a claim is taken over only when stale with nothing uploaded or
// held by a sensor no longer designated.
func TestFeedRelaySpoolStore(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping feed relay spool test")
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
	cleanup := func() {
		for _, q := range relayCleanup[1:] {
			_, _ = sqldb.ExecContext(context.Background(), q)
		}
	}
	cleanup()
	t.Cleanup(cleanup)
	db := &postgres.DB{DB: sqldb}
	repo := postgres.NewFeedRelayRoundRepository(db)
	sensorRepo := postgres.NewSensorRepository(db)
	mk := func() shared.ID {
		s, err := sensordom.NewSensor(shared.NewID(), "spool-"+shared.NewID().String()[24:], sensordom.SensorTypeWorker, "", nil, sensordom.ExecutionModeDaemon)
		if err != nil {
			t.Fatal(err)
		}
		s.Scope, s.TenantID = sensordom.ScopeInstance, nil
		key, err := sensorkey.New(sensorkey.PrefixSensorKey)
		if err != nil {
			t.Fatal(err)
		}
		s.SetAPIKey(crypto.HashTokenPeppered(key, ""), sensorkey.DisplayPrefix(key))
		if err := sensorRepo.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = sqldb.ExecContext(context.Background(), "DELETE FROM sensors WHERE id = $1", s.ID.String())
		})
		return s.ID
	}
	a, b := mk(), mk()
	now := time.Now().UTC().Truncate(time.Millisecond)
	rd := &dom.Round{ID: shared.NewID(), Feed: dom.FeedVulnFeed, Phase: dom.PhaseHead, Status: dom.StatusOpen, Origins: []string{"https://feeds.example"},
		Files: []dom.File{{Name: "a", MaxBytes: 10}, {Name: "b", MaxBytes: 10}}, CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute)}
	if err := repo.Create(ctx, rd); err != nil {
		t.Fatal(err)
	}
	both := []shared.ID{a, b}
	claim := func(who shared.ID, at time.Time, designated []shared.ID) *dom.Round {
		t.Helper()
		got, err := repo.Claim(ctx, dom.ClaimRule{SensorID: who, Designated: designated, StaleBefore: at.Add(-10 * time.Minute), Now: at})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := claim(a, now, both); got == nil || got.SensorID == nil || *got.SensorID != a {
		t.Fatalf("claim by a: %+v", got)
	}
	if got := claim(b, now.Add(time.Minute), both); got != nil {
		t.Fatal("a fresh claim was taken over")
	}
	store := func(who shared.ID, name string, data []byte, budget, quota int64) error {
		sum := sha256.Sum256(data)
		return repo.Store(ctx, dom.Upload{RoundID: rd.ID, SensorID: who, Feed: dom.FeedVulnFeed, Name: name,
			SHA256: fmt.Sprintf("%x", sum[:]), Data: data, RoundBudget: budget, SpoolQuota: quota, Now: now.Add(time.Minute)})
	}
	if err := store(b, "a", []byte("1"), 100, 100); !errors.Is(err, dom.ErrRoundClosed) {
		t.Fatalf("store by a non-claimer: %v", err)
	}
	if err := store(a, "a", []byte("1234"), 5, 100); err != nil {
		t.Fatal(err)
	}
	if err := store(a, "a", []byte("9999"), 5, 100); !errors.Is(err, dom.ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := store(a, "b", []byte("12"), 5, 100); !errors.Is(err, dom.ErrRoundFull) {
		t.Fatalf("round budget: %v", err)
	}
	if err := store(a, "b", []byte("12"), 100, 5); !errors.Is(err, dom.ErrSpoolFull) {
		t.Fatalf("spool quota: %v", err)
	}
	var code string
	_ = sqldb.QueryRowContext(ctx, "SELECT error_code FROM feed_relay_rounds WHERE id = $1", rd.ID.String()).Scan(&code)
	if code != dom.CodeSpoolFull {
		t.Fatalf("quota not recorded: %q", code)
	}
	// Stale, but a file was uploaded: the claim holds; once a is no longer
	// designated, b takes it.
	if got := claim(b, now.Add(11*time.Minute), both); got != nil {
		t.Fatal("a claim with uploads was taken over")
	}
	if got := claim(b, now.Add(11*time.Minute), []shared.ID{b}); got == nil || *got.SensorID != b {
		t.Fatalf("claim of an undesignated sensor: %+v", got)
	}
	files, err := repo.List(ctx, dom.FeedVulnFeed)
	if err != nil || len(files) != 1 || files[0].Name != "a" || files[0].Size != 4 {
		t.Fatalf("list %+v %v", files, err)
	}
	if n, err := repo.Prune(ctx, dom.FeedVulnFeed, []string{"zzz"}); err != nil || n != 1 {
		t.Fatalf("prune %d %v", n, err)
	}
}
