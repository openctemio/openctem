package routes

// Content delivery to sensors (research/139): the desired set with ETag and
// 304, packs by digest, file index and files, over the real v2 route
// registration against a migrated database; tenant isolation and
// revocation; and the traffic of 3 sensors over 2 runs before (each sensor
// downloads every new version in full) and after (held digests never
// fetched again, new versions by changed files only).

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/sensor"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

type contentHarness struct {
	t       *testing.T
	db      *sql.DB
	srv     *httptest.Server
	sensors *sensor.SensorService
	packs   *contentpackapp.Service
	// platform holds the platform's packs and channels; repo the sensors.
	platform *contentpackapp.PlatformService
	repo     *postgres.SensorRepository
	bytes    atomic.Int64 // response body bytes served on content routes
}

func newContentHarness(t *testing.T) *contentHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping content delivery test")
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
	ih := handler.NewIngestHandler(ingestSvc, sensorSvc, log)
	ctl := handler.NewSensorControlV2Handler(ih, nil, nil, nil, log)
	signer, _ := contentpack.NewSigner(bytes.Repeat([]byte{7}, 32))
	packs := contentpackapp.NewService(postgres.NewContentPackRepository(db), storage.NewLocalStorage(t.TempDir()), signer, nil, log)
	platform := contentpackapp.NewPlatformService(postgres.NewPlatformContentPackRepository(db), storage.NewLocalStorage(t.TempDir()), signer, log)
	ctl.SetContent(handler.NewSensorContentV2Handler(contentpackapp.NewDelivery(packs, platform), log))
	receiver := ingest.NewV2Receiver(postgres.NewIngestReportRepository(db), postgres.NewIngestJobRepository(db),
		postgres.NewIngestJobRepository(db), postgres.NewCommandRepository(db), protov2.DefaultLimits(), 100, log)
	results := handler.NewSensorResultsV2Handler(receiver, sensorSvc, log)
	router := infrahttp.NewChiRouter()
	registerSensorV2Routes(router, results, ctl, nil, log)
	h := &contentHarness{t: t, db: sqldb, sensors: sensorSvc, packs: packs, platform: platform, repo: sensorRepo}
	inner := router.(interface{ Handler() http.Handler }).Handler()
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cw := &countingWriter{ResponseWriter: w}
		inner.ServeHTTP(cw, r)
		if strings.Contains(r.URL.Path, protov2.ContentPath) {
			h.bytes.Add(cw.n)
		}
	}))
	t.Cleanup(h.srv.Close)
	return h
}

type countingWriter struct {
	http.ResponseWriter
	n int64
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

func (h *contentHarness) tenant() string {
	h.t.Helper()
	id := shared.NewID().String()
	if _, err := h.db.ExecContext(context.Background(), `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id, "content-"+id); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM content_packs WHERE tenant_id = $1`, id)
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM content_pack_blobs WHERE tenant_id = $1`, id)
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM sensors WHERE tenant_id = $1`, id)
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id)
	})
	return id
}

func (h *contentHarness) sensorKey(tenantID string) string {
	h.t.Helper()
	out, err := h.sensors.CreateSensor(context.Background(), sensor.CreateSensorInput{TenantID: tenantID, Name: "s-" + shared.NewID().String()[:8],
		Type: "worker", Capabilities: []string{"dast"}, ExecutionMode: "daemon"})
	if err != nil {
		h.t.Fatal(err)
	}
	return out.APIKey
}

func wordlist(files map[string]string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		_ = tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(files[n]))})
		_, _ = tw.Write([]byte(files[n]))
	}
	_ = tw.Close()
	return buf.Bytes()
}

func (h *contentHarness) upload(tenantID, version string, files map[string]string) *contentpack.Pack {
	h.t.Helper()
	p, err := h.packs.Upload(context.Background(), contentpackapp.UploadInput{TenantID: tenantID, Name: "words", Version: version,
		Kind: "wordlist", Archive: bytes.NewReader(wordlist(files))}, auditapp.AuditContext{})
	if err != nil {
		h.t.Fatalf("upload: %v", err)
	}
	return p
}

func (h *contentHarness) get(key, path string, hdr ...string) (*http.Response, []byte) {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+protov2.PathPrefix+protov2.ContentPath+path, nil)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("User-Agent", "openctem-sdk-go/0.9.0 (openctemio-sensor/0.5.0)")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func words(n int, changed map[int]bool) map[string]string {
	out := map[string]string{}
	for i := 0; i < n; i++ {
		var b strings.Builder
		for j := 0; j < 200; j++ {
			fmt.Fprintf(&b, "path-%d-%d\n", i, j)
		}
		if changed[i] {
			b.WriteString("changed-entry\n")
		}
		out[fmt.Sprintf("lists/list-%03d.txt", i)] = b.String()
	}
	return out
}

func TestSensorContentV2_DesiredPacksIndexFilesAndIsolation(t *testing.T) {
	h := newContentHarness(t)
	a, b := h.tenant(), h.tenant()
	keyA, keyB := h.sensorKey(a), h.sensorKey(b)
	p := h.upload(a, "1.0.0", words(5, nil))

	resp, raw := h.get(keyA, "/desired")
	if resp.StatusCode != 200 {
		t.Fatalf("desired %d %s", resp.StatusCode, raw)
	}
	var doc contentpackapp.Desired
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range doc.Packs {
		if d.Digest == p.Digest && d.Scope == "tenant" && len(d.Signature) > 0 && d.Size == p.SizeBytes {
			found = true
		}
	}
	if !found {
		t.Fatalf("tenant pack not desired: %s", raw)
	}
	etag := resp.Header.Get("ETag")
	if resp, raw := h.get(keyA, "/desired", "If-None-Match", etag); resp.StatusCode != http.StatusNotModified || len(raw) != 0 {
		t.Fatalf("unchanged desired: %d %d bytes", resp.StatusCode, len(raw))
	}

	resp, arc := h.get(keyA, "/packs/"+p.Digest)
	sum := sha256.Sum256(arc)
	if resp.StatusCode != 200 || "sha256:"+hex.EncodeToString(sum[:]) != p.Digest || !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("pack %d", resp.StatusCode)
	}
	if resp, _ := h.get(keyA, "/packs/"+p.Digest, "If-None-Match", `"`+p.Digest+`"`); resp.StatusCode != http.StatusNotModified {
		t.Fatalf("held pack re-sent: %d", resp.StatusCode)
	}
	_, rawIdx := h.get(keyA, "/packs/"+p.Digest+"/index")
	var idx []contentpackapp.IndexEntry
	if err := json.Unmarshal(rawIdx, &idx); err != nil || len(idx) != 5 {
		t.Fatalf("index %s %v", rawIdx, err)
	}
	resp, f := h.get(keyA, "/packs/"+p.Digest+"/files/"+idx[2].SHA256)
	fs := sha256.Sum256(f)
	if resp.StatusCode != 200 || hex.EncodeToString(fs[:]) != idx[2].SHA256 {
		t.Fatalf("file %d", resp.StatusCode)
	}

	// SECURITY: another organization's sensor sees none of it.
	_, rawB := h.get(keyB, "/desired")
	if strings.Contains(string(rawB), p.Digest) {
		t.Fatal("another organization's pack in the desired set")
	}
	for _, path := range []string{"/packs/" + p.Digest, "/packs/" + p.Digest + "/index", "/packs/" + p.Digest + "/files/" + idx[2].SHA256} {
		if resp, raw := h.get(keyB, path); resp.StatusCode != http.StatusNotFound || !strings.Contains(string(raw), "content-not-found") {
			t.Errorf("%s from another organization: %d %s", path, resp.StatusCode, raw)
		}
	}
	// Unknown file or malformed values.
	for _, path := range []string{"/packs/" + p.Digest + "/files/" + strings.Repeat("0", 64), "/packs/" + p.Digest + "/files/../../x", "/packs/sha256:zz"} {
		if resp, _ := h.get(keyA, path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
	// No key, no content.
	if resp, _ := h.get("", "/desired"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated: %d", resp.StatusCode)
	}
}

// Revoking a pack puts it in the revoked list and stops serving it (after
// the short authorization cache of a fresh delivery).
func TestSensorContentV2_Revocation(t *testing.T) {
	h := newContentHarness(t)
	a := h.tenant()
	key := h.sensorKey(a)
	p := h.upload(a, "1.0.0", words(3, nil))
	if _, err := h.packs.Revoke(context.Background(), a, p.ID.String(), "test", auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	_, raw := h.get(key, "/desired")
	var doc contentpackapp.Desired
	_ = json.Unmarshal(raw, &doc)
	for _, d := range doc.Packs {
		if d.Digest == p.Digest {
			t.Fatal("revoked pack still desired")
		}
	}
	// The platform's revoked packs (other tests' too) are in the list as well.
	if !slices.Contains(doc.Revoked, p.Digest) {
		t.Fatalf("revoked list %v", doc.Revoked)
	}
	if resp, _ := h.get(key, "/packs/"+p.Digest); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("revoked pack served: %d", resp.StatusCode)
	}
}

// fakeSensor is the content protocol as the sdk-go cache runs it (the
// platform never imports the sensor runtime): desired with ETag; a held
// digest is never fetched; a new digest by index and the files whose
// sha256 it does not hold.
type fakeSensor struct {
	h     *contentHarness
	key   string
	etag  string
	held  map[string]bool
	files map[string]bool
}

func (s *fakeSensor) sync(t *testing.T) {
	t.Helper()
	resp, raw := s.h.get(s.key, "/desired", "If-None-Match", s.etag)
	if resp.StatusCode == http.StatusNotModified {
		return
	}
	s.etag = resp.Header.Get("ETag")
	var doc contentpackapp.Desired
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range doc.Packs {
		if s.held[p.Digest] {
			continue
		}
		if len(s.files) == 0 {
			s.h.get(s.key, "/packs/"+p.Digest)
		}
		_, rawIdx := s.h.get(s.key, "/packs/"+p.Digest+"/index")
		var idx []contentpackapp.IndexEntry
		_ = json.Unmarshal(rawIdx, &idx)
		for _, e := range idx {
			if !s.files[e.SHA256] && len(s.files) > 0 {
				s.h.get(s.key, "/packs/"+p.Digest+"/files/"+e.SHA256)
			}
		}
		for _, e := range idx {
			s.files[e.SHA256] = true
		}
		s.held[p.Digest] = true
	}
}

// Traffic of 3 sensors over 2 runs; the second run comes after a new
// version with 2 of 40 files changed. "Before" is what sensors fetching
// content themselves download: every sensor, the whole archive of every
// new version, on every run that checks.
func TestSensorContentV2_TrafficThreeSensorsTwoRuns(t *testing.T) {
	h := newContentHarness(t)
	a := h.tenant()
	sensors := make([]*fakeSensor, 3)
	for i := range sensors {
		sensors[i] = &fakeSensor{h: h, key: h.sensorKey(a), held: map[string]bool{}, files: map[string]bool{}}
	}
	v1 := h.upload(a, "1.0.0", words(40, nil))
	before := int64(0)

	// Run 1: each sensor syncs before its scan, and again at the next check.
	for _, s := range sensors {
		s.sync(t)
		s.sync(t)
	}
	before += 3 * v1.SizeBytes // each sensor downloads v1 once (it then checks a version string)
	run1 := h.bytes.Load()

	// A new version: 2 of 40 files changed; the old one is revoked.
	v2 := h.upload(a, "1.1.0", words(40, map[int]bool{3: true, 17: true}))
	if _, err := h.packs.Revoke(context.Background(), a, v1.ID.String(), "superseded", auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(11 * time.Second) // the delivery's authorization cache (desiredTTL)
	for _, s := range sensors {
		s.sync(t)
		s.sync(t)
	}
	before += 3 * v2.SizeBytes
	run2 := h.bytes.Load() - run1
	after := h.bytes.Load()
	t.Logf("TRAFFIC 3 sensors x 2 runs: archive v1=%d B, v2=%d B; before (each sensor downloads each version in full)=%d B; after=%d B (run 1 %d B, run 2 %d B); saved %.1f%% overall, %.1f%% on the new version",
		v1.SizeBytes, v2.SizeBytes, before, after, run1, run2, 100*(1-float64(after)/float64(before)), 100*(1-float64(run2)/float64(3*v2.SizeBytes)))
	if run2 >= 3*v2.SizeBytes/4 {
		t.Fatalf("the new version cost %d B, close to %d B of full downloads", run2, 3*v2.SizeBytes)
	}
}

// sharedSensorKey creates a shared sensor (scope instance, no tenant).
func (h *contentHarness) sharedSensorKey() string {
	h.t.Helper()
	key, err := sensorkey.New(sensorkey.PrefixSensorKey)
	if err != nil {
		h.t.Fatal(err)
	}
	s, err := sensordom.NewSensor(shared.NewID(), "shared-"+shared.NewID().String()[:8], sensordom.SensorTypeWorker, "", nil, sensordom.ExecutionModeDaemon)
	if err != nil {
		h.t.Fatal(err)
	}
	s.Scope, s.TenantID = sensordom.ScopeInstance, nil
	s.SetAPIKey(crypto.HashTokenPeppered(key, ""), sensorkey.DisplayPrefix(key))
	if err := h.repo.Create(context.Background(), s); err != nil {
		h.t.Fatalf("create shared sensor: %v", err)
	}
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM sensors WHERE id = $1`, s.ID.String())
	})
	return key
}

// A shared sensor reads the platform's stable packs, one copy for every
// organization, and nothing else: an organization's pack is
// content-not-found for it by digest, in the index and by file, and is not in
// its desired set. The platform pack is the same bytes for it and for an
// organization's sensor.
func TestSensorContentV2_SharedSensorReadsPlatformPacksOnly(t *testing.T) {
	h := newContentHarness(t)
	a := h.tenant()
	keyA, keyShared := h.sensorKey(a), h.sharedSensorKey()
	own := h.upload(a, "1.0.0", words(3, nil))
	ctx := context.Background()
	plat, err := h.platform.Upload(ctx, contentpackapp.PlatformInput{Name: "wordlists-" + shared.NewID().String()[:8], Version: "1", Kind: "wordlist"},
		bytes.NewReader(wordlist(words(4, nil))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.platform.MoveChannel(ctx, plat.ID.String(), contentpack.ChannelStable); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM platform_content_channels WHERE pack_id = $1`, plat.ID.String())
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM platform_content_packs WHERE id = $1`, plat.ID.String())
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM platform_content_pack_blobs WHERE digest = $1`, plat.Digest)
	})

	resp, raw := h.get(keyShared, "/desired")
	if resp.StatusCode != 200 {
		t.Fatalf("desired %d %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), plat.Digest) || strings.Contains(string(raw), own.Digest) {
		t.Fatalf("shared sensor's desired set: %s", raw)
	}
	var doc contentpackapp.Desired
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range doc.Packs {
		if p.Scope != "platform" {
			t.Errorf("a %s pack in a shared sensor's desired set", p.Scope)
		}
	}
	// The organization's own sensor still gets both.
	_, rawA := h.get(keyA, "/desired")
	if !strings.Contains(string(rawA), plat.Digest) || !strings.Contains(string(rawA), own.Digest) {
		t.Fatalf("organization sensor's desired set: %s", rawA)
	}
	// Platform pack: served to both, the same bytes.
	r1, b1 := h.get(keyShared, "/packs/"+plat.Digest)
	r2, b2 := h.get(keyA, "/packs/"+plat.Digest)
	if r1.StatusCode != 200 || r2.StatusCode != 200 || !bytes.Equal(b1, b2) {
		t.Fatalf("platform pack: shared %d, organization %d", r1.StatusCode, r2.StatusCode)
	}
	_, rawIdx := h.get(keyA, "/packs/"+own.Digest+"/index")
	var idx []contentpackapp.IndexEntry
	if err := json.Unmarshal(rawIdx, &idx); err != nil || len(idx) == 0 {
		t.Fatalf("index %s %v", rawIdx, err)
	}
	// SECURITY: an organization's pack is not served to a shared sensor.
	for _, path := range []string{"/packs/" + own.Digest, "/packs/" + own.Digest + "/index", "/packs/" + own.Digest + "/files/" + idx[0].SHA256} {
		if resp, raw := h.get(keyShared, path); resp.StatusCode != http.StatusNotFound || !strings.Contains(string(raw), "content-not-found") {
			t.Errorf("%s for a shared sensor: %d %s", path, resp.StatusCode, raw)
		}
	}
}
