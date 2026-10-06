package routes

// RFC-026 WP-A5: sensor protocol v2 results over the real route registration
// (registerSensorV2Routes: authenticator, edge chain, handlers) against a
// migrated database. Every client-visible row of RFC-026 §3.8 is reached
// here; the route isolation of RFC-023 C-2 is asserted in both directions.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

type v2Harness struct {
	t        *testing.T
	db       *sql.DB
	srv      *httptest.Server
	key      string
	sensorID string
	tenantID string
	reports  *postgres.IngestReportRepository
	jobs     *postgres.IngestJobRepository
	proc     *ingest.V2JobProcessor
	ingest   *ingest.Service
	sensors  *app.SensorService
	jwtToken string
}

type v2HarnessOpts struct {
	limits        protov2.Limits
	maxPending    int
	tenantLimiter *middleware.TelemetryRateLimiter
	control       *handler.SensorControlV2Handler
	// ciKeys, when set, is the "OIDC required for CI" policy.
	ciKeys handler.CIRunnerKeyPolicy
}

func newV2Harness(t *testing.T, opts v2HarnessOpts) *v2Harness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping protocol v2 route test")
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
	ingestSvc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		sensorRepo, postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), log)
	h := &v2Harness{t: t, db: sqldb, reports: postgres.NewIngestReportRepository(db), jobs: postgres.NewIngestJobRepository(db), sensors: sensorSvc, ingest: ingestSvc}
	parked := parkedJobs{h.jobs}
	limits := opts.limits
	if limits.MaxContentBytes == 0 {
		limits = protov2.DefaultLimits()
	}
	receiver := ingest.NewV2Receiver(h.reports, parked, h.jobs, postgres.NewCommandRepository(db), limits, opts.maxPending, log)
	h.proc = ingest.NewV2JobProcessor(ingestSvc, h.reports, h.jobs, limits, ingest.DefaultBlindingGuard(), log)

	// A user route behind the real JWT authenticator, for route isolation.
	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "v2-route-test-secret-0123456789abcdef", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	userAuth := middleware.UnifiedAuth(middleware.UnifiedAuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen, Logger: log})
	tok, _, err := gen.GenerateAccessToken(shared.NewID().String(), shared.NewID().String(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	h.jwtToken = tok

	router := infrahttp.NewChiRouter()
	resultsHandler := handler.NewSensorResultsV2Handler(receiver, sensorSvc, log)
	if opts.ciKeys != nil {
		resultsHandler.SetCIRunnerKeyPolicy(opts.ciKeys)
	}
	registerSensorV2Routes(router, resultsHandler, opts.control, opts.tenantLimiter, log)
	router.Group("/api/v1/probe", func(r Router) {
		r.GET("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) })
	}, userAuth)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)

	ctx := context.Background()
	tenantID := shared.NewID()
	if _, err := sqldb.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`,
		tenantID.String(), "v2-routes-"+tenantID.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		// Reports first (their jobs cascade), so no queue row outlives the
		// test even if the tenant delete fails.
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM ingest_reports WHERE tenant_id = $1`, tenantID.String())
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID.String())
	})
	out, err := sensorSvc.CreateSensor(ctx, app.CreateSensorInput{TenantID: tenantID.String(), Name: "v2-sensor",
		Type: "worker", Capabilities: []string{"sast"}, Tools: []string{"semgrep"}, ExecutionMode: "daemon"})
	if err != nil {
		t.Fatalf("create sensor: %v", err)
	}
	h.key, h.sensorID, h.tenantID = out.APIKey, out.Sensor.ID.String(), tenantID.String()
	return h
}

// parkedJobs stores v2 jobs a day in the future, so the ingest worker's
// ClaimBatch — and the v1 queue tests that call it in a parallel package —
// never see them. The tests run the processor on their own jobs directly.
type parkedJobs struct{ *postgres.IngestJobRepository }

func (p parkedJobs) EnqueueV2(ctx context.Context, job *ingestjob.Job) (*ingestjob.Job, bool, error) {
	job.DelayUntil(time.Now().Add(24 * time.Hour))
	return p.IngestJobRepository.EnqueueV2(ctx, job)
}

func v2Segment(tool, version string, rules ...string) []byte {
	var f []string
	for _, r := range rules {
		f = append(f, fmt.Sprintf(`{"type":"vulnerability","title":"t %s","severity":"high","rule_id":%q,"asset_ref":"repo","location":{"path":"src/%s.go","start_line":3}}`, r, r, r))
	}
	return []byte(fmt.Sprintf(`{"version":%q,"metadata":{"timestamp":"2026-10-01T12:00:00Z","coverage_type":"full","branch":{"name":"main","is_default_branch":true}},`+
		`"tool":{"name":%q},"assets":[{"id":"repo","type":"repository","value":"github.com/acme/v2-routes"}],"findings":[%s]}`,
		version, tool, strings.Join(f, ",")))
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(s[:]) + ":"
}

type reqOpt func(*http.Request)

func (h *v2Harness) do(method, path string, body []byte, opts ...reqOpt) (*http.Response, []byte) {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, rdr)
	req.Header.Set("Authorization", "Bearer "+h.key)
	if body != nil {
		req.Header.Set("Content-Type", protov2.MediaTypeCTIS)
		req.Header.Set(protov2.HeaderContentDigest, digestOf(body))
	}
	for _, o := range opts {
		o(req)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func (h *v2Harness) expect(resp *http.Response, raw []byte, status int, problem string) {
	h.t.Helper()
	if resp.StatusCode != status {
		h.t.Fatalf("status %d, want %d: %s", resp.StatusCode, status, raw)
	}
	if resp.Header.Get(protov2.HeaderProtocol) != "2" {
		h.t.Fatalf("missing %s header", protov2.HeaderProtocol)
	}
	if problem == "" {
		return
	}
	var p protov2.Problem
	if err := json.Unmarshal(raw, &p); err != nil || p.Type != protov2.ProblemTypeBase+problem {
		h.t.Fatalf("problem %q, want %q (%s)", p.Type, problem, raw)
	}
}

func (h *v2Harness) status(raw []byte) protov2.Status {
	h.t.Helper()
	var st protov2.Status
	if err := json.Unmarshal(raw, &st); err != nil {
		h.t.Fatalf("status body: %v %s", err, raw)
	}
	return st
}

// work runs the worker over every job of a report.
func (h *v2Harness) work(reportID string) {
	h.t.Helper()
	ctx := context.Background()
	rep, err := h.reports.Get(ctx, shared.MustIDFromString(h.tenantID), shared.MustIDFromString(h.sensorID), reportID)
	if err != nil {
		h.t.Fatalf("report: %v", err)
	}
	digests, _ := h.jobs.V2SegmentDigests(ctx, rep.ID)
	for seq := range digests {
		job, err := h.jobs.GetV2Segment(ctx, rep.ID, seq)
		if err != nil {
			h.t.Fatal(err)
		}
		if _, err := h.proc.Process(ctx, job); err != nil {
			h.t.Fatalf("process: %v", err)
		}
	}
	if job, err := h.jobs.GetV2Commit(ctx, rep.ID); err == nil {
		if _, err := h.proc.Process(ctx, job); err != nil {
			h.t.Fatalf("process commit: %v", err)
		}
	}
}

func newReportID() string {
	return strings.ToLower(shared.NewID().String())
}

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

func TestSensorV2_WholeReportReplayConflict(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	id := newReportID()
	body := v2Segment("semgrep", "1.0", "a", "b")

	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id, body)
	h.expect(resp, raw, 202, "")
	if resp.Header.Get("Location") != "/api/v2/sensor/results/"+id || resp.Header.Get("Retry-After") != "2" {
		t.Fatalf("headers %v", resp.Header)
	}
	if st := h.status(raw); st.State != protov2.StateQueued || st.Segments.Received != 1 || st.Segments.Expected == nil {
		t.Fatalf("accepted status %+v", st)
	}

	// Identical replay: 200, nothing new stored.
	resp, raw = h.do(http.MethodPut, "/api/v2/sensor/results/"+id, body)
	h.expect(resp, raw, 200, "")
	// Different content under the same id: 409.
	resp, raw = h.do(http.MethodPut, "/api/v2/sensor/results/"+id, v2Segment("semgrep", "1.0", "a"))
	h.expect(resp, raw, 409, "report-conflict")

	h.work(id)
	resp, raw = h.do(http.MethodGet, "/api/v2/sensor/results/"+id, nil)
	h.expect(resp, raw, 200, "")
	st := h.status(raw)
	if st.State != protov2.StateCompleted || st.Accepted.Findings != 2 || st.Accepted.Assets != 1 {
		t.Fatalf("final status %+v", st)
	}
	var jobs int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM ingest_jobs j JOIN ingest_reports r ON r.id = j.ingest_report_id WHERE r.report_id = $1`, id).Scan(&jobs)
	if jobs != 2 { // one segment + the implicit commit
		t.Fatalf("jobs %d", jobs)
	}
}

func TestSensorV2_SegmentedReportAndCommit(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	id := newReportID()
	base := "/api/v2/sensor/results/" + id
	s0, s1 := v2Segment("semgrep", "1.0", "a"), v2Segment("semgrep", "1.0", "b", "c")

	resp, raw := h.do(http.MethodPut, base+"/segments/1", s1) // any order
	h.expect(resp, raw, 202, "")
	if st := h.status(raw); st.State != protov2.StateReceiving {
		t.Fatalf("state %s", st.State)
	}
	resp, raw = h.do(http.MethodPut, base+"/segments/0", s0)
	h.expect(resp, raw, 202, "")
	resp, raw = h.do(http.MethodPut, base+"/segments/0", s0)
	h.expect(resp, raw, 200, "")

	// A segment whose tool or metadata differ does not belong to the report.
	resp, raw = h.do(http.MethodPut, base+"/segments/2",
		bytes.Replace(v2Segment("semgrep", "1.0", "d"), []byte(`"full"`), []byte(`"incremental"`), 1))
	h.expect(resp, raw, 409, "segment-header-mismatch")
	// The same report through the command-bound form is a different binding.
	resp, raw = h.do(http.MethodPut, "/api/v2/sensor/commands/"+newReportID()+"/results/"+id+"/segments/2", s0)
	h.expect(resp, raw, 404, "command-not-found")

	commit := func(n int, digests ...string) (*http.Response, []byte) {
		b, _ := json.Marshal(protov2.CommitRequest{SegmentCount: n, SegmentDigests: digests})
		return h.do(http.MethodPost, base+"/commit", nil, func(r *http.Request) {
			r.Body = io.NopCloser(bytes.NewReader(b))
			r.ContentLength = int64(len(b))
			r.Header.Set("Content-Type", "application/json")
		})
	}
	resp, raw = commit(2, digestOf(s0), digestOf(v2Segment("semgrep", "1.0", "x")))
	h.expect(resp, raw, 409, "segment-set-mismatch")
	resp, raw = commit(3, digestOf(s0), digestOf(s1), digestOf(s1))
	h.expect(resp, raw, 409, "segment-set-mismatch")
	resp, raw = commit(2, digestOf(s0))
	h.expect(resp, raw, 400, "invalid-request")
	resp, raw = commit(2, digestOf(s0), digestOf(s1))
	h.expect(resp, raw, 202, "")
	resp, raw = commit(2, digestOf(s0), digestOf(s1)) // replayed commit
	h.expect(resp, raw, 200, "")
	resp, raw = h.do(http.MethodPut, base+"/segments/2", v2Segment("semgrep", "1.0", "late"))
	h.expect(resp, raw, 409, "report-committed")

	h.work(id)
	resp, raw = h.do(http.MethodGet, base, nil)
	h.expect(resp, raw, 200, "")
	if st := h.status(raw); st.State != protov2.StateCompleted || st.Accepted.Findings != 3 || *st.Segments.Expected != 2 {
		t.Fatalf("status %+v", st)
	}
	// Unknown report.
	resp, raw = h.do(http.MethodGet, "/api/v2/sensor/results/"+newReportID(), nil)
	h.expect(resp, raw, 404, "report-not-found")
}

func TestSensorV2_AbandonAndOpenReportCap(t *testing.T) {
	limits := protov2.DefaultLimits()
	limits.MaxOpenReportsPerSensor = 2
	h := newV2Harness(t, v2HarnessOpts{limits: limits})
	seg := v2Segment("semgrep", "1.0", "a")
	ids := []string{newReportID(), newReportID(), newReportID()}
	for i, id := range ids {
		resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id+"/segments/0", seg)
		if i < 2 {
			h.expect(resp, raw, 202, "")
		} else {
			h.expect(resp, raw, 429, "too-many-open-reports")
		}
	}
	resp, raw := h.do(http.MethodDelete, "/api/v2/sensor/results/"+ids[0], nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete: %d %s", resp.StatusCode, raw)
	}
	_, raw = h.do(http.MethodGet, "/api/v2/sensor/results/"+ids[0], nil)
	if st := h.status(raw); st.State != protov2.StateExpired {
		t.Fatalf("abandoned state %s", st.State)
	}
	resp, raw = h.do(http.MethodPut, "/api/v2/sensor/results/"+ids[2]+"/segments/0", seg)
	h.expect(resp, raw, 202, "")
	resp, raw = h.do(http.MethodPut, "/api/v2/sensor/results/"+ids[0]+"/segments/1", seg)
	h.expect(resp, raw, 409, "report-expired")
}

func TestSensorV2_EdgeAndValidationProblems(t *testing.T) {
	// This test sends more requests than one sensor's write burst.
	oldBurst := v2WriteBurstPerSensor
	v2WriteBurstPerSensor = 1000
	t.Cleanup(func() { v2WriteBurstPerSensor = oldBurst })
	limits := protov2.DefaultLimits()
	limits.MaxFindingsPerSegment = 3
	limits.MaxFindingsPerReport = 4
	h := newV2Harness(t, v2HarnessOpts{limits: limits})
	put := func(body []byte, opts ...reqOpt) (*http.Response, []byte) {
		return h.do(http.MethodPut, "/api/v2/sensor/results/"+newReportID(), body, opts...)
	}
	good := v2Segment("semgrep", "1.0", "a")

	cases := []struct {
		name    string
		body    []byte
		opts    []reqOpt
		status  int
		problem string
	}{
		{"application/json", good, []reqOpt{withHeader("Content-Type", "application/json")}, 415, "unsupported-media-type"},
		{"brotli", good, []reqOpt{withHeader("Content-Encoding", "br")}, 415, "unsupported-encoding"},
		{"no digest", good, []reqOpt{func(r *http.Request) { r.Header.Del(protov2.HeaderContentDigest) }}, 400, "digest-required"},
		{"bad digest", good, []reqOpt{withHeader(protov2.HeaderContentDigest, digestOf([]byte("x")))}, 400, "digest-mismatch"},
		{"duplicate keys", []byte(`{"version":"1.0","version":"1.0"}`), nil, 422, "invalid-json"},
		{"invalid utf-8", []byte("{\"version\":\"\xff\"}"), nil, 422, "invalid-json"},
		{"unknown field", bytes.Replace(good, []byte(`"version"`), []byte(`"tenant_id":"x","version"`), 1), nil, 422, "schema-invalid"},
		{"version 2", bytes.Replace(good, []byte(`"version":"1.0"`), []byte(`"version":"2.0"`), 1), nil, 422, "version-mismatch"},
		{"undeclared tool", v2Segment("trivy", "1.0", "a"), nil, 422, "tool-not-permitted"},
		{"reserved tool", v2Segment("pentest", "1.0", "a"), nil, 422, "tool-not-permitted"},
		{"too many findings in a segment", v2Segment("semgrep", "1.0", "a", "b", "c", "d"), nil, 413, "report-too-large"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, raw := put(c.body, c.opts...)
			h.expect(resp, raw, c.status, c.problem)
		})
	}

	// 415 carries Accept.
	resp, _ := put(good, withHeader("Content-Type", "application/json"))
	if resp.Header.Get("Accept") != protov2.MediaTypeCTIS {
		t.Fatalf("Accept %q", resp.Header.Get("Accept"))
	}
	// Ids: upper-case report id, bad segment number.
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+strings.ToUpper(newReportID()), good)
	h.expect(resp, raw, 400, "invalid-id")
	resp, raw = h.do(http.MethodPut, "/api/v2/sensor/results/"+newReportID()+"/segments/01", good)
	h.expect(resp, raw, 400, "invalid-id")
	resp, raw = h.do(http.MethodPut, "/api/v2/sensor/results/"+newReportID()+"/segments/256", good)
	h.expect(resp, raw, 400, "invalid-id")

	// The report total (4) is enforced across segments.
	id := newReportID()
	resp, raw = h.do(http.MethodPut, "/api/v2/sensor/results/"+id+"/segments/0", v2Segment("semgrep", "1.0", "a", "b", "c"))
	h.expect(resp, raw, 202, "")
	resp, raw = h.do(http.MethodPut, "/api/v2/sensor/results/"+id+"/segments/1", v2Segment("semgrep", "1.0", "d", "e"))
	h.expect(resp, raw, 413, "report-too-large")

	// Gzip: digest over the compressed bytes is accepted.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(good)
	_ = zw.Close()
	resp, raw = put(gz.Bytes(), withHeader("Content-Encoding", "gzip"))
	h.expect(resp, raw, 202, "")

	// Decompression bomb.
	var bomb bytes.Buffer
	zw = gzip.NewWriter(&bomb)
	_, _ = zw.Write(make([]byte, 70<<20))
	_ = zw.Close()
	resp, raw = put(bomb.Bytes(), withHeader("Content-Encoding", "gzip"))
	h.expect(resp, raw, 413, "decompressed-too-large")

	// Oversize declared length: refused before the body is read.
	resp, raw = put(good, func(r *http.Request) {
		r.Body = io.NopCloser(io.LimitReader(zeroReader{}, limits.MaxContentBytes+1))
		r.ContentLength = limits.MaxContentBytes + 1
	})
	h.expect(resp, raw, 413, "content-too-large")

	// Chunked: no Content-Length.
	resp, raw = put(good, func(r *http.Request) {
		r.Body = io.NopCloser(bytes.NewReader(good))
		r.ContentLength = -1
	})
	h.expect(resp, raw, 411, "length-required")

	// An asset-less finding is accepted as a report but rejected as an item.
	id = newReportID()
	partial := []byte(`{"version":"1.0","metadata":{"timestamp":"2026-10-01T12:00:00Z"},"tool":{"name":"semgrep"},` +
		`"assets":[{"id":"repo","type":"repository","value":"github.com/acme/v2-partial"}],` +
		`"findings":[{"type":"vulnerability","title":"ok","severity":"low","asset_ref":"repo"},` +
		`{"type":"vulnerability","title":"orphan","severity":"low","asset_ref":"nowhere"}]}`)
	resp, raw = h.do(http.MethodPut, "/api/v2/sensor/results/"+id, partial)
	h.expect(resp, raw, 202, "")
	h.work(id)
	_, raw = h.do(http.MethodGet, "/api/v2/sensor/results/"+id, nil)
	st := h.status(raw)
	if st.State != protov2.StateCompleted || st.Accepted.Findings != 1 || st.Rejected.Findings != 1 ||
		len(st.Errors) != 1 || st.Errors[0].Pointer != "/findings/1/asset_ref" {
		t.Fatalf("partial success %+v", st)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// RFC-023 C-2 in both directions, and a disabled sensor.
func TestSensorV2_RouteIsolation(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	good := v2Segment("semgrep", "1.0", "a")
	path := "/api/v2/sensor/results/" + newReportID()

	for name, opt := range map[string]reqOpt{
		"no credentials": func(r *http.Request) { r.Header.Del("Authorization") },
		"unknown key":    withHeader("Authorization", "Bearer rda_not-a-real-key"),
		"user JWT":       withHeader("Authorization", "Bearer "+h.jwtToken),
		"oct_ API key":   withHeader("Authorization", "Bearer oct_0123456789abcdef"),
		"session cookie": func(r *http.Request) {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "auth_token", Value: h.jwtToken})
		},
		"key in X-API-Key": func(r *http.Request) { r.Header.Del("Authorization"); r.Header.Set("X-API-Key", "rda_wrong") },
	} {
		t.Run(name, func(t *testing.T) {
			resp, raw := h.do(http.MethodPut, path, good, opt)
			h.expect(resp, raw, 401, "unauthenticated")
			resp, raw = h.do(http.MethodGet, "/api/v2/sensor/hello", nil, opt)
			h.expect(resp, raw, 401, "unauthenticated")
		})
	}

	// The sensor key is refused on a user route.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+"/api/v1/probe/", nil)
	req.Header.Set("Authorization", "Bearer "+h.key)
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("sensor key on a user route: %d", resp.StatusCode)
	}
	// ...where the user JWT works.
	req.Header.Set("Authorization", "Bearer "+h.jwtToken)
	if resp, err = h.srv.Client().Do(req); err != nil || resp.StatusCode != 299 {
		t.Fatalf("user JWT on the user route: %v %v", resp, err)
	}
	_ = resp.Body.Close()

	// hello with the sensor key.
	r2, raw := h.do(http.MethodGet, "/api/v2/sensor/hello", nil)
	h.expect(r2, raw, 200, "")
	var hello protov2.Hello
	if json.Unmarshal(raw, &hello) != nil || hello.Protocol != 2 || hello.Limits.MaxContentBytes != protov2.DefaultMaxContentBytes {
		t.Fatalf("hello %s", raw)
	}

	// A disabled sensor is refused on v2.
	if _, err := h.db.Exec(`UPDATE sensors SET status = 'disabled' WHERE id = $1`, h.sensorID); err != nil {
		t.Fatal(err)
	}
	r2, raw = h.do(http.MethodPut, path, good)
	h.expect(r2, raw, 401, "unauthenticated")
}

// Another tenant's sensor cannot see or write this tenant's report, even
// with the same report id, nor use this tenant's command.
func TestSensorV2_CrossTenant(t *testing.T) {
	a := newV2Harness(t, v2HarnessOpts{})
	b := newV2Harness(t, v2HarnessOpts{})
	id := newReportID()
	resp, raw := a.do(http.MethodPut, "/api/v2/sensor/results/"+id, v2Segment("semgrep", "1.0", "a"))
	a.expect(resp, raw, 202, "")

	// b's sensor (another tenant) talks to a's server with its own key.
	b.srv = a.srv
	resp, raw = b.do(http.MethodGet, "/api/v2/sensor/results/"+id, nil)
	b.expect(resp, raw, 404, "report-not-found")
	resp, raw = b.do(http.MethodPut, "/api/v2/sensor/results/"+id, v2Segment("semgrep", "1.0", "zzz"))
	b.expect(resp, raw, 202, "") // its own report, its own tenant
	_, raw = a.do(http.MethodGet, "/api/v2/sensor/results/"+id, nil)
	if st := a.status(raw); st.Segments.Received != 1 {
		t.Fatalf("a's report changed: %+v", st)
	}

	// A command of tenant a, assigned to a's sensor: b cannot bind to it,
	// a can once it is claimed.
	cmdID := shared.NewID().String()
	if _, err := a.db.Exec(`INSERT INTO commands (id, tenant_id, sensor_id, type, priority, payload, status, created_at)
		VALUES ($1, $2, $3, 'scan', 'normal', '{"scanner":"semgrep"}', 'running', NOW())`, cmdID, a.tenantID, a.sensorID); err != nil {
		t.Fatalf("seed command: %v", err)
	}
	path := "/api/v2/sensor/commands/" + strings.ToLower(cmdID) + "/results/" + newReportID()
	resp, raw = b.do(http.MethodPut, path, v2Segment("semgrep", "1.0", "a"))
	b.expect(resp, raw, 404, "command-not-found")
	resp, raw = a.do(http.MethodPut, path, v2Segment("semgrep", "1.0", "a"))
	a.expect(resp, raw, 202, "")
	if st := a.status(raw); st.CommandID != strings.ToLower(cmdID) {
		t.Fatalf("command binding %+v", st)
	}
	// The bound command's tool is the only tool it may report.
	if _, err := a.db.Exec(`UPDATE commands SET payload = '{"scanner":"trivy"}' WHERE id = $1`, cmdID); err != nil {
		t.Fatal(err)
	}
	resp, raw = a.do(http.MethodPut, "/api/v2/sensor/commands/"+strings.ToLower(cmdID)+"/results/"+newReportID(), v2Segment("semgrep", "1.0", "a"))
	a.expect(resp, raw, 422, "tool-not-permitted")
}

func TestSensorV2_RateLimitAndQueueFull(t *testing.T) {
	limiter := middleware.NewTelemetryRateLimiter(0.001, 1, time.Minute, logger.NewNop())
	defer limiter.Stop()
	h := newV2Harness(t, v2HarnessOpts{tenantLimiter: limiter})
	good := v2Segment("semgrep", "1.0", "a")
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+newReportID(), good)
	h.expect(resp, raw, 202, "")
	resp, raw = h.do(http.MethodPut, "/api/v2/sensor/results/"+newReportID(), good)
	h.expect(resp, raw, 429, "rate-limited")
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}

	q := newV2Harness(t, v2HarnessOpts{maxPending: 1})
	resp, raw = q.do(http.MethodPut, "/api/v2/sensor/results/"+newReportID(), good)
	q.expect(resp, raw, 202, "")
	resp, raw = q.do(http.MethodPut, "/api/v2/sensor/results/"+newReportID(), good)
	q.expect(resp, raw, 429, "queue-full")
}

// A completed v2 report counts toward the sensor's totals once, as a v1
// ingest does. The v2 path counted every segment as a scan, so a report sent
// in N segments added N scans (the drawer's "Scans to date").
func TestSensorV2_CompletedReportCountsTowardSensorTotals(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	totals := func() (scans, findings int64) {
		t.Helper()
		if err := h.db.QueryRow(`SELECT total_scans, total_findings FROM sensors WHERE id = $1`, h.sensorID).
			Scan(&scans, &findings); err != nil {
			t.Fatalf("totals: %v", err)
		}
		return scans, findings
	}
	scans0, findings0 := totals()

	id := newReportID()
	base := "/api/v2/sensor/results/" + id
	s0, s1 := v2Segment("semgrep", "1.0", "a"), v2Segment("semgrep", "1.0", "b", "c")
	for seq, body := range [][]byte{s0, s1} {
		resp, raw := h.do(http.MethodPut, fmt.Sprintf("%s/segments/%d", base, seq), body)
		h.expect(resp, raw, 202, "")
	}
	b, _ := json.Marshal(protov2.CommitRequest{SegmentCount: 2, SegmentDigests: []string{digestOf(s0), digestOf(s1)}})
	resp, raw := h.do(http.MethodPost, base+"/commit", nil, func(r *http.Request) {
		r.Body = io.NopCloser(bytes.NewReader(b))
		r.ContentLength = int64(len(b))
		r.Header.Set("Content-Type", "application/json")
	})
	h.expect(resp, raw, 202, "")

	h.work(id)
	scans, findings := totals()
	if scans-scans0 != 1 || findings-findings0 != 3 {
		t.Fatalf("after one report of 2 segments: +%d scans, +%d findings; want +1, +3", scans-scans0, findings-findings0)
	}
	// A late retry of the report's jobs does not count it again.
	h.work(id)
	if scans2, findings2 := totals(); scans2 != scans || findings2 != findings {
		t.Fatalf("retry counted again: %d/%d -> %d/%d", scans, findings, scans2, findings2)
	}
}

// A report queued by a sensor that is revoked before the worker reaches it
// is dropped, not ingested (RFC-040 §5.2). The worker used to rebuild the
// sensor as active from the job and land the report anyway.
func TestSensorV2_QueuedReportOfRevokedSensorIsDropped(t *testing.T) {
	for _, action := range []string{"revoke", "disable"} {
		t.Run(action, func(t *testing.T) {
			h := newV2Harness(t, v2HarnessOpts{})
			id := newReportID()
			resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id, v2Segment("semgrep", "1.0", "a", "b"))
			h.expect(resp, raw, 202, "")

			ctx := context.Background()
			var err error
			if action == "revoke" {
				_, err = h.sensors.RevokeSensor(ctx, h.tenantID, h.sensorID, "compromised", nil)
			} else {
				_, err = h.sensors.DisableSensor(ctx, h.tenantID, h.sensorID, "maintenance", nil)
			}
			if err != nil {
				t.Fatalf("%s sensor: %v", action, err)
			}

			h.work(id) // fails the test if the worker returns an error (a retry)

			var findings, assets int
			_ = h.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1`, h.tenantID).Scan(&findings)
			_ = h.db.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1`, h.tenantID).Scan(&assets)
			if findings != 0 || assets != 0 {
				t.Fatalf("%sd sensor's queued report was ingested: %d findings, %d assets", action, findings, assets)
			}
			var state string
			_ = h.db.QueryRow(`SELECT state FROM ingest_reports WHERE report_id = $1`, id).Scan(&state)
			if state != string(protov2.StateFailed) {
				t.Fatalf("report state %q, want failed", state)
			}
			var audited int
			_ = h.db.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'ingest.failed'
				AND result = 'denied' AND resource_id = $2`, h.tenantID, id).Scan(&audited)
			if audited == 0 {
				t.Fatal("dropped report not in the audit log")
			}
			_, _ = h.db.ExecContext(ctx, `DELETE FROM audit_logs WHERE tenant_id = $1`, h.tenantID)
		})
	}
}

// The same for a protocol v1 report queued in async mode.
func TestIngestV1_QueuedReportOfRevokedSensorIsDropped(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	ctx := context.Background()
	tenantID, sensorID := shared.MustIDFromString(h.tenantID), shared.MustIDFromString(h.sensorID)
	report := []byte(`{"version":"1.0","metadata":{"id":"v1-queued","source_type":"scanner"},"tool":{"name":"semgrep"},` +
		`"assets":[{"id":"repo","type":"repository","value":"github.com/acme/v1-queued"}],` +
		`"findings":[{"type":"vulnerability","title":"t","severity":"high","rule_id":"r1","asset_ref":"repo"}]}`)
	proc := ingest.NewJobProcessor(h.ingest)

	// While the sensor is active the queued report is ingested.
	if _, err := proc.Process(ctx, ingestjob.NewJob(tenantID, &sensorID, "v1-queued", "scanner", report)); err != nil {
		t.Fatalf("active sensor: %v", err)
	}
	var assets int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1`, h.tenantID).Scan(&assets)
	if assets != 1 {
		t.Fatalf("active sensor's report: %d assets, want 1", assets)
	}
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM findings WHERE tenant_id = $1`, `DELETE FROM assets WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`} {
			_, _ = h.db.ExecContext(context.Background(), q, h.tenantID)
		}
	})

	if _, err := h.sensors.RevokeSensor(ctx, h.tenantID, h.sensorID, "compromised", nil); err != nil {
		t.Fatal(err)
	}
	second := bytes.Replace(report, []byte("v1-queued"), []byte("v1-queued-2"), -1)
	out, err := proc.Process(ctx, ingestjob.NewJob(tenantID, &sensorID, "v1-queued-2", "scanner", second))
	if err != nil {
		t.Fatalf("a dropped job must complete, not retry: %v", err)
	}
	var dropped ingest.DroppedJob
	if err := json.Unmarshal(out, &dropped); err != nil || !dropped.Dropped {
		t.Fatalf("job result %s, want a drop", out)
	}
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1`, h.tenantID).Scan(&assets)
	if assets != 1 {
		t.Fatalf("revoked sensor's queued report was ingested: %d assets, want 1", assets)
	}
	var audited int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'ingest.failed'
		AND result = 'denied' AND resource_id = 'v1-queued-2'`, h.tenantID).Scan(&audited)
	if audited != 1 {
		t.Fatalf("%d audit entries for the dropped report, want 1", audited)
	}
}
