package routes

// Sensor protocol v3, HTTPS binding (docs/rfcs/RFC-059-sensor-transport-v3.md)
// over the real wiring: the v3 server serving every RPC through the
// in-process v2 route group, behind the RFC 9421 authenticator, against a
// migrated database. Both the Connect and the gRPC protocol are exercised.
// Asserts: signed key-bound identity only (no bearer, no unsigned), the v2
// semantics of every RPC, tenant isolation (another tenant's command is
// NOT_FOUND), idempotent uploads, the paused rule, and the control stream
// (push on a new command within a second; a revoked key ends it).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/commandlog"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/sensor"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/sensortransport"
	"github.com/openctemio/openctem/api/internal/testdb"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
	"github.com/openctemio/openctem/api/pkg/sensorproto/v3/sensorv3connect"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type v3Harness struct {
	t       *testing.T
	db      *sql.DB
	srv     *httptest.Server
	cmds    *command.Service
	v3      *sensortransport.Server
	sensors *sensor.SensorService
}

type v3Sensor struct {
	id, tenantID string
	signer       *sensorsig.Signer
	key          ed25519.PrivateKey
}

// newV3Harness builds the stack; recheck is the control stream's periodic
// re-check (0: 30 s, so only a wake can deliver an event sooner).
func newV3Harness(t *testing.T, recheck ...time.Duration) *v3Harness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping protocol v3 test")
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
	sensorSvc.SetSigningKeyRepository(postgres.NewSensorSigningKeyRepository(db))
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
	ch.SetCommandLogs(commandlog.NewService(postgres.NewCommandLogRepository(db)))
	sh := handler.NewSuppressionHandler(suppression.NewService(postgres.NewSuppressionRepository(db), log), log)
	ctl := handler.NewSensorControlV2Handler(ih, ch, sh, nil, log)
	receiver := ingest.NewV2Receiver(postgres.NewIngestReportRepository(db), parkedJobs{postgres.NewIngestJobRepository(db)},
		postgres.NewIngestJobRepository(db), cmdRepo, protov2.DefaultLimits(), 100, log)
	results := handler.NewSensorResultsV2Handler(receiver, sensorSvc, log)

	cfg := sensortransport.Config{GRPCEndpoint: "sensors.test:443", Keepalive: time.Second}
	if len(recheck) > 0 {
		cfg.Recheck = recheck[0]
	}
	v3 := sensortransport.NewServer(cfg, nil, log)
	cmdRepo.SetChangeNotifier(v3.Hub())
	results.SetTransportV3(&protov2.TransportV3{HTTPSPath: sensortransport.PathPrefix, GRPCEndpoint: "sensors.test:443"})

	budgets := newSensorV2Budgets(nil, log)
	router := infrahttp.NewChiRouter()
	mountSensorV2(router, results, ctl, budgets, results.Authenticate)
	v3.Attach(sensorV2InProcess(results, ctl, budgets), ctl, results)
	https := v3.HTTPSHandler(results.AuthenticateV3)
	mux := http.NewServeMux()
	mux.Handle(sensortransport.PathPrefix+"/", https)
	mux.Handle("/", router.Handler())

	// TLS + HTTP/2, so the gRPC protocol works on the HTTPS binding too.
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	sensorSvc.SetStatusNotifier(v3.Hub().Wake)
	sensorSvc.SetEventRepository(postgres.NewSensorEventRepository(db), sensordom.DefaultEventLimits())
	return &v3Harness{t: t, db: sqldb, srv: srv, cmds: cmdSvc, v3: v3, sensors: sensorSvc}
}

func (h *v3Harness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

func (h *v3Harness) newTenant() string {
	h.t.Helper()
	id := shared.NewID().String()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id, "v3-"+id)
	h.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = h.db.ExecContext(ctx, `DELETE FROM ingest_reports WHERE tenant_id = $1`, id)
		_, _ = h.db.ExecContext(ctx, `DELETE FROM commands WHERE tenant_id = $1`, id)
		_, _ = h.db.ExecContext(ctx, `DELETE FROM sensor_keys WHERE tenant_id = $1`, id)
		_, _ = h.db.ExecContext(ctx, `DELETE FROM sensors WHERE tenant_id = $1`, id)
		_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id)
	})
	return id
}

// newKeyBound inserts a key-bound sensor of tenantID that verified semgrep.
func (h *v3Harness) newKeyBound(tenantID string) v3Sensor {
	h.t.Helper()
	sid := shared.NewID().String()
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix,
	        max_concurrent_jobs, auth_kind, capabilities, reported_tools, reported_tool_names, reported_at)
	        VALUES ($1, $2, $3, 'worker', 'active', 'unknown', 'daemon', $4, '', 5, 'key_bound', ARRAY['sast'],
	        '[{"name":"semgrep","installed":true}]', ARRAY['semgrep'], NOW())`,
		sid, tenantID, "v3-"+sid[:8], sensordom.KeyBoundHashPlaceholder())
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := sensorsig.NewSigner(key)
	h.exec(`INSERT INTO sensor_keys (tenant_id, sensor_id, thumbprint, public_key, status) VALUES ($1, $2, $3, $4, 'active')`,
		tenantID, sid, signer.KeyID(), []byte(signer.PublicKey()))
	return v3Sensor{id: sid, tenantID: tenantID, signer: signer, key: key}
}

// client is a v3 client of the HTTPS binding signing with s's key; grpc
// selects the gRPC protocol (else Connect).
func (h *v3Harness) client(s v3Sensor, grpc bool) sensorv3connect.SensorServiceClient {
	base := h.srv.Client().Transport.(*http.Transport).Clone()
	var rt http.RoundTripper = base
	if grpc {
		p := new(http.Protocols)
		p.SetHTTP2(true)
		rt = &http.Transport{TLSClientConfig: base.TLSClientConfig.Clone(), Protocols: p}
	}
	var hc *http.Client
	if s.signer != nil {
		hc = &http.Client{Transport: &sensorsig.Transport{Signer: s.signer, Base: rt}}
	} else {
		hc = &http.Client{Transport: rt}
	}
	var opts []connect.ClientOption
	if grpc {
		opts = append(opts, connect.WithGRPC())
	}
	return sensorv3connect.NewSensorServiceClient(hc, h.srv.URL+sensortransport.PathPrefix, opts...)
}

func (h *v3Harness) newCommand(tenantID, sensorID string) string {
	h.t.Helper()
	c, err := h.cmds.Create(context.Background(), command.CreateInput{TenantID: tenantID, SensorID: sensorID,
		Type: "scan", Priority: "normal", Payload: json.RawMessage(`{"scanner":"semgrep","target":"."}`), ExpiresIn: 3600})
	if err != nil {
		h.t.Fatalf("create command: %v", err)
	}
	return c.ID.String()
}

func wantCode(t *testing.T, err error, code connect.Code) {
	t.Helper()
	if connect.CodeOf(err) != code {
		t.Fatalf("error %v (code %v), want %v", err, connect.CodeOf(err), code)
	}
}

func problemOf(t *testing.T, err error) *sensorv3.Problem {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("not a connect error: %v", err)
	}
	for _, d := range ce.Details() {
		v, derr := d.Value()
		if p, ok := v.(*sensorv3.Problem); derr == nil && ok {
			return p
		}
	}
	t.Fatalf("no problem detail on %v", err)
	return nil
}

func TestSensorV3HTTPS_IdentityIsTheSignatureOnly(t *testing.T) {
	h := newV3Harness(t)
	tid := h.newTenant()
	s := h.newKeyBound(tid)
	ctx := context.Background()

	for _, grpc := range []bool{false, true} {
		out, err := h.client(s, grpc).Hello(ctx, connect.NewRequest(&sensorv3.HelloRequest{}))
		if err != nil {
			t.Fatalf("hello (grpc=%v): %v", grpc, err)
		}
		if out.Msg.GetProtocol() != 3 || out.Msg.GetGrpcEndpoint() != "sensors.test:443" ||
			out.Msg.GetBinding() != sensorv3.Binding_BINDING_HTTPS {
			t.Fatalf("hello: %+v", out.Msg)
		}
		var hello protov2.Hello
		if err := json.Unmarshal(out.Msg.GetHelloJson(), &hello); err != nil || hello.TransportV3 == nil ||
			hello.TransportV3.HTTPSPath != "/api/v3/sensor" {
			t.Fatalf("hello document: %s", out.Msg.GetHelloJson())
		}
	}

	// Unsigned: refused.
	_, err := h.client(v3Sensor{}, false).Hello(ctx, connect.NewRequest(&sensorv3.HelloRequest{}))
	wantCode(t, err, connect.CodeUnauthenticated)

	// A bearer key is not an identity on v3, even a valid one.
	var hash string
	if err := h.db.QueryRow(`SELECT api_key_hash FROM sensors WHERE id = $1`, s.id).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	req := connect.NewRequest(&sensorv3.HelloRequest{})
	req.Header().Set("Authorization", "Bearer "+hash)
	_, err = h.client(v3Sensor{}, false).Hello(ctx, req)
	wantCode(t, err, connect.CodeUnauthenticated)

	// A replayed signature: refused (the nonce is spent).
	replayed := &replayTransport{base: h.srv.Client().Transport}
	rc := sensorv3connect.NewSensorServiceClient(&http.Client{Transport: &sensorsig.Transport{Signer: s.signer, Base: replayed}},
		h.srv.URL+sensortransport.PathPrefix)
	if _, err := rc.Hello(ctx, connect.NewRequest(&sensorv3.HelloRequest{})); err != nil {
		t.Fatalf("first: %v", err)
	}
	replayed.replay = true
	_, err = rc.Hello(ctx, connect.NewRequest(&sensorv3.HelloRequest{}))
	wantCode(t, err, connect.CodeUnauthenticated)

	// A revoked key: refused.
	h.exec(`UPDATE sensor_keys SET status = 'revoked', revoked_at = NOW() WHERE sensor_id = $1`, s.id)
	_, err = h.client(s, false).Hello(ctx, connect.NewRequest(&sensorv3.HelloRequest{}))
	wantCode(t, err, connect.CodeUnauthenticated)
}

// replayTransport sends the first request and then, when replay is set, the
// first request's headers again.
type replayTransport struct {
	base   http.RoundTripper
	first  http.Header
	body   []byte
	replay bool
}

func (r *replayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if r.first == nil {
		r.first = req.Header.Clone()
		if req.GetBody != nil {
			b, _ := req.GetBody()
			buf := new(strings.Builder)
			_, _ = io.Copy(buf, b)
			r.body = []byte(buf.String())
		}
	} else if r.replay {
		req = req.Clone(req.Context())
		req.Header = r.first.Clone()
		req.Body = io.NopCloser(bytes.NewReader(r.body))
		req.ContentLength = int64(len(r.body))
	}
	return r.base.RoundTrip(req)
}

func TestSensorV3HTTPS_CommandsTenantIsolationAndPaused(t *testing.T) {
	h := newV3Harness(t)
	tidA, tidB := h.newTenant(), h.newTenant()
	a := h.newKeyBound(tidA)
	h.newKeyBound(tidB)
	ctx := context.Background()

	for _, grpc := range []bool{false, true} {
		c := h.client(a, grpc)
		cmdID := h.newCommand(tidA, "")
		claimed, err := c.ClaimCommands(ctx, connect.NewRequest(&sensorv3.ClaimCommandsRequest{Limit: 5}))
		if err != nil {
			t.Fatalf("claim (grpc=%v): %v", grpc, err)
		}
		list := decodeAs[protov2.CommandList](t, claimed.Msg.GetCommandsJson())
		if len(list.Commands) != 1 || list.Commands[0].ID != cmdID || list.Commands[0].Status != "acknowledged" {
			t.Fatalf("claimed %s", claimed.Msg.GetCommandsJson())
		}
		epoch := int64(list.Commands[0].LeaseEpoch)
		for _, tr := range []sensorv3.CommandTransition{sensorv3.CommandTransition_COMMAND_TRANSITION_START,
			sensorv3.CommandTransition_COMMAND_TRANSITION_COMPLETE} {
			out, err := c.TransitionCommand(ctx, connect.NewRequest(&sensorv3.TransitionCommandRequest{
				CommandId: cmdID, Transition: tr, LeaseEpoch: &epoch, BodyJson: []byte(`{"result":{"ok":true}}`)}))
			if err != nil {
				t.Fatalf("%v: %v", tr, err)
			}
			_ = out
		}
		var status string
		_ = h.db.QueryRow(`SELECT status FROM commands WHERE id = $1`, cmdID).Scan(&status)
		if status != "completed" {
			t.Fatalf("status %q", status)
		}
		// A stale lease epoch is refused as v2 refuses it.
		stale := epoch + 7
		_, err = c.TransitionCommand(ctx, connect.NewRequest(&sensorv3.TransitionCommandRequest{
			CommandId: cmdID, Transition: sensorv3.CommandTransition_COMMAND_TRANSITION_FAIL, LeaseEpoch: &stale}))
		if err == nil {
			t.Fatal("transition with a stale epoch accepted")
		}
	}

	// Tenant B's command is not found for tenant A's sensor, whatever the RPC.
	other := h.newCommand(tidB, "")
	_, err := h.client(a, false).TransitionCommand(ctx, connect.NewRequest(&sensorv3.TransitionCommandRequest{
		CommandId: other, Transition: sensorv3.CommandTransition_COMMAND_TRANSITION_CLAIM}))
	wantCode(t, err, connect.CodeNotFound)
	if p := problemOf(t, err); p.GetHttpStatus() != 404 || !strings.HasSuffix(p.GetType(), "command-not-found") {
		t.Fatalf("problem %+v", p)
	}
	var st string
	_ = h.db.QueryRow(`SELECT status FROM commands WHERE id = $1`, other).Scan(&st)
	if st != "pending" {
		t.Fatalf("tenant B's command changed: %q", st)
	}

	// A malformed id never becomes a path.
	_, err = h.client(a, false).TransitionCommand(ctx, connect.NewRequest(&sensorv3.TransitionCommandRequest{
		CommandId: "../../results", Transition: sensorv3.CommandTransition_COMMAND_TRANSITION_CLAIM}))
	wantCode(t, err, connect.CodeInvalidArgument)

	// Paused (disabled): heartbeat answers paused, nothing else passes.
	h.exec(`UPDATE sensors SET status = 'disabled' WHERE id = $1`, a.id)
	hb, err := h.client(a, false).Heartbeat(ctx, connect.NewRequest(&sensorv3.HeartbeatRequest{HeartbeatJson: []byte(`{}`)}))
	if err != nil {
		t.Fatalf("paused heartbeat: %v", err)
	}
	if r := decodeAs[protov2.HeartbeatResponse](t, hb.Msg.GetHeartbeatJson()); r.Status != "paused" || r.SensorID != a.id {
		t.Fatalf("paused heartbeat: %s", hb.Msg.GetHeartbeatJson())
	}
	_, err = h.client(a, false).ClaimCommands(ctx, connect.NewRequest(&sensorv3.ClaimCommandsRequest{Limit: 1}))
	wantCode(t, err, connect.CodeUnauthenticated)
}

func TestSensorV3HTTPS_ResultsAreIdempotent(t *testing.T) {
	h := newV3Harness(t)
	tid := h.newTenant()
	s := h.newKeyBound(tid)
	ctx := context.Background()
	c := h.client(s, true)

	report := shared.NewID().String()
	body := v2Segment("semgrep", "1.6", "r1")
	put := func(content []byte) (*connect.Response[sensorv3.PutResultResponse], error) {
		return c.PutResult(ctx, connect.NewRequest(&sensorv3.PutResultRequest{
			ReportId: report, Content: content, ContentType: protov2.MediaTypeCTIS, ContentDigest: digestOf(content)}))
	}
	first, err := put(body)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !first.Msg.GetCreated() {
		t.Fatalf("first put not created: %s", first.Msg.GetStatusJson())
	}
	again, err := put(body)
	if err != nil {
		t.Fatalf("replayed put: %v", err)
	}
	if again.Msg.GetCreated() {
		t.Fatal("a replayed upload created a second report")
	}
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM ingest_reports WHERE tenant_id = $1`, tid).Scan(&n)
	if n != 1 {
		t.Fatalf("%d reports, want 1", n)
	}
	// The same report id with other content is a conflict.
	_, err = put(v2Segment("semgrep", "1.6", "r2"))
	wantCode(t, err, connect.CodeAborted)

	// A wrong digest never reaches the receiver.
	_, err = c.PutResult(ctx, connect.NewRequest(&sensorv3.PutResultRequest{
		ReportId: shared.NewID().String(), Content: body, ContentType: protov2.MediaTypeCTIS, ContentDigest: digestOf([]byte("x"))}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad digest: %v", err)
	}
	st, err := c.GetResultStatus(ctx, connect.NewRequest(&sensorv3.GetResultStatusRequest{ReportId: report}))
	if err != nil || !strings.Contains(string(st.Msg.GetStatusJson()), report) {
		t.Fatalf("status: %v %s", err, st.Msg.GetStatusJson())
	}
}

func TestSensorV3HTTPS_ControlStreamPushes(t *testing.T) {
	h := newV3Harness(t)
	tid := h.newTenant()
	s := h.newKeyBound(tid)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for _, grpc := range []bool{false, true} {
		sctx, scancel := context.WithCancel(ctx)
		stream, err := h.client(s, grpc).Subscribe(sctx, connect.NewRequest(&sensorv3.SubscribeRequest{}))
		if err != nil {
			t.Fatalf("subscribe: %v", err)
		}
		if !stream.Receive() {
			t.Fatalf("no first event (grpc=%v): %v", grpc, stream.Err())
		}
		if ev := stream.Msg(); ev.GetStatus() != "ok" {
			t.Fatalf("first event %+v", ev)
		}
		start := time.Now()
		h.newCommand(tid, "")
		for {
			if !stream.Receive() {
				t.Fatalf("stream ended: %v", stream.Err())
			}
			if ev := stream.Msg(); !ev.GetKeepalive() && ev.GetPendingJobs() >= 1 {
				break
			}
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("pushed after %v, want under 1s", d)
		}
		scancel()
		_ = stream.Close()
		h.exec(`DELETE FROM commands WHERE tenant_id = $1`, tid)
	}
}

func TestSensorV3HTTPS_ControlStreamEndsOnRevoke(t *testing.T) {
	h := newV3Harness(t, 300*time.Millisecond)
	tid := h.newTenant()
	s := h.newKeyBound(tid)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// A revoked key ends a live stream within the re-check interval.
	stream, err := h.client(s, true).Subscribe(ctx, connect.NewRequest(&sensorv3.SubscribeRequest{}))
	if err != nil || !stream.Receive() {
		t.Fatalf("subscribe: %v %v", err, stream.Err())
	}
	h.exec(`UPDATE sensor_keys SET status = 'revoked', revoked_at = NOW() WHERE sensor_id = $1`, s.id)
	deadline := time.Now().Add(5 * time.Second)
	for stream.Receive() {
		if time.Now().After(deadline) {
			t.Fatal("stream outlived the revoked key")
		}
	}
	wantCode(t, stream.Err(), connect.CodeUnauthenticated)
	if h.v3.Hub().Streams() != 0 {
		t.Fatalf("%d streams left", h.v3.Hub().Streams())
	}
}
