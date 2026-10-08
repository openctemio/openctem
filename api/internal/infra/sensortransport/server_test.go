package sensortransport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
	"github.com/openctemio/openctem/api/pkg/sensorproto/v3/sensorv3connect"
)

func TestCodeForStatus(t *testing.T) {
	cases := map[int]connect.Code{
		400: connect.CodeInvalidArgument, 401: connect.CodeUnauthenticated, 403: connect.CodePermissionDenied,
		404: connect.CodeNotFound, 409: connect.CodeAborted, 412: connect.CodeFailedPrecondition,
		413: connect.CodeResourceExhausted, 415: connect.CodeInvalidArgument, 422: connect.CodeInvalidArgument,
		429: connect.CodeResourceExhausted, 500: connect.CodeInternal, 503: connect.CodeUnavailable,
		504: connect.CodeDeadlineExceeded, 418: connect.CodeInvalidArgument, 502: connect.CodeInternal,
	}
	for status, want := range cases {
		if got := codeForStatus(status); got != want {
			t.Errorf("%d: %v, want %v", status, got, want)
		}
	}
}

func TestProblemErrorCarriesTheV2Problem(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "7")
	body := []byte(`{"type":"https://openctem.io/problems/sensor/command-not-found","title":"Command not found","status":404}`)
	err := problemError(404, h, body)
	if err.Code() != connect.CodeNotFound || err.Message() != "Command not found" {
		t.Fatalf("%v", err)
	}
	if len(err.Details()) != 1 {
		t.Fatalf("details %d", len(err.Details()))
	}
	v, derr := err.Details()[0].Value()
	p, ok := v.(*sensorv3.Problem)
	if derr != nil || !ok || p.GetHttpStatus() != 404 || p.GetRetryAfterSeconds() != 7 ||
		!strings.HasSuffix(p.GetType(), "command-not-found") || string(p.GetProblemJson()) != string(body) {
		t.Fatalf("problem %+v %v", p, derr)
	}
	// A body that is not a problem never becomes the message.
	if e := problemError(500, http.Header{}, []byte("panic: secret stack")); e.Message() != "Internal Server Error" {
		t.Fatalf("message %q", e.Message())
	}
}

func TestEnvelopeGuards(t *testing.T) {
	for _, f := range []string{"capacity", "logs", "a-b_c9"} {
		if !featureToken(f) {
			t.Errorf("%q refused", f)
		}
	}
	for _, f := range []string{"", "Capacity", "a,b", "a b", "x\r\ny", strings.Repeat("a", 33)} {
		if featureToken(f) {
			t.Errorf("%q accepted", f)
		}
	}
	for _, id := range []string{"", "../x", "123", "00000000-0000-0000-0000-00000000000g"} {
		if validID(id) {
			t.Errorf("id %q accepted", id)
		}
	}
	if _, err := resultPath(shared.NewID().String(), "../../keys"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("command id path injection: %v", err)
	}
	if retryAfterSeconds(http.Header{"Retry-After": []string{"99999"}}) != 0 {
		t.Fatal("unbounded retry-after")
	}
}

func TestHubLimitsAndWakes(t *testing.T) {
	h := NewHub(2)
	a1, err := h.add("t1", "s1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.add("t1", "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.add("t1", "s1"); !errors.Is(err, errTooManyStreams) {
		t.Fatalf("third stream: %v", err)
	}
	b, _ := h.add("t2", "s2")

	h.Wake("t1", "s9") // another sensor of t1: nobody
	select {
	case <-a1.wake:
		t.Fatal("woken for another sensor")
	default:
	}
	h.Wake("t1", "")
	select {
	case <-a1.wake:
	default:
		t.Fatal("tenant wake missed")
	}
	select {
	case <-b.wake:
		t.Fatal("another tenant woken")
	default:
	}
	// Wakes coalesce and never block.
	for range 100 {
		h.Wake("t2", "s2")
	}
	h.WakeAll()
	h.remove(a1)
	if h.Streams() != 2 {
		t.Fatalf("streams %d", h.Streams())
	}
	if _, err := h.add("t1", "s1"); err != nil {
		t.Fatalf("slot not freed: %v", err)
	}
}

// fakeV2 answers every in-process call with status and body.
type fakeV2 struct {
	status int
	body   string
	got    *http.Request
}

func (f *fakeV2) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.got = r
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.status)
	_, _ = w.Write([]byte(f.body))
}

type noHints struct{}

func (noHints) StreamHints(context.Context, []string) handler.StreamHints {
	return handler.StreamHints{Status: "ok"}
}

type sameAuth struct{}

func (sameAuth) Reauthenticate(_ context.Context, id sensorapp.SensorIdentity) (sensorapp.SensorIdentity, error) {
	return id, nil
}

// serve mounts s behind an authenticator that installs id (nil: none).
func serve(t *testing.T, s *Server, id *sensorapp.SensorIdentity) sensorv3connect.SensorServiceClient {
	t.Helper()
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if id != nil {
				ctx = handler.WithSensorIdentity(ctx, *id)
				ctx = handler.WithSensorPeer(ctx, handler.SensorPeer{IP: "203.0.113.7", UserAgent: "ua/1"})
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	srv := httptest.NewServer(s.HTTPSHandler(auth))
	t.Cleanup(srv.Close)
	return sensorv3connect.NewSensorServiceClient(srv.Client(), srv.URL+PathPrefix)
}

func tenantSensor() sensorapp.SensorIdentity {
	tid := shared.NewID()
	return sensorapp.SensorIdentity{Sensor: &sensordom.Sensor{ID: shared.NewID(), TenantID: &tid}}
}

func TestIdentityIsRequired(t *testing.T) {
	ctx := context.Background()
	s := NewServer(Config{}, nil, logger.NewNop())
	f := &fakeV2{status: 200, body: `{}`}
	s.Attach(f, noHints{}, sameAuth{})

	_, err := serve(t, s, nil).Hello(ctx, connect.NewRequest(&sensorv3.HelloRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no identity: %v", err)
	}
	// A tenant-less (platform) sensor is refused, as on v2.
	platform := sensorapp.SensorIdentity{Sensor: &sensordom.Sensor{ID: shared.NewID()}}
	_, err = serve(t, s, &platform).Hello(ctx, connect.NewRequest(&sensorv3.HelloRequest{}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("platform sensor: %v", err)
	}
	if f.got != nil {
		t.Fatal("a refused call reached v2")
	}
	// Not attached yet: unavailable, never a nil dereference.
	early := NewServer(Config{}, nil, logger.NewNop())
	id := tenantSensor()
	_, err = serve(t, early, &id).Hello(ctx, connect.NewRequest(&sensorv3.HelloRequest{}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("unattached: %v", err)
	}
}

func TestCallsBecomeV2Requests(t *testing.T) {
	ctx := context.Background()
	s := NewServer(Config{}, nil, logger.NewNop())
	f := &fakeV2{status: 202, body: `{"report_id":"r"}`}
	s.Attach(f, noHints{}, sameAuth{})
	id := tenantSensor()
	c := serve(t, s, &id)

	report, cmd := shared.NewID().String(), shared.NewID().String()
	seg := uint32(3)
	out, err := c.PutResult(ctx, connect.NewRequest(&sensorv3.PutResultRequest{ReportId: report, CommandId: cmd, Segment: &seg,
		Content: []byte("x"), ContentType: protov2.MediaTypeCTIS, ContentEncoding: "gzip", ContentDigest: "sha-256=:a:"}))
	if err != nil || !out.Msg.GetCreated() {
		t.Fatalf("put: %v %+v", err, out)
	}
	r := f.got
	if r.Method != http.MethodPut || r.URL.Path != "/api/v2/sensor/commands/"+cmd+"/results/"+report+"/segments/3" ||
		r.Header.Get("Content-Encoding") != "gzip" || r.Header.Get("Content-Digest") != "sha-256=:a:" ||
		r.Header.Get("Content-Type") != protov2.MediaTypeCTIS || r.UserAgent() != "ua/1" || !strings.HasPrefix(r.RemoteAddr, "203.0.113.7:") {
		t.Fatalf("v2 request %s %s %v %s", r.Method, r.URL.Path, r.Header, r.RemoteAddr)
	}

	epoch := int64(4)
	f.status, f.body = 200, `{}`
	if _, err := c.TransitionCommand(ctx, connect.NewRequest(&sensorv3.TransitionCommandRequest{CommandId: cmd,
		Transition: sensorv3.CommandTransition_COMMAND_TRANSITION_RELEASE, LeaseEpoch: &epoch, BodyJson: []byte(`{"reason":"drain"}`)})); err != nil {
		t.Fatal(err)
	}
	if f.got.URL.Path != "/api/v2/sensor/commands/"+cmd+"/release" || f.got.Header.Get(protov2.HeaderLeaseEpoch) != "4" {
		t.Fatalf("release %s %v", f.got.URL.Path, f.got.Header)
	}

	if _, err := c.ClaimCommands(ctx, connect.NewRequest(&sensorv3.ClaimCommandsRequest{Limit: 3, Features: []string{"logs"}})); err != nil {
		t.Fatal(err)
	}
	if f.got.URL.RawQuery != "limit=3" || f.got.Header.Get(protov2.HeaderSensorFeatures) != "capacity,logs" {
		t.Fatalf("claim %s %v", f.got.URL.RawQuery, f.got.Header)
	}
	for _, bad := range []*sensorv3.ClaimCommandsRequest{{Limit: 0}, {Limit: 101}, {Limit: 1, Features: []string{"a\r\nX-Evil: 1"}}} {
		if _, err := c.ClaimCommands(ctx, connect.NewRequest(bad)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("claim %+v: %v", bad, err)
		}
	}

	f.status, f.body = 304, ""
	sup, err := c.GetSuppressions(ctx, connect.NewRequest(&sensorv3.GetSuppressionsRequest{Etag: `"abc"`}))
	if err != nil || !sup.Msg.GetNotModified() || f.got.Header.Get("If-None-Match") != `"abc"` {
		t.Fatalf("suppressions %v %+v", err, sup)
	}
}

func TestHTTPSBindingGuards(t *testing.T) {
	s := NewServer(Config{MaxContentBytes: 1024}, nil, logger.NewNop())
	s.Attach(&fakeV2{status: 200}, noHints{}, sameAuth{})
	id := tenantSensor()
	authCalled := false
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCalled = true
			next.ServeHTTP(w, r.WithContext(handler.WithSensorIdentity(r.Context(), id)))
		})
	}
	h := s.HTTPSHandler(auth)
	path := PathPrefix + sensorv3connect.SensorServiceHelloProcedure

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusMethodNotAllowed || authCalled {
		t.Fatalf("GET: %d auth=%v", rec.Code, authCalled)
	}
	rec = httptest.NewRecorder()
	big := httptest.NewRequest(http.MethodPost, path, strings.NewReader(strings.Repeat("x", 4<<20)))
	h.ServeHTTP(rec, big)
	if rec.Code != http.StatusRequestEntityTooLarge || authCalled {
		t.Fatalf("oversized: %d auth=%v", rec.Code, authCalled)
	}
}

func TestSubscribeSendsTheDoorbellThenKeepalives(t *testing.T) {
	s := NewServer(Config{Keepalive: 50 * time.Millisecond}, nil, logger.NewNop())
	s.Attach(&fakeV2{status: 200}, noHints{}, sameAuth{})
	id := tenantSensor()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := serve(t, s, &id).Subscribe(ctx, connect.NewRequest(&sensorv3.SubscribeRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Receive() || st.Msg().GetKeepalive() || st.Msg().GetStatus() != "ok" {
		t.Fatalf("first: %+v %v", st.Msg(), st.Err())
	}
	if !st.Receive() || !st.Msg().GetKeepalive() {
		t.Fatalf("keepalive: %+v %v", st.Msg(), st.Err())
	}
}
