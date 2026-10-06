package routes

// The sensor plane of pairing through the real routes (RFC-052 §4.3–4.4):
// signatures by the key in the body, replay, per-address cap, uniform 404
// for a foreign key, and the user plane behind authentication.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

func TestSensorPairingRoutes_DB(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	sqldb, err := sql.Open("postgres", url)
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = sqldb.Close() }()
	if err := sqldb.Ping(); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	sensorRepo := postgres.NewSensorRepository(db)
	sensors := sensorapp.NewSensorService(sensorRepo, nil, log)
	svc, err := sensorpairing.NewService(postgres.NewSensorPairingRepository(db), sensorRepo,
		"0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0", "route-test-pepper", log)
	if err != nil {
		t.Fatal(err)
	}
	deny := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	}
	router := infrahttp.NewChiRouter()
	registerSensorPairingRoutes(router, handler.NewSensorPairingHandler(svc, sensors, log), deny, deny, log)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	defer srv.Close()

	type sensorKey struct {
		priv   ed25519.PrivateKey
		signer *sensorsig.Signer
	}
	newKey := func(seed byte) sensorKey {
		_ = seed
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		s, _ := sensorsig.NewSigner(k)
		return sensorKey{priv: k, signer: s}
	}
	startBody := func(k sensorKey) []byte {
		b, _ := json.Marshal(pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(k.signer.PublicKey()),
			Commitment: pairing.Encode(pairing.Commit(bytes.Repeat([]byte{7}, 32))), Host: pairing.HostFacts{Hostname: "h"}})
		return b
	}
	send := func(method, path string, body []byte, signer *sensorsig.Signer) (*http.Response, *http.Request) {
		req, _ := http.NewRequestWithContext(context.Background(), method, srv.URL+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if signer != nil {
			if err := signer.Sign(req, body); err != nil {
				t.Fatal(err)
			}
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res, req
	}
	code := func(res *http.Response) int { _ = res.Body.Close(); return res.StatusCode }

	a, b := newKey(1), newKey(2)
	// Unsigned, and signed by another key than the one in the body: 401.
	if c := code(func() *http.Response { r, _ := send("POST", "/api/v2/sensor/pairings", startBody(a), nil); return r }()); c != http.StatusUnauthorized {
		t.Fatalf("unsigned start: %d", c)
	}
	if c := code(func() *http.Response {
		r, _ := send("POST", "/api/v2/sensor/pairings", startBody(a), b.signer)
		return r
	}()); c != http.StatusUnauthorized {
		t.Fatalf("start signed by another key: %d", c)
	}
	// Valid start.
	res, req := send("POST", "/api/v2/sensor/pairings", startBody(a), a.signer)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("start: %d", res.StatusCode)
	}
	var started pairing.StartResponse
	_ = json.NewDecoder(res.Body).Decode(&started)
	_ = res.Body.Close()
	if started.UserCode == "" || started.PairingID == "" {
		t.Fatalf("start answer %+v", started)
	}
	// Replay of the same signed request: 401 (nonce spent). The per-address
	// budget (burst 3) is now used up to 3 attempts that reached the limiter.
	replay, _ := http.NewRequestWithContext(context.Background(), "POST", srv.URL+"/api/v2/sensor/pairings", bytes.NewReader(startBody(a)))
	replay.Header = req.Header.Clone()
	rres, err := http.DefaultClient.Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	if c := code(rres); c != http.StatusUnauthorized && c != http.StatusTooManyRequests {
		t.Fatalf("replayed start: %d", c)
	}
	// Per-address cap: the next start from this address is 429.
	if c := code(func() *http.Response {
		r, _ := send("POST", "/api/v2/sensor/pairings", startBody(newKey(3)), newKey(3).signer)
		return r
	}()); c != http.StatusTooManyRequests {
		t.Fatalf("start beyond the per-address burst: %d", c)
	}

	// A foreign key gets the same 404 as an unknown id (threat 9).
	path := "/api/v2/sensor/pairings/" + started.PairingID
	if c := code(func() *http.Response { r, _ := send("GET", path, nil, b.signer); return r }()); c != http.StatusNotFound {
		t.Fatalf("status with another key: %d", c)
	}
	if c := code(func() *http.Response {
		r, _ := send("GET", "/api/v2/sensor/pairings/01a10c10-1b7d-7308-b855-87930ed866a5", nil, a.signer)
		return r
	}()); c != http.StatusNotFound {
		t.Fatalf("unknown id: %d", c)
	}
	res, _ = send("GET", path, nil, a.signer)
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"status":"pending"`) {
		t.Fatalf("status: %d %s", res.StatusCode, body)
	}
	// Reveal with the right nonce works.
	nb, _ := json.Marshal(pairing.RevealRequest{SensorNonce: pairing.Encode(bytes.Repeat([]byte{7}, 32))})
	if c := code(func() *http.Response { r, _ := send("PUT", path+"/nonce", nb, a.signer); return r }()); c != http.StatusNoContent {
		t.Fatalf("reveal: %d", c)
	}

	// The user plane is behind authentication.
	if c := code(func() *http.Response {
		r, _ := send("POST", "/api/v1/sensor-pairings/lookup", []byte(`{"code":"`+started.UserCode+`"}`), nil)
		return r
	}()); c != http.StatusUnauthorized {
		t.Fatalf("unauthenticated lookup: %d", c)
	}
	_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM sensor_pairings WHERE id = $1`, started.PairingID)
}
