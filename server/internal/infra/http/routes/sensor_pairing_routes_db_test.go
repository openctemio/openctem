package routes

// The sensor plane of pairing through the real routes (RFC-052 §4.3–4.4):
// signatures by the key in the body, replay, clock skew, the start budgets
// (per address, per code), uniform 404
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
	"time"

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
	// The entry budget (every start per address) is lifted so this test
	// reaches the budgets of verified starts.
	defer func(b int) { pairingStartPerIPBurst = b }(pairingStartPerIPBurst)
	pairingStartPerIPBurst = 50
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
	// Replay of the same signed request: 401 (nonce spent).
	replay, _ := http.NewRequestWithContext(context.Background(), "POST", srv.URL+"/api/v2/sensor/pairings", bytes.NewReader(startBody(a)))
	replay.Header = req.Header.Clone()
	rres, err := http.DefaultClient.Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	if c := code(rres); c != http.StatusUnauthorized {
		t.Fatalf("replayed start: %d", c)
	}
	created := []string{started.PairingID}
	startWith := func(pairingCode string) (int, string) {
		k := newKey(0)
		b, _ := json.Marshal(pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(k.signer.PublicKey()),
			Commitment: pairing.Encode(pairing.Commit(bytes.Repeat([]byte{7}, 32))), Code: pairingCode, Host: pairing.HostFacts{Hostname: "h"}})
		res, _ := send("POST", "/api/v2/sensor/pairings", b, k.signer)
		var sr pairing.StartResponse
		raw, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if json.Unmarshal(raw, &sr) == nil && sr.PairingID != "" {
			created = append(created, sr.PairingID)
		}
		return res.StatusCode, string(raw)
	}
	// The three refused starts above (unsigned, wrong key, replay) did not
	// spend the per-address budget of verified starts (burst 3): two more
	// codeless starts are accepted, the next one is 429.
	for i := range 2 {
		if c, body := startWith(""); c != http.StatusCreated {
			t.Fatalf("codeless start %d after refused ones: %d %s", i+2, c, body)
		}
	}
	if c, _ := startWith(""); c != http.StatusTooManyRequests {
		t.Fatalf("codeless start beyond the per-address burst: %d", c)
	}
	// A start with a code is budgeted by the code: accepted from the same
	// address, with the same answer whether or not the code is open, up to
	// the per-code bound.
	for i := range 3 {
		if c, body := startWith("K7QM-4ZTD"); c != http.StatusCreated {
			t.Fatalf("start %d with a code after the codeless budget: %d %s", i+1, c, body)
		}
	}
	if c, _ := startWith("K7QM-4ZTD"); c != http.StatusTooManyRequests {
		t.Fatalf("start beyond the per-code bound: %d", c)
	}
	// A start on a clock 4 h ahead, signed by the key in its body, is the
	// clock-skew problem with the server time and the offset.
	sk := newKey(0)
	sk.signer.Now = func() time.Time { return time.Now().Add(4 * time.Hour) }
	res, _ = send("POST", "/api/v2/sensor/pairings", startBody(sk), sk.signer)
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(string(raw), "/clock-skew") ||
		!strings.Contains(string(raw), `"server_time"`) || !strings.Contains(string(raw), `"clock_offset_seconds":14`) {
		t.Fatalf("skewed start: %d %s", res.StatusCode, raw)
	}
	defer func() {
		for _, id := range created {
			_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM sensor_pairings WHERE id = $1`, id)
		}
	}()

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
}
