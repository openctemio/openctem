package routes

// A sensor that starts pairing again with the key it kept (restarted before
// approval) gets a new request, not a 500; a key that was already registered
// to a sensor gets a 409 with a type it can act on.

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
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

func TestSensorPairingRoutes_RestartWithSameKey_DB(t *testing.T) {
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
	ctx := context.Background()
	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	sensorRepo := postgres.NewSensorRepository(db)
	sensors := sensorapp.NewSensorService(sensorRepo, nil, log)
	svc, err := sensorpairing.NewService(postgres.NewSensorPairingRepository(db), sensorRepo,
		"0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0", "route-restart-pepper", log)
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

	start := func(signer *sensorsig.Signer, nonce byte) (int, string) {
		t.Helper()
		body, _ := json.Marshal(pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(signer.PublicKey()),
			Commitment: pairing.Encode(pairing.Commit(bytes.Repeat([]byte{nonce}, 32))), Host: pairing.HostFacts{Hostname: "io-sensor"}})
		req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/api/v2/sensor/pairings", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if err := signer.Sign(req, body); err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		return res.StatusCode, string(raw)
	}

	// Restarted before approval: the second start is a new request.
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := sensorsig.NewSigner(k)
	t.Cleanup(func() {
		_, _ = sqldb.ExecContext(ctx, `DELETE FROM sensor_pairings WHERE thumbprint = $1`, signer.KeyID())
	})
	var first, second pairing.StartResponse
	c, body := start(signer, 1)
	if c != http.StatusCreated || json.Unmarshal([]byte(body), &first) != nil {
		t.Fatalf("first start: %d %s", c, body)
	}
	c, body = start(signer, 2)
	if c != http.StatusCreated || json.Unmarshal([]byte(body), &second) != nil {
		t.Fatalf("restart with the same key: %d %s", c, body)
	}
	if second.PairingID == first.PairingID || second.UserCode == first.UserCode {
		t.Fatalf("restart reused the old request: %+v", second)
	}

	// A key already registered to a sensor: 409 pairing-key-registered.
	tid, sid := shared.NewID(), shared.NewID()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqldb.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'pairing restart', $2)`, tid.String(), "prs-"+tid.String())
	t.Cleanup(func() {
		_, _ = sqldb.ExecContext(ctx, `DELETE FROM sensors WHERE tenant_id = $1`, tid.String())
		_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tid.String())
	})
	exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, max_concurrent_jobs, auth_kind)
	      VALUES ($1, $2, 'kb', 'worker', 'active', 'unknown', 'daemon', $3, '', 5, 'key_bound')`,
		sid.String(), tid.String(), sensordom.KeyBoundHashPlaceholder())
	_, rk, _ := ed25519.GenerateKey(rand.Reader)
	registered, _ := sensorsig.NewSigner(rk)
	// Revoked: a thumbprint is never reused, whatever became of the key.
	exec(`INSERT INTO sensor_keys (tenant_id, sensor_id, thumbprint, public_key, status, revoked_at)
	      VALUES ($1, $2, $3, $4, 'revoked', NOW())`,
		tid.String(), sid.String(), registered.KeyID(), []byte(registered.PublicKey()))
	c, body = start(registered, 3)
	if c != http.StatusConflict || !strings.Contains(body, protov2.ProblemPairingKeyRegistered.URI()) {
		t.Fatalf("registered key: %d %s", c, body)
	}
	if strings.Contains(body, registered.KeyID()) || strings.Contains(body, tid.String()) || strings.Contains(body, sid.String()) {
		t.Fatalf("the refusal names the key, tenant or sensor: %s", body)
	}
}
