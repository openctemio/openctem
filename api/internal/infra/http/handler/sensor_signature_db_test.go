package handler

// The v1 and v2 sensor authenticators against a migrated database (RFC-052
// §4.3): a key-bound sensor's signed request passes, its tenant reaches the
// context, a replay or a bearer key does not, and a disabled key-bound sensor
// only reaches the heartbeat.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

func TestSignedSensorAuth_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = sqldb.Close() }()
	if err := sqldb.Ping(); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqldb.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	tid, sid := shared.NewID(), shared.NewID()
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'signed auth IT', $2)`, tid.String(), "sig-"+tid.String())
	t.Cleanup(func() {
		_, _ = sqldb.ExecContext(ctx, `DELETE FROM sensors WHERE tenant_id = $1`, tid.String())
		_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tid.String())
	})
	exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, max_concurrent_jobs, auth_kind)
	      VALUES ($1, $2, 'kb', 'worker', 'active', 'unknown', 'daemon', $3, '', 5, 'key_bound')`,
		sid.String(), tid.String(), sensordom.KeyBoundHashPlaceholder())
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32))
	signer, _ := sensorsig.NewSigner(key)
	exec(`INSERT INTO sensor_keys (tenant_id, sensor_id, thumbprint, public_key, status) VALUES ($1, $2, $3, $4, 'active')`,
		tid.String(), sid.String(), signer.KeyID(), []byte(signer.PublicKey()))

	db := &postgres.DB{DB: sqldb}
	svc := app.NewSensorService(postgres.NewSensorRepository(db), nil, logger.NewNop())
	svc.SetSigningKeyRepository(postgres.NewSensorSigningKeyRepository(db))

	var gotTenant string
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant, _ = r.Context().Value(middleware.TenantIDKey).(string)
		w.WriteHeader(http.StatusNoContent)
	})
	v2 := NewSensorResultsV2Handler(nil, svc, logger.NewNop()).Authenticate(ok)
	v1 := NewIngestHandler(nil, svc, logger.NewNop()).AuthenticateSource(ok)

	do := func(h http.Handler, r *http.Request) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	sign := func(method, path, body string) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if err := signer.Sign(r, []byte(body)); err != nil {
			t.Fatal(err)
		}
		return r
	}

	r := sign(http.MethodPost, "/api/v2/sensor/heartbeat", `{"status":"online"}`)
	if code := do(v2, r); code != http.StatusNoContent || gotTenant != tid.String() {
		t.Fatalf("v2 signed: %d tenant=%q", code, gotTenant)
	}
	replay := httptest.NewRequest(http.MethodPost, "/api/v2/sensor/heartbeat", strings.NewReader(`{"status":"online"}`))
	replay.Header = r.Header.Clone()
	if code := do(v2, replay); code != http.StatusUnauthorized {
		t.Fatalf("v2 replay: %d", code)
	}
	if code := do(v1, sign(http.MethodGet, "/api/v1/agent/commands", "")); code != http.StatusNoContent {
		t.Fatalf("v1 signed: %d", code)
	}

	// The placeholder hash is no bearer key.
	var hash string
	_ = sqldb.QueryRowContext(ctx, `SELECT api_key_hash FROM sensors WHERE id = $1`, sid.String()).Scan(&hash)
	bearer := httptest.NewRequest(http.MethodGet, "/api/v2/sensor/hello", nil)
	bearer.Header.Set("Authorization", "Bearer "+hash)
	if code := do(v2, bearer); code != http.StatusUnauthorized {
		t.Fatalf("bearer for a key-bound sensor: %d", code)
	}

	// Disabled: heartbeat only.
	exec(`UPDATE sensors SET status = 'disabled' WHERE id = $1`, sid.String())
	if code := do(v2, sign(http.MethodGet, "/api/v2/sensor/commands", "")); code != http.StatusUnauthorized {
		t.Fatalf("disabled sensor polled: %d", code)
	}
	if code := do(v2, sign(http.MethodPost, "/api/v2/sensor/heartbeat", `{}`)); code != http.StatusNoContent {
		t.Fatalf("disabled sensor heartbeat: %d", code)
	}
	// Revoked key: nothing.
	exec(`UPDATE sensors SET status = 'active' WHERE id = $1`, sid.String())
	exec(`UPDATE sensor_keys SET status = 'revoked', revoked_at = NOW() WHERE sensor_id = $1`, sid.String())
	if code := do(v2, sign(http.MethodPost, "/api/v2/sensor/heartbeat", `{}`)); code != http.StatusUnauthorized {
		t.Fatalf("revoked key: %d", code)
	}
}
