package routes

// Self-binding of a signing key by a bearer-key sensor
// (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md §4.8), end to end
// on the v2 routes against a scratch database. Asserts: the bind makes the
// same sensor key-bound (signed requests work, its API key is dead, one
// way), the proof of possession is required, a second or concurrent bind
// loses, a paused sensor and an organization that requires approval are
// refused, and nothing names another tenant (the tenant comes from the key).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

func newKeyBindHarness(t *testing.T) *ctlHarness {
	t.Helper()
	h := newCtlHarness(t)
	db := &postgres.DB{DB: h.db}
	h.sensors.SetSigningKeyRepository(postgres.NewSensorSigningKeyRepository(db))
	h.sensors.SetIdentityPolicyRepository(postgres.NewSensorIdentityPolicyRepository(db))
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM sensor_keys WHERE tenant_id = $1`, h.tenantID)
	})
	allowBearer(t, h, h.tenantID)
	return h
}

// allowBearer lets tenantID create bearer-key sensors (new organizations
// require pairing).
func allowBearer(t *testing.T, h *ctlHarness, tenantID string) {
	t.Helper()
	if _, err := h.db.Exec(`UPDATE tenants SET sensor_bearer_keys_allowed = TRUE WHERE id = $1`, tenantID); err != nil {
		t.Fatal(err)
	}
}

// bindRequest is a valid bind of key at now (proof by key itself).
func bindRequest(key ed25519.PrivateKey, at time.Time) protov2.KeyBindRequest {
	pub := key.Public().(ed25519.PublicKey)
	ts := at.UTC().Format(time.RFC3339)
	sig := ed25519.Sign(key, sensor.KeyBindProofMessage(sensorsig.Thumbprint(pub), ts))
	return protov2.KeyBindRequest{PublicKey: base64.RawURLEncoding.EncodeToString(pub), IssuedAt: ts,
		Proof: base64.RawURLEncoding.EncodeToString(sig)}
}

func newEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// signedCall makes a request signed by key (RFC 9421), no bearer key.
func (h *ctlHarness) signedCall(key ed25519.PrivateKey, method, path string) *http.Response {
	h.t.Helper()
	signer, err := sensorsig.NewSigner(key)
	if err != nil {
		h.t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, bytes.NewReader(nil))
	req.Header.Set("User-Agent", "openctem-sdk-go/0.20.0 (openctemio-sensor/0.13.0)")
	hc := &http.Client{Transport: &sensorsig.Transport{Signer: signer, Base: h.srv.Client().Transport}}
	resp, err := hc.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}

const bindPath = protov2.PathPrefix + protov2.IdentityBindPath

func TestSensorKeyBind_BearerSensorBecomesKeyBound(t *testing.T) {
	h := newKeyBindHarness(t)
	s := h.newSensor(h.tenantID, "bind-me")
	key := newEd25519(t)

	resp, raw := h.call(s.key, http.MethodPost, bindPath, bindRequest(key, time.Now()))
	h.want(resp, raw, http.StatusCreated, "")
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", resp.Header.Get("Cache-Control"))
	}
	got := decodeAs[protov2.KeyBindResponse](t, raw)
	thumb := sensorsig.Thumbprint(key.Public().(ed25519.PublicKey))
	if got.SensorID != s.id || got.TenantID != h.tenantID || got.KeyID != thumb {
		t.Fatalf("bind answered %+v, want sensor %s tenant %s key %s", got, s.id, h.tenantID, thumb)
	}
	// Same sensor, now key-bound: a signed request works...
	if r := h.signedCall(key, http.MethodPost, "/api/v2/sensor/heartbeat"); r.StatusCode != http.StatusOK {
		t.Fatalf("signed heartbeat after the bind: %d", r.StatusCode)
	}
	// ...and the API key is dead (one way).
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/heartbeat", nil)
	h.want(resp, raw, http.StatusUnauthorized, ingestProblem("unauthenticated"))
	var kind string
	var grantKept bool
	if err := h.db.QueryRow(`SELECT auth_kind FROM sensors WHERE id = $1 AND tenant_id = $2`, s.id, h.tenantID).Scan(&kind); err != nil || kind != "key_bound" {
		t.Fatalf("auth_kind %q (%v)", kind, err)
	}
	if err := h.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM sensor_keys WHERE sensor_id = $1 AND tenant_id = $2 AND thumbprint = $3 AND status = 'active')`,
		s.id, h.tenantID, thumb).Scan(&grantKept); err != nil || !grantKept {
		t.Fatalf("the bound key is not the sensor's active key (%v)", err)
	}
	// A key-bound sensor never binds again (signed, so authenticated).
	if r := h.signedCall(key, http.MethodPost, bindPath); r.StatusCode == http.StatusCreated {
		t.Fatal("a key-bound sensor bound again")
	}
}

func TestSensorKeyBind_ProofIsRequired(t *testing.T) {
	h := newKeyBindHarness(t)
	s := h.newSensor(h.tenantID, "proof")
	key, other := newEd25519(t), newEd25519(t)

	// Signed by another key than the one bound.
	forged := bindRequest(other, time.Now())
	forged.PublicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	stale := bindRequest(key, time.Now().Add(-time.Hour))
	future := bindRequest(key, time.Now().Add(time.Hour))
	short := bindRequest(key, time.Now())
	short.PublicKey = base64.RawURLEncoding.EncodeToString([]byte("short"))
	for name, req := range map[string]protov2.KeyBindRequest{"forged": forged, "stale": stale, "future": future, "short key": short} {
		resp, raw := h.call(s.key, http.MethodPost, bindPath, req)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("%s proof: %d %s", name, resp.StatusCode, raw)
		}
		h.want(resp, raw, http.StatusConflict, sensorProblem(string(protov2.ProblemKeyBindRefused)))
	}
	resp, raw := h.call(s.key, http.MethodPost, bindPath, []byte(`{"public_key":"%%%","proof":"x","issued_at":"x"}`))
	h.want(resp, raw, http.StatusConflict, sensorProblem(string(protov2.ProblemKeyBindRefused)))
	// Nothing changed: the API key still works.
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/heartbeat", nil)
	h.want(resp, raw, http.StatusOK, "")
}

func TestSensorKeyBind_ConcurrentBindsOneWins(t *testing.T) {
	h := newKeyBindHarness(t)
	s := h.newSensor(h.tenantID, "race")
	const n = 4
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _ := h.call(s.key, http.MethodPost, bindPath, bindRequest(newEd25519(t), time.Now()))
			codes[i] = resp.StatusCode
		}()
	}
	wg.Wait()
	won := 0
	for _, c := range codes {
		if c == http.StatusCreated {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("binds answered %v: exactly one must win", codes)
	}
	var keys int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM sensor_keys WHERE sensor_id = $1 AND status = 'active'`, s.id).Scan(&keys); err != nil || keys != 1 {
		t.Fatalf("active keys %d (%v), want 1", keys, err)
	}
}

func TestSensorKeyBind_KeyOfAnotherSensorAndTenant(t *testing.T) {
	h := newKeyBindHarness(t)
	otherTenant := h.newTenant()
	allowBearer(t, h, otherTenant)
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM sensor_keys WHERE tenant_id = $1`, otherTenant)
	})
	a := h.newSensor(h.tenantID, "a")
	b := h.newSensor(otherTenant, "b")
	key := newEd25519(t)
	resp, raw := h.call(a.key, http.MethodPost, bindPath, bindRequest(key, time.Now()))
	h.want(resp, raw, http.StatusCreated, "")
	// Tenant B's sensor presenting tenant A's key: refused (a thumbprint is
	// never registered twice); B keeps its own key and tenant.
	resp, raw = h.call(b.key, http.MethodPost, bindPath, bindRequest(key, time.Now()))
	h.want(resp, raw, http.StatusConflict, sensorProblem(string(protov2.ProblemKeyBindRefused)))
	resp, raw = h.call(b.key, http.MethodPost, "/api/v2/sensor/heartbeat", nil)
	h.want(resp, raw, http.StatusOK, "")
	var kind string
	if err := h.db.QueryRow(`SELECT auth_kind FROM sensors WHERE id = $1`, b.id).Scan(&kind); err != nil || kind == "key_bound" {
		t.Fatalf("tenant B's sensor changed: %q (%v)", kind, err)
	}
	// The bound key belongs to tenant A's sensor only.
	var tid string
	if err := h.db.QueryRow(`SELECT tenant_id FROM sensor_keys WHERE sensor_id = $1 AND status = 'active'`, a.id).Scan(&tid); err != nil || tid != h.tenantID {
		t.Fatalf("bound key in tenant %q (%v), want %s", tid, err, h.tenantID)
	}
}

func TestSensorKeyBind_PolicyAndState(t *testing.T) {
	h := newKeyBindHarness(t)

	// The organization requires approval: refused, the API key keeps working.
	s := h.newSensor(h.tenantID, "approval")
	if _, err := h.db.Exec(`UPDATE tenants SET sensor_key_bind_requires_approval = TRUE WHERE id = $1`, h.tenantID); err != nil {
		t.Fatal(err)
	}
	resp, raw := h.call(s.key, http.MethodPost, bindPath, bindRequest(newEd25519(t), time.Now()))
	h.want(resp, raw, http.StatusForbidden, sensorProblem(string(protov2.ProblemKeyBindApproval)))
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/heartbeat", nil)
	h.want(resp, raw, http.StatusOK, "")
	if _, err := h.db.Exec(`UPDATE tenants SET sensor_key_bind_requires_approval = FALSE WHERE id = $1`, h.tenantID); err != nil {
		t.Fatal(err)
	}

	// A paused (disabled) sensor only reaches heartbeat and hello: no bind.
	p := h.newSensor(h.tenantID, "paused")
	if _, err := h.db.Exec(`UPDATE sensors SET status = 'disabled' WHERE id = $1`, p.id); err != nil {
		t.Fatal(err)
	}
	resp, _ = h.call(p.key, http.MethodPost, bindPath, bindRequest(newEd25519(t), time.Now()))
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("a disabled sensor bound a key")
	}
	// No key at all.
	resp, _ = h.call("", http.MethodPost, bindPath, bindRequest(newEd25519(t), time.Now()))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated bind: %d", resp.StatusCode)
	}
}
