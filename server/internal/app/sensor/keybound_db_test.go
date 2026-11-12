package sensor_test

// Key-bound identity against a migrated database (RFC-052 §4.3): a signed
// request resolves to its sensor only through an active key, the sensor's
// status applies, a key-bound sensor never authenticates or renews with a
// bearer key, and nonces are single use.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

// keyBoundSensor inserts a key-bound sensor with one key in status.
func (h *activityHarness) keyBoundSensor(tenantID shared.ID, seed byte, status string) (shared.ID, string) {
	h.t.Helper()
	id := shared.NewID()
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, max_concurrent_jobs, auth_kind)
	        VALUES ($1, $2, $3, 'worker', 'active', 'unknown', 'daemon', $4, '', 5, 'key_bound')`,
		id.String(), tenantID.String(), "kb-"+id.String()[:8], sensordom.KeyBoundHashPlaceholder())
	_ = seed
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	thumb := sensorsig.Thumbprint(pub)
	revokedAt := "NULL"
	if status == "revoked" {
		revokedAt = "NOW()"
	}
	h.exec(`INSERT INTO sensor_keys (tenant_id, sensor_id, thumbprint, public_key, status, revoked_at)
	        VALUES ($1, $2, $3, $4, $5, `+revokedAt+`)`, tenantID.String(), id.String(), thumb, []byte(pub), status)
	return id, thumb
}

func keyBoundService(h *activityHarness) *signingService {
	svc := newPepperedService(h, "")
	repo := postgres.NewSensorSigningKeyRepository(&postgres.DB{DB: h.db})
	svc.SetSigningKeyRepository(repo)
	return &signingService{svc: svc, repo: repo}
}

func TestKeyBound_SigningIdentity_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	ctx := context.Background()
	s := keyBoundService(h)

	active, activeThumb := h.keyBoundSensor(tid, 1, "active")
	_, pendingThumb := h.keyBoundSensor(tid, 2, "pending")
	_, revokedThumb := h.keyBoundSensor(tid, 3, "revoked")

	id, pub, err := s.svc.SigningIdentity(ctx, activeThumb, true)
	if err != nil || id.Sensor == nil || id.Sensor.ID != active || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("active key: %v", err)
	}
	if !id.KeyBound() || !id.Sensor.KeyBound() {
		t.Fatal("identity must be key-bound")
	}
	// An unknown thumbprint differs from the active one in its first character
	// (a fixed "x" would equal it when the random thumbprint starts with "x").
	unknownThumb := "x" + activeThumb[1:]
	if activeThumb[0] == 'x' {
		unknownThumb = "y" + activeThumb[1:]
	}
	for name, thumb := range map[string]string{"pending": pendingThumb, "revoked": revokedThumb, "unknown": unknownThumb} {
		if _, _, err := s.svc.SigningIdentity(ctx, thumb, true); err == nil {
			t.Errorf("%s key authenticated", name)
		}
	}

	// The sensor's status applies: disabled is paused (heartbeat only),
	// revoked is refused.
	h.exec(`UPDATE sensors SET status = 'disabled' WHERE id = $1`, active.String())
	if id, _, err := s.svc.SigningIdentity(ctx, activeThumb, true); err != nil || !id.Paused {
		t.Fatalf("disabled sensor: paused=%v err=%v", id.Paused, err)
	}
	if _, _, err := s.svc.SigningIdentity(ctx, activeThumb, false); err == nil {
		t.Fatal("disabled sensor must be refused when paused is not allowed")
	}
	h.exec(`UPDATE sensors SET status = 'revoked' WHERE id = $1`, active.String())
	if _, _, err := s.svc.SigningIdentity(ctx, activeThumb, true); err == nil {
		t.Fatal("revoked sensor authenticated")
	}

	// Revoking the key stops it at once.
	h.exec(`UPDATE sensors SET status = 'active' WHERE id = $1`, active.String())
	keys, err := s.repo.ListBySensor(ctx, tid, active)
	if err != nil || len(keys) != 1 {
		t.Fatalf("list keys: %d %v", len(keys), err)
	}
	other := h.tenant()
	if ok, _ := s.repo.Revoke(ctx, other, active, keys[0].ID, sensordom.KeyRevokedAdmin, keys[0].CreatedAt); ok {
		t.Fatal("another tenant revoked the key")
	}
	if ok, err := s.repo.Revoke(ctx, tid, active, keys[0].ID, sensordom.KeyRevokedAdmin, keys[0].CreatedAt); !ok || err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, err := s.svc.SigningIdentity(ctx, activeThumb, true); err == nil {
		t.Fatal("revoked key authenticated")
	}
}

func TestKeyBound_BearerRefused_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	ctx := context.Background()
	s := keyBoundService(h)

	// A key row on a sensor that is not key-bound authenticates nothing
	// (auth_kind is the authority).
	bearer := h.sensor(tid)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	thumb := sensorsig.Thumbprint(pub)
	h.exec(`INSERT INTO sensor_keys (tenant_id, sensor_id, thumbprint, public_key, status) VALUES ($1, $2, $3, $4, 'active')`,
		tid.String(), bearer.String(), thumb, []byte(pub))
	if _, _, err := s.svc.SigningIdentity(ctx, thumb, true); err == nil {
		t.Fatal("a bearer sensor authenticated with a signing key")
	}

	// A key-bound sensor cannot renew into a bearer key.
	kb, kbThumb := h.keyBoundSensor(tid, 10, "active")
	id, _, err := s.svc.SigningIdentity(ctx, kbThumb, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.svc.RenewAPIKey(ctx, id); err == nil {
		t.Fatal("a key-bound sensor got a bearer key")
	}
	// Its placeholder hash matches no presented key.
	var hash string
	if err := h.db.QueryRowContext(ctx, `SELECT api_key_hash FROM sensors WHERE id = $1`, kb.String()).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.svc.AuthenticateIdentity(ctx, hash); err == nil {
		t.Fatal("the placeholder authenticated as a bearer key")
	}
}

func TestKeyBound_NonceSingleUse_DB(t *testing.T) {
	h := newActivityHarness(t)
	s := keyBoundService(h)
	ctx := context.Background()
	if err := s.svc.UseNonce(ctx, "k", "nonce-nonce-nonce-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.svc.UseNonce(ctx, "k", "nonce-nonce-nonce-1"); err == nil {
		t.Fatal("a nonce was accepted twice")
	}
	if err := s.svc.UseNonce(ctx, "other", "nonce-nonce-nonce-1"); err != nil {
		t.Fatal("nonces are per key")
	}
}

type signingService struct {
	svc  *sensorapp.SensorService
	repo *postgres.SensorSigningKeyRepository
}
