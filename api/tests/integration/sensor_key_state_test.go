package integration

// A sensor that renewed its key under rotation overlap authenticates with a
// sensor_api_keys row, while the inline key columns on the sensors row keep
// the retired bootstrap key (its key_expires_at is the end of the renewal
// grace). The sensor's key state used to be read from those inline columns,
// so on live a sensor heartbeating 21 seconds earlier showed "API key expired"
// (critical, Degraded) for hours, and dispatch would have refused it.
//
// These tests drive the real renewal path against a migrated database.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type keyStateFixture struct {
	t        *testing.T
	ctx      context.Context
	db       *sql.DB
	tenantID string
	repo     *postgres.SensorRepository
	keys     *postgres.SensorAPIKeyRepository
	svc      *sensorapp.SensorService
}

func newKeyStateFixture(t *testing.T) *keyStateFixture {
	t.Helper()
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping sensor key state DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("database not available: %v", err)
	}
	f := &keyStateFixture{t: t, ctx: context.Background(), db: db, tenantID: uuid.NewString()}
	if _, err := db.ExecContext(f.ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'Key state IT', $2)`,
		f.tenantID, "keystate-"+strings.ReplaceAll(f.tenantID[:13], "-", "")); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM sensors WHERE tenant_id = $1`, f.tenantID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, f.tenantID)
		_ = db.Close()
	})
	pdb := &postgres.DB{DB: db}
	f.repo = postgres.NewSensorRepository(pdb)
	f.keys = postgres.NewSensorAPIKeyRepository(pdb)
	f.svc = sensorapp.NewSensorService(f.repo, nil, logger.NewNop())
	f.svc.SetAPIKeyRepository(f.keys)
	f.svc.SetKeyTTL(90 * 24 * time.Hour)
	return f
}

// createRenewedSensor creates a daemon sensor, renews its key (rotation
// overlap) and returns the sensor and the renewed key.
func (f *keyStateFixture) createRenewedSensor(name string) (*sensor.Sensor, string, *time.Time) {
	f.t.Helper()
	out, err := f.svc.CreateSensor(f.ctx, sensorapp.CreateSensorInput{
		TenantID: f.tenantID, Name: name, Type: "worker", ExecutionMode: "daemon",
	})
	if err != nil {
		f.t.Fatalf("create sensor: %v", err)
	}
	ident, err := f.svc.AuthenticateIdentity(f.ctx, out.APIKey)
	if err != nil {
		f.t.Fatalf("authenticate: %v", err)
	}
	newKey, exp, err := f.svc.RenewAPIKey(f.ctx, ident)
	if err != nil {
		f.t.Fatalf("renew: %v", err)
	}
	if exp == nil {
		f.t.Fatal("renewal with a key TTL returned no expiry")
	}
	return out.Sensor, newKey, exp
}

func (f *keyStateFixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.db.ExecContext(f.ctx, q, args...); err != nil {
		f.t.Fatalf("exec: %v\n%s", err, q)
	}
}

func (f *keyStateFixture) reload(id string) *sensor.Sensor {
	f.t.Helper()
	s, err := f.svc.GetSensor(f.ctx, f.tenantID, id)
	if err != nil {
		f.t.Fatalf("get sensor: %v", err)
	}
	return s
}

func keyReasons(a sensor.HealthAssessment) []sensor.HealthReasonCode {
	var out []sensor.HealthReasonCode
	for _, r := range a.Reasons {
		if r.Code == sensor.ReasonKeyExpired || r.Code == sensor.ReasonKeyExpiring {
			out = append(out, r.Code)
		}
	}
	return out
}

func TestSensorKeyState_AfterRenewalGraceNoExpiryWarning(t *testing.T) {
	f := newKeyStateFixture(t)
	s, newKey, exp := f.createRenewedSensor("renewed-sensor")

	// The live situation: the renewal grace ended hours ago, so the inline
	// (bootstrap) key is expired, while the renewed key is valid for months.
	f.exec(`UPDATE sensors SET key_expires_at = NOW() - INTERVAL '7 hours', health = 'online', last_seen_at = NOW() - INTERVAL '21 seconds' WHERE id = $1`, s.ID.String())

	got := f.reload(s.ID.String())
	ks := got.KeyState()
	if !ks.Rotating || ks.ExpiresAt == nil || ks.ExpiresAt.Sub(*exp).Abs() > time.Second {
		t.Fatalf("KeyState = %+v, want the renewed key expiring %v", ks, exp)
	}
	if !strings.HasPrefix(newKey, ks.Prefix) {
		t.Fatalf("KeyState prefix %q is not the renewed key's", ks.Prefix)
	}
	if got.InlineKeyPrefix == ks.Prefix {
		t.Fatal("test is not exercising the bug: inline and rotating prefixes are equal")
	}

	a := got.AssessHealth(time.Now(), sensor.HealthPolicy{}.Normalized())
	if r := keyReasons(a); len(r) != 0 {
		t.Fatalf("renewed sensor reports %v; its key is valid until %v", r, exp)
	}

	// The renewed key still authenticates, and the retired inline key does not.
	if _, err := f.svc.AuthenticateByAPIKey(f.ctx, newKey); err != nil {
		t.Fatalf("renewed key no longer authenticates: %v", err)
	}
}

func TestSensorKeyState_TrulyExpiredActiveKeyWarns(t *testing.T) {
	f := newKeyStateFixture(t)
	s, _, _ := f.createRenewedSensor("expired-sensor")
	f.exec(`UPDATE sensors SET key_expires_at = NOW() - INTERVAL '30 days' WHERE id = $1`, s.ID.String())
	f.exec(`UPDATE sensor_api_keys SET expires_at = NOW() - INTERVAL '1 hour' WHERE sensor_id = $1`, s.ID.String())

	a := f.reload(s.ID.String()).AssessHealth(time.Now(), sensor.HealthPolicy{}.Normalized())
	if r := keyReasons(a); len(r) != 1 || r[0] != sensor.ReasonKeyExpired {
		t.Fatalf("key reasons = %v, want [key_expired]", r)
	}
}

func TestSensorKeyState_GraceWindowUsesLatestKey(t *testing.T) {
	f := newKeyStateFixture(t)
	s, _, _ := f.createRenewedSensor("grace-sensor")
	// A second overlap key that expires sooner (the superseded one during
	// grace): the state must follow the latest expiry, not the newest row.
	f.exec(`INSERT INTO sensor_api_keys (sensor_id, name, key_hash, key_prefix, expires_at, created_at)
		VALUES ($1, 'older', $2, 'rda_olderkey', NOW() + INTERVAL '10 minutes', NOW() + INTERVAL '1 second')`,
		s.ID.String(), strings.Repeat("e", 64))

	ks := f.reload(s.ID.String()).KeyState()
	if ks.Prefix == "rda_olderkey" {
		t.Fatalf("KeyState picked the key that expires in 10 minutes: %+v", ks)
	}
	if ks.ExpiresAt == nil || time.Until(*ks.ExpiresAt) < 24*time.Hour {
		t.Fatalf("KeyState = %+v, want the long-lived renewed key", ks)
	}
}

func TestSensorKeyState_RevokedKeysFallBackToInline(t *testing.T) {
	f := newKeyStateFixture(t)
	s, _, _ := f.createRenewedSensor("regenerated-sensor")
	// Admin regeneration revokes every rotating key and writes a fresh inline key.
	if _, err := f.svc.RegenerateAPIKey(f.ctx, f.tenantID, s.ID.String(), nil); err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	got := f.reload(s.ID.String())
	ks := got.KeyState()
	if ks.Rotating || ks.Prefix != got.InlineKeyPrefix {
		t.Fatalf("after regeneration KeyState = %+v, want the inline key %q", ks, got.InlineKeyPrefix)
	}
}
