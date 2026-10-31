package postgres

import (
	"context"
	"testing"
	"time"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// An expected pairing (code made by an admin, no sensor key yet) can be denied
// and can expire. Before migration sensor_pairings_key_check_closed_states the
// key check refused both: Deny failed, and one expired expectation rolled back
// the whole platform sweep, so no pairing ever expired again.
// Requires DATABASE_URL.
func TestSensorPairingRepository_ExpectationCloses(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	r := NewSensorPairingRepository(db)
	tenant := seedTenant(ctx, t, db)
	other := seedTenant(ctx, t, db)
	actor := seedUser(ctx, t, db)
	now := time.Now().UTC().Truncate(time.Microsecond)

	expect := func(expires time.Time) *sensordom.Pairing {
		t.Helper()
		p := &sensordom.Pairing{
			ID: shared.NewID(), TenantID: &tenant, CodeHash: "test-code-" + shared.NewID().String(),
			CreatedAt: now.Add(-time.Hour), ExpiresAt: expires,
		}
		if err := r.CreateExpectation(ctx, p); err != nil {
			t.Fatalf("create expectation: %v", err)
		}
		t.Cleanup(func() {
			_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM sensor_pairings WHERE id = $1`, p.ID.String())
		})
		return p
	}
	status := func(id shared.ID) string {
		t.Helper()
		var s string
		if err := sqlDB.QueryRowContext(ctx, `SELECT status FROM sensor_pairings WHERE id = $1`, id.String()).Scan(&s); err != nil {
			t.Fatalf("read status: %v", err)
		}
		return s
	}

	// Another tenant cannot deny it (no row, not an error that leaks it).
	open := expect(now.Add(10 * time.Minute))
	if p, err := r.Deny(ctx, other, open.ID, actor, "", now); err == nil && p != nil {
		t.Fatalf("a foreign tenant denied the expectation")
	}
	if got := status(open.ID); got != "expecting" {
		t.Fatalf("foreign deny changed the status to %q", got)
	}
	// Its own tenant can.
	if _, err := r.Deny(ctx, tenant, open.ID, actor, "", now); err != nil {
		t.Fatalf("deny an expected code: %v", err)
	}
	if got := status(open.ID); got != "denied" {
		t.Fatalf("status after deny = %q", got)
	}

	// The sweep expires an unused expectation instead of rolling back.
	stale := expect(now.Add(-time.Minute))
	if _, err := r.ExpireForPlatform(ctx, now, now.Add(-24*time.Hour)); err != nil {
		t.Fatalf("sweep with an expired expectation: %v", err)
	}
	if got := status(stale.ID); got != "expired" {
		t.Fatalf("status after sweep = %q", got)
	}

	// The open/key rule still holds for states that need a key.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE sensor_pairings SET status = 'pending' WHERE id = $1`, stale.ID.String()); err == nil {
		t.Fatalf("a pending pairing without a key was accepted")
	}
}
