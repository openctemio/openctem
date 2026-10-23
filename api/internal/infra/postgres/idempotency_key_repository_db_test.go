package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/idempotency"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A key is claimed once; while the first request runs a second claim sees
// it pending; once done it carries the answer; another tenant or principal
// has its own key; an expired key can be taken over, and the request that
// lost its claim can neither finish nor release the new one.
func TestIdempotencyKeys_Lifecycle_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewIdempotencyKeyRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	s, err := idempotency.NewScope(tenant, "user:u1", "POST /findings/imports", "retry-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idempotency.NewScope(tenant, "user:u1", "r", "bad key"); err == nil {
		t.Fatal("a key with a space was accepted")
	}

	c, existing, err := repo.Claim(ctx, s, time.Minute)
	if err != nil || c == nil || existing != nil {
		t.Fatalf("first claim: %v %v %v", c, existing, err)
	}
	c2, existing, err := repo.Claim(ctx, s, time.Minute)
	if err != nil || c2 != nil || existing == nil || existing.State != idempotency.StatePending {
		t.Fatalf("second claim while pending: %v %+v %v", c2, existing, err)
	}
	for _, sc := range []idempotency.Scope{
		{TenantID: other, Principal: s.Principal, Route: s.Route, KeyHash: s.KeyHash},
		{TenantID: tenant, Principal: "user:u2", Route: s.Route, KeyHash: s.KeyHash},
	} {
		if oc, _, err := repo.Claim(ctx, sc, time.Minute); err != nil || oc == nil {
			t.Fatalf("an independent key was not claimable: %+v %v", sc, err)
		}
	}
	receipt := shared.NewID()
	if err := repo.Complete(ctx, c, "fp-1", 201, []byte(`{"ok":true}`), &receipt); err != nil {
		t.Fatal(err)
	}
	_, existing, err = repo.Claim(ctx, s, time.Minute)
	if err != nil || existing == nil || existing.State != idempotency.StateDone || existing.RequestSHA256 != "fp-1" ||
		existing.Status != 201 || string(existing.Response) != `{"ok":true}` || existing.ReceiptID == nil || *existing.ReceiptID != receipt {
		t.Fatalf("done record = %+v, %v", existing, err)
	}

	// Expired: taken over; the old claim is dead.
	s2, _ := idempotency.NewScope(tenant, "user:u1", "POST /findings/imports", "slow-1")
	old, _, err := repo.Claim(ctx, s2, time.Minute)
	if err != nil || old == nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE idempotency_keys SET expires_at = now() - interval '1 second' WHERE tenant_id = $1 AND key_hash = $2`,
		tenant.String(), s2.KeyHash); err != nil {
		t.Fatal(err)
	}
	fresh, _, err := repo.Claim(ctx, s2, time.Minute)
	if err != nil || fresh == nil {
		t.Fatalf("expired key not taken over: %v", err)
	}
	if err := repo.Complete(ctx, old, "fp-old", 201, []byte(`{}`), nil); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a lost claim finished the key: %v", err)
	}
	if err := repo.Release(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, existing, _ := repo.Claim(ctx, s2, time.Minute); existing == nil || existing.State != idempotency.StatePending {
		t.Fatal("a lost claim released the new holder's key")
	}
	if err := repo.Release(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if again, _, err := repo.Claim(ctx, s2, time.Minute); err != nil || again == nil {
		t.Fatalf("a released key is not claimable: %v", err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE idempotency_keys SET expires_at = now() - interval '1 hour' WHERE tenant_id = $1`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	if n, err := repo.PurgeExpiredForPlatform(ctx, time.Now(), 1000); err != nil || n < 2 {
		t.Fatalf("purge = %d, %v", n, err)
	}
}
