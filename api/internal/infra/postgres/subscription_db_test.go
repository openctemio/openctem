package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/subscription"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/licensekey"
	lkt "github.com/openctemio/openctem/api/pkg/licensekey/licensekeytest"
)

// The license store against Postgres: append-only history, one stored row
// per license id, high-water marks that only rise, revocations that are only
// added, and the service end to end (a row edited in the table grants
// nothing). Requires DATABASE_URL.
func TestSubscriptionRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	reset := func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM subscription_licenses`)
		_, _ = sqlDB.ExecContext(context.Background(), `UPDATE subscription_state SET keyset_high_water = 0,
			revoked_license_ids = '{}', revoked_key_ids = '{}', time_high_water = now() - interval '1 hour'`)
	}
	reset()
	t.Cleanup(reset)
	r := NewSubscriptionRepository(&DB{DB: sqlDB})

	st, err := r.State(ctx)
	if err != nil || st.InstallationID == "" {
		t.Fatalf("state %+v err %v", st, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	c := lkt.Claims(now)
	file := lkt.File(now, c)
	actor := shared.NewID()
	rec := subscription.Record{
		ID: shared.NewID(), LicenseID: c.ID, CustomerID: c.CustomerID, Type: c.Type, LicenseeName: c.Licensee.Name,
		IssuedAt: c.IssuedAt, NotBefore: c.NotBefore, ExpiresAt: c.ExpiresAt, GraceDays: 14, Entitlements: c.Entitlements,
		KeySetVersion: 3, SigningKeyID: lkt.DefaultKeySetKeyID(), File: file, Source: subscription.SourceUpload,
		AddedBy: &actor, AddedAt: now,
	}
	if err := r.Add(ctx, rec, 3, licensekey.Revocations{LicenseIDs: []string{"lic_OLD00001"}}); err != nil {
		t.Fatal(err)
	}
	dup := rec
	dup.ID = shared.NewID()
	if err := r.Add(ctx, dup, 3, licensekey.Revocations{}); !errors.Is(err, subscription.ErrAlreadyStored) {
		t.Fatalf("duplicate license id: %v", err)
	}
	// A lower key set and new revocations: the mark stays, revocations add up.
	other := rec
	other.ID, other.LicenseID = shared.NewID(), "lic_OTHER001"
	if err := r.Add(ctx, other, 2, licensekey.Revocations{LicenseIDs: []string{"lic_OLD00002", "lic_OLD00001"}, KeyIDs: []string{"SHA256:aa"}}); err != nil {
		t.Fatal(err)
	}
	st2, _ := r.State(ctx)
	if st2.KeySetHighWater != 3 || len(st2.Revoked.LicenseIDs) != 2 || len(st2.Revoked.KeyIDs) != 1 || st2.Version != st.Version+2 {
		t.Fatalf("state after adds: %+v", st2)
	}

	list, err := r.List(ctx, 10)
	if err != nil || len(list) != 2 {
		t.Fatalf("list %d err %v", len(list), err)
	}
	got := list[1]
	if got.LicenseID != c.ID || string(got.File) != string(file) || got.AddedBy == nil || *got.AddedBy != actor ||
		len(got.Entitlements) != len(limits.GrantKeys()) || got.KeySetVersion != 3 || got.RemovedAt != nil {
		t.Fatalf("round trip: %+v", got)
	}

	if err := r.Remove(ctx, rec.ID, &actor, now); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove(ctx, rec.ID, &actor, now); !errors.Is(err, subscription.ErrNotFound) {
		t.Fatalf("second remove: %v", err)
	}
	if err := r.Add(ctx, dup, 3, licensekey.Revocations{}); err != nil {
		t.Fatalf("re-add after removal: %v", err)
	}
	if list, _ = r.List(ctx, 10); len(list) != 3 {
		t.Fatalf("history kept %d rows", len(list))
	}

	future := now.Add(48 * time.Hour)
	if err := r.AdvanceTimeHighWater(ctx, future); err != nil {
		t.Fatal(err)
	}
	_ = r.AdvanceTimeHighWater(ctx, now.Add(-48*time.Hour))
	if st3, _ := r.State(ctx); !st3.TimeHighWater.Equal(future) {
		t.Fatalf("time high-water %s, want %s", st3.TimeHighWater, future)
	}

	// The table refuses an oversized file and unknown sources.
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO subscription_licenses (license_id, customer_id, license_type,
		licensee_name, issued_at, not_before, expires_at, grace_days, keyset_version, signing_key_id, file, source)
		VALUES ('lic_X', 'cus_X', 'enterprise', 'x', now(), now(), now() + interval '1 day', 0, 1, 'k', $1, 'email')`, []byte("x")); err == nil {
		t.Fatal("unknown source accepted")
	}
}

// End to end: a row whose file was edited in the database is ignored.
func TestSubscriptionEditedRowGrantsNothing(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	reset := func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM subscription_licenses`)
		_, _ = sqlDB.ExecContext(context.Background(), `UPDATE subscription_state SET keyset_high_water = 0,
			revoked_license_ids = '{}', revoked_key_ids = '{}', time_high_water = now() - interval '1 hour'`)
	}
	reset()
	t.Cleanup(reset)
	svc := subscription.NewService(NewSubscriptionRepository(&DB{DB: sqlDB}), lkt.Verifier(), nil)
	now := time.Now()
	if _, err := svc.Activate(ctx, lkt.File(now, lkt.Claims(now)), subscription.SourceUpload, nil); err != nil {
		t.Fatal(err)
	}
	if !svc.Has(ctx, limits.GrantAIWorker) {
		t.Fatal("not granted after activation")
	}
	// Push the expiry out by editing the stored file's bytes.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE subscription_licenses SET file = overlay(file placing 'X'::bytea from 200 for 1),
		expires_at = expires_at + interval '10 years'`); err != nil {
		t.Fatal(err)
	}
	fresh := subscription.NewService(NewSubscriptionRepository(&DB{DB: sqlDB}), lkt.Verifier(), nil)
	st, err := fresh.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Has(ctx, limits.GrantAIWorker) || st.Invalid != 1 {
		t.Fatalf("edited row: state %s invalid %d", st.State, st.Invalid)
	}
}
