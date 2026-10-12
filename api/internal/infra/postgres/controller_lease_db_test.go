package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Controller leases (RFC-046 P1.8) against the real SQL: one holder wins,
// every take bumps the epoch, expiry hands over, a lost lease cannot be
// renewed or released by its old holder.

func TestControllerLease_OneHolderEpochAndHandover(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewControllerLeaseRepository(&DB{DB: db})
	name := "test:" + shared.NewID().String()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM controller_leases WHERE name = $1`, name)
	})

	a, ok, err := repo.TryAcquire(ctx, name, "replica-a", time.Minute)
	if err != nil || !ok || a.Epoch != 1 {
		t.Fatalf("first take = %+v ok=%v err=%v, want epoch 1", a, ok, err)
	}
	if _, ok, err := repo.TryAcquire(ctx, name, "replica-b", time.Minute); err != nil || ok {
		t.Fatalf("second holder took a live lease: ok=%v err=%v", ok, err)
	}
	if held, err := repo.Renew(ctx, a, time.Minute); err != nil || !held {
		t.Fatalf("holder renew = %v, %v", held, err)
	}

	// The holder dies: its lease expires and another replica takes it.
	if _, err := db.ExecContext(ctx, `UPDATE controller_leases SET expires_at = NOW() - interval '1 second' WHERE name = $1`, name); err != nil {
		t.Fatal(err)
	}
	b, ok, err := repo.TryAcquire(ctx, name, "replica-b", time.Minute)
	if err != nil || !ok || b.Epoch != 2 {
		t.Fatalf("take after expiry = %+v ok=%v err=%v, want epoch 2", b, ok, err)
	}
	// The old holder comes back: it can neither renew nor release.
	if held, _ := repo.Renew(ctx, a, time.Minute); held {
		t.Fatal("the old holder renewed a lease another replica holds")
	}
	if err := repo.Release(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := repo.TryAcquire(ctx, name, "replica-c", time.Minute); ok {
		t.Fatal("the old holder's release freed the new holder's lease")
	}
	// The new holder releases: the next take is immediate, epoch 3.
	if err := repo.Release(ctx, b); err != nil {
		t.Fatal(err)
	}
	c, ok, err := repo.TryAcquire(ctx, name, "replica-c", time.Minute)
	if err != nil || !ok || c.Epoch != 3 {
		t.Fatalf("take after release = %+v ok=%v err=%v, want epoch 3", c, ok, err)
	}
}

func TestControllerLease_RaceHasOneWinner(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewControllerLeaseRepository(&DB{DB: db})
	name := "test-race:" + shared.NewID().String()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM controller_leases WHERE name = $1`, name)
	})

	const n = 8
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, ok, err := repo.TryAcquire(ctx, name, "replica-"+string(rune('a'+i)), time.Minute)
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d replicas took the lease, want exactly 1", wins)
	}
}

// The per-tenant sweep locks that replaced session advisory locks.
func TestControllerLease_TenantSweepLocks(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenant := seedScanTriggerTenant(ctx, t, db)
	ct := NewCTMonitorStateRepository(&DB{DB: db})
	dns := NewEASMDNSRepository(&DB{DB: db})

	release, ok, err := ct.TryLockTenant(ctx, tenant)
	if err != nil || !ok {
		t.Fatalf("ct lock: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := ct.TryLockTenant(ctx, tenant); ok {
		t.Fatal("a second ct sweep of the same tenant took the lock")
	}
	other := seedScanTriggerTenant(ctx, t, db)
	if r2, ok, _ := ct.TryLockTenant(ctx, other); !ok {
		t.Fatal("another tenant's ct sweep was blocked")
	} else {
		r2()
	}
	release()
	if r3, ok, _ := ct.TryLockTenant(ctx, tenant); !ok {
		t.Fatal("ct lock not free after release")
	} else {
		r3()
	}

	rd, ok, err := dns.TryLockTenant(ctx, tenant, "spf")
	if err != nil || !ok {
		t.Fatalf("dns lock: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := dns.TryLockTenant(ctx, tenant, "spf"); ok {
		t.Fatal("a second dns check of the same kind took the lock")
	}
	if r4, ok, _ := dns.TryLockTenant(ctx, tenant, "dmarc"); !ok {
		t.Fatal("another check kind was blocked")
	} else {
		r4()
	}
	rd()
	_, _ = db.ExecContext(context.Background(), `DELETE FROM controller_leases WHERE name LIKE '%' || $1 || '%'`, tenant.String())
}
