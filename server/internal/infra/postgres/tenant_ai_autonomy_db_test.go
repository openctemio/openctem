package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	aidom "github.com/openctemio/openctem/server/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// The limits on changes AI agents make without a person
// (docs/architecture/ai-autonomy.md): concurrent reservations of one
// organization never exceed the hour limit, the day limit counts the last
// 24 clock hours, another organization's count is its own, and the setting
// round-trips with unlimited (nil) limits. Requires DATABASE_URL.
func TestAIAutonomy_ReserveAndSetting(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewTenantAISettingsRepository(&DB{DB: sqlDB})
	org, other := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{org, other} {
		id := id
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id, "ai-autonomy-"+id.String()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id) })
	}

	// Never saved: not found (the caller applies the defaults).
	if _, found, err := r.GetAutonomy(ctx, org); err != nil || found {
		t.Fatalf("unsaved: found=%v %v", found, err)
	}
	five := 5
	if ok, err := r.SaveAutonomy(ctx, org, nil, aidom.Autonomy{Paused: true, PerHour: &five}); err != nil || !ok {
		t.Fatalf("first save: %v %v", ok, err)
	}
	got, found, err := r.GetAutonomy(ctx, org)
	if err != nil || !found || !got.Paused || got.PerHour == nil || *got.PerHour != 5 || got.PerDay != nil {
		t.Fatalf("round trip: %+v found=%v %v", got, found, err)
	}
	// Compare-and-set: "none saved" no longer holds, and a write against the
	// stored value succeeds once; a second write against the same (now
	// stale) value is refused and leaves the newer one.
	ten, eight := 10, 8
	if ok, err := r.SaveAutonomy(ctx, org, nil, aidom.Autonomy{PerHour: &ten}); err != nil || ok {
		t.Fatalf("a write expecting nothing saved overwrote a saved setting: %v %v", ok, err)
	}
	if ok, err := r.SaveAutonomy(ctx, org, &got, aidom.Autonomy{PerHour: &ten}); err != nil || !ok {
		t.Fatalf("write over the stored value: %v %v", ok, err)
	}
	if ok, err := r.SaveAutonomy(ctx, org, &got, aidom.Autonomy{PerHour: &eight}); err != nil || ok {
		t.Fatalf("a write over a stale value was stored: %v %v", ok, err)
	}
	if cur, _, _ := r.GetAutonomy(ctx, org); cur.PerHour == nil || *cur.PerHour != 10 {
		t.Fatalf("stored %+v, want the newer 10 an hour", cur)
	}

	now := time.Now()
	three, day := 3, 4
	var (
		wg sync.WaitGroup
		mu sync.Mutex
		ok int
	)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			yes, err := r.ReserveAutoChange(ctx, org, &three, nil, now)
			if err != nil {
				t.Error(err)
				return
			}
			if yes {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 3 {
		t.Fatalf("%d concurrent changes allowed under a limit of 3 an hour", ok)
	}
	// Next hour: the hour limit resets, the day limit (4) counts the 3.
	next := now.Add(time.Hour)
	if yes, err := r.ReserveAutoChange(ctx, org, &three, &day, next); err != nil || !yes {
		t.Fatalf("next hour, first change: %v %v", yes, err)
	}
	if yes, err := r.ReserveAutoChange(ctx, org, &three, &day, next); err != nil || yes {
		t.Fatalf("day limit not applied: %v %v", yes, err)
	}
	// Unlimited, and another organization's count is its own.
	if yes, err := r.ReserveAutoChange(ctx, org, nil, nil, next); err != nil || !yes {
		t.Fatalf("unlimited: %v %v", yes, err)
	}
	if yes, err := r.ReserveAutoChange(ctx, other, &three, &day, next); err != nil || !yes {
		t.Fatalf("another organization was limited by this one's count: %v %v", yes, err)
	}
}
