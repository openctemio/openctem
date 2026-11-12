package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webevidence"
)

// Web evidence storage against the real schema. Requires DATABASE_URL.
func TestAssetWebEvidenceRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	repo := NewAssetWebEvidenceRepository(db)
	dnsRepo := NewEASMDNSRepository(db)

	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	a := seedNamedAsset(ctx, t, dnsRepo, tenant, "app.example.com", "subdomain", "active")
	foreign := seedNamedAsset(ctx, t, dnsRepo, other, "app.example.net", "subdomain", "active")
	now := time.Now().UTC().Truncate(time.Second)

	rec := func(tn, asset shared.ID, at time.Time, key string) webevidence.Record {
		r := webevidence.Record{TenantID: tn.String(), AssetID: asset.String(), Capture: webevidence.Capture{
			URL: "https://app.example.com/", StatusCode: 200, Title: "App", Snippet: "<html>", CapturedAt: at}}
		if key != "" {
			exp := at.Add(webevidence.ScreenshotRetention)
			r.ScreenshotKey, r.ScreenshotProvider, r.ScreenshotSHA256 = key, "local", "ab"+key[len(key)-2:]+"0000000000000000000000000000000000000000000000000000000000"
			r.ScreenshotSize, r.ScreenshotWidth, r.ScreenshotHeight, r.ScreenshotExpiresAt = 100, 10, 10, &exp
		}
		return r
	}
	// Seven captures, the two oldest with screenshots: pruning keeps five and
	// queues the dropped screenshots as orphans.
	for i := 0; i < 7; i++ {
		key := ""
		if i < 2 {
			key = "k/old-0" + string(rune('0'+i))
		}
		if err := repo.Insert(ctx, rec(tenant, a, now.Add(time.Duration(i-10)*time.Hour), key)); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.Insert(ctx, rec(other, foreign, now, "k/foreign-01")); err != nil {
		t.Fatal(err)
	}
	list, err := repo.List(ctx, tenant, a)
	if err != nil || len(list) != webevidence.MaxCapturesPerAsset {
		t.Fatalf("list: %v %d", err, len(list))
	}
	if !list[0].CapturedAt.After(list[4].CapturedAt) {
		t.Fatal("not newest first")
	}
	orphans, err := repo.TakeOrphans(ctx, 100)
	if err != nil || len(orphans) != 2 || orphans[0].TenantID != tenant.String() {
		t.Fatalf("orphans: %v %+v", err, orphans)
	}
	if again, _ := repo.TakeOrphans(ctx, 100); len(again) != 0 {
		t.Fatal("orphans taken twice")
	}

	// Another tenant's capture is never readable through this tenant.
	fl, _ := repo.List(ctx, tenant, foreign)
	if len(fl) != 0 {
		t.Fatal("foreign asset listed")
	}
	other1, _ := repo.List(ctx, other, foreign)
	if _, err := repo.Get(ctx, tenant, foreign, other1[0].ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if _, err := repo.Get(ctx, tenant, a, "not-a-uuid"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}

	// A screenshot past its expiry is detached and returned once; the text stays.
	withShot := rec(tenant, a, now, "k/new-01")
	past := now.Add(-time.Minute)
	withShot.ScreenshotExpiresAt = &past
	if err := repo.Insert(ctx, withShot); err != nil {
		t.Fatal(err)
	}
	expired, err := repo.ExpireScreenshots(ctx, now, 100)
	if err != nil || len(expired) != 1 || expired[0].Key != "k/new-01" {
		t.Fatalf("expire: %v %+v", err, expired)
	}
	list, _ = repo.List(ctx, tenant, a)
	if list[0].HasScreenshot() || list[0].Title != "App" {
		t.Fatalf("after expiry: %+v", list[0])
	}
	if n, err := repo.DeleteOlderThan(ctx, now.Add(time.Hour)); err != nil || n < 5 {
		t.Fatalf("delete old: %v %d", err, n)
	}

	// Deleting the asset queues its screenshot file.
	if err := repo.Insert(ctx, rec(tenant, a, now, "k/last-01")); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.ExecContext(ctx, `DELETE FROM assets WHERE id = $1`, a.String()); err != nil {
		t.Fatal(err)
	}
	orphans, _ = repo.TakeOrphans(ctx, 100)
	if len(orphans) != 1 || orphans[0].Key != "k/last-01" {
		t.Fatalf("cascade orphan: %+v", orphans)
	}
}
