package unit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
)

func bundleKEV(n int) []*threatintel.KEVEntry {
	out := make([]*threatintel.KEVEntry, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, threatintel.NewKEVEntry(fmt.Sprintf("CVE-2021-%05d", 10000+i), "V", "P", "N", "D",
			time.Date(2022, 3, 3, 0, 0, 0, 0, time.UTC), time.Time{}, "Unknown", "", nil))
	}
	return out
}

func bundleEPSS(n int, date time.Time) []*threatintel.EPSSScore {
	out := make([]*threatintel.EPSSScore, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, threatintel.NewEPSSScore(fmt.Sprintf("CVE-2020-%05d", i), 0.2, 50, "v2025.03.14", date))
	}
	return out
}

var (
	bDay1 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	bDay2 = bDay1.Add(24 * time.Hour)
)

func bundleStream(asOf time.Time) threat.BundleStream {
	return threat.BundleStream{AsOf: asOf, FetchedAt: asOf.Add(time.Hour), Sequence: 9}
}

func TestApplyBundleKEV_AppliesAndRecordsTheSource(t *testing.T) {
	repo := newThreatIntelMockRepo()
	status := threatIntelAddSyncStatus(repo, "kev", true)
	svc := newThreatIntelService(repo)
	swept := ""
	svc.SetAfterBundleApply(func(_ context.Context, source string) { swept = source })

	out, err := svc.ApplyBundleKEV(context.Background(), bundleStream(bDay1), bundleKEV(600), "2026.10.25")
	if err != nil || !out.Applied || out.Records != 600 {
		t.Fatalf("%+v %v", out, err)
	}
	if len(repo.kev.entries) != 600 || swept != "kev" {
		t.Fatalf("entries %d swept %q", len(repo.kev.entries), swept)
	}
	meta := status.Metadata()
	if meta[threat.MetaDeliveredVia] != threat.ViaBundle || meta[threat.MetaIntelAsOf] != bDay1.Format(time.RFC3339) ||
		meta[threat.MetaBundleFetched] != bDay1.Add(time.Hour).Format(time.RFC3339) || meta[threat.MetaBundleSequence] != uint64(9) {
		t.Fatalf("metadata %+v", meta)
	}
	if status.RecordsSynced() != 600 {
		t.Fatalf("records %d", status.RecordsSynced())
	}
}

func TestApplyBundleKEV_NotNewerOnlyRefreshesFreshness(t *testing.T) {
	repo := newThreatIntelMockRepo()
	status := threatIntelAddSyncStatus(repo, "kev", true)
	svc := newThreatIntelService(repo)
	ctx := context.Background()
	if _, err := svc.ApplyBundleKEV(ctx, bundleStream(bDay2), bundleKEV(600), ""); err != nil {
		t.Fatal(err)
	}
	// An older data date (a replayed or carried copy) changes nothing, and
	// the same date writes nothing either; the freshness is still recorded.
	for name, asOf := range map[string]time.Time{"older": bDay1, "same": bDay2} {
		repo.kev.entries = map[string]*threatintel.KEVEntry{"CVE-2000-00001": nil}
		st := bundleStream(asOf)
		st.FetchedAt = bDay2.Add(5 * time.Hour)
		out, err := svc.ApplyBundleKEV(ctx, st, bundleKEV(600), "")
		if err != nil || out.Applied {
			t.Fatalf("%s: %+v %v", name, out, err)
		}
		if len(repo.kev.entries) != 1 {
			t.Fatalf("%s: the catalog was rewritten", name)
		}
		if got := status.Metadata()[threat.MetaBundleFetched]; got != bDay2.Add(5*time.Hour).Format(time.RFC3339) {
			t.Fatalf("%s: freshness %v", name, got)
		}
		if status.Metadata()[threat.MetaIntelAsOf] != bDay2.Format(time.RFC3339) {
			t.Fatalf("%s: the data date went backwards: %v", name, status.Metadata()[threat.MetaIntelAsOf])
		}
	}
}

func TestApplyBundleKEV_DoesNotOverwriteNewerDirectData(t *testing.T) {
	repo := newThreatIntelMockRepo()
	status := threatIntelAddSyncStatus(repo, "kev", true)
	meta := status.Metadata()
	meta[threat.MetaDeliveredVia] = threat.ViaDirect
	meta[threat.MetaIntelAsOf] = bDay2.Format(time.RFC3339)
	status.SetMetadata(meta)
	svc := newThreatIntelService(repo)
	out, err := svc.ApplyBundleKEV(context.Background(), bundleStream(bDay1), bundleKEV(600), "")
	if err != nil || out.Applied || len(repo.kev.entries) != 0 {
		t.Fatalf("%+v %v %d", out, err, len(repo.kev.entries))
	}
	if status.Metadata()[threat.MetaDeliveredVia] != threat.ViaDirect {
		t.Fatal("an older bundle copy replaced the direct fetch's record")
	}
}

func TestApplyBundle_RefusesATruncatedSnapshot(t *testing.T) {
	repo := newThreatIntelMockRepo()
	threatIntelAddSyncStatus(repo, "kev", true)
	threatIntelAddSyncStatus(repo, "epss", true)
	svc := newThreatIntelService(repo)
	repo.kev.countVal = 1500
	repo.epss.countVal = 400000
	if _, err := svc.ApplyBundleKEV(context.Background(), bundleStream(bDay2), bundleKEV(600), ""); err == nil {
		t.Fatal("a KEV snapshot at 40% of the stored catalog was applied")
	}
	if _, err := svc.ApplyBundleEPSS(context.Background(), bundleStream(bDay2), bundleEPSS(300000, bDay2)); err == nil {
		t.Fatal("an EPSS snapshot at 75% of the stored scores was applied")
	}
	if len(repo.kev.entries) != 0 || len(repo.epss.scores) != 0 {
		t.Fatal("a refused snapshot was written")
	}
}

func TestApplyBundleEPSS_ByDayAndSource(t *testing.T) {
	repo := newThreatIntelMockRepo()
	status := threatIntelAddSyncStatus(repo, "epss", true)
	svc := newThreatIntelService(repo)
	ctx := context.Background()
	out, err := svc.ApplyBundleEPSS(ctx, bundleStream(bDay1), bundleEPSS(50, bDay1))
	if err != nil || !out.Applied || len(repo.epss.scores) != 50 {
		t.Fatalf("%+v %v", out, err)
	}
	if status.Metadata()[threat.MetaDeliveredVia] != threat.ViaBundle {
		t.Fatalf("%+v", status.Metadata())
	}
	// Later the same day (scores are dated by day): nothing to apply.
	out, err = svc.ApplyBundleEPSS(ctx, bundleStream(bDay1.Add(3*time.Hour)), bundleEPSS(50, bDay1))
	if err != nil || out.Applied {
		t.Fatalf("same day: %+v %v", out, err)
	}
	out, err = svc.ApplyBundleEPSS(ctx, bundleStream(bDay2), bundleEPSS(50, bDay2))
	if err != nil || !out.Applied {
		t.Fatalf("next day: %+v %v", out, err)
	}
}

func TestApplyBundle_DisabledSourceIsLeftAlone(t *testing.T) {
	repo := newThreatIntelMockRepo()
	threatIntelAddSyncStatus(repo, "kev", false)
	svc := newThreatIntelService(repo)
	out, err := svc.ApplyBundleKEV(context.Background(), bundleStream(bDay1), bundleKEV(600), "")
	if err != nil || out.Applied || len(repo.kev.entries) != 0 {
		t.Fatalf("%+v %v", out, err)
	}
	if ok, err := svc.BundleWanted(context.Background(), "kev", bDay2); err != nil || ok {
		t.Fatalf("a disabled source wants nothing: %v %v", ok, err)
	}
}

func TestBundleWantedAndRefusalRecord(t *testing.T) {
	repo := newThreatIntelMockRepo()
	status := threatIntelAddSyncStatus(repo, "kev", true)
	svc := newThreatIntelService(repo)
	ctx := context.Background()
	if ok, _ := svc.BundleWanted(ctx, "kev", bDay1); !ok {
		t.Fatal("nothing held: the stream is wanted")
	}
	if _, err := svc.ApplyBundleKEV(ctx, bundleStream(bDay1), bundleKEV(600), ""); err != nil {
		t.Fatal(err)
	}
	if ok, _ := svc.BundleWanted(ctx, "kev", bDay1); ok {
		t.Fatal("the same data date is not wanted again")
	}
	if ok, _ := svc.BundleWanted(ctx, "kev", bDay2); !ok {
		t.Fatal("a newer data date is wanted")
	}
	svc.RecordBundleRefused(ctx, "kev", fmt.Errorf("size or SHA-256 does not match the manifest"))
	if status.Metadata()[threat.MetaBundleError] == nil {
		t.Fatal("the refusal was not recorded")
	}
	if err := svc.RecordBundleSeen(ctx, "kev", bundleStream(bDay2)); err != nil {
		t.Fatal(err)
	}
	if status.Metadata()[threat.MetaBundleError] != nil {
		t.Fatal("a good copy clears the refusal")
	}
}
