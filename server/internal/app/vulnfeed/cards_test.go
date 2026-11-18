package vulnfeed

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/advisory"
	"github.com/openctemio/openctem/server/pkg/vulnbundle"
)

type fakeCards struct {
	asOf    time.Time
	applied [][]*advisory.Card
	seq     uint64
}

func (f *fakeCards) AsOf(context.Context) (time.Time, error) { return f.asOf, nil }
func (f *fakeCards) Apply(_ context.Context, cs []*advisory.Card, seq uint64, _ time.Time) (advisory.Applied, error) {
	f.applied, f.seq = append(f.applied, cs), seq
	return advisory.Applied{Published: len(cs)}, nil
}
func (f *fakeCards) ExploitationFor(context.Context, []string) (map[string]advisory.Exploitation, error) {
	return nil, nil
}

func cardsRelease(t *testing.T, asOf time.Time, line string) intelRelease {
	t.Helper()
	gz, f, _ := gzFile(line)
	f.Name = vulnbundle.IntelFileName(vulnbundle.IntelStreamCards)
	now := time.Now().UTC().Truncate(time.Second)
	rel := newIntelRelease(t, 9, rel0(), rel0(), vulnbundle.IntelStream{Name: vulnbundle.IntelStreamCards, AsOf: asOf,
		FetchedAt: now, Version: advisory.Schema, File: f})
	rel.files[f.Name] = gz
	return rel
}

func fixtureCardLine(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../../pkg/domain/advisory/testdata/OCA-2026-9001.json")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestSyncIntel_AppliesCards(t *testing.T) {
	asOf := time.Date(2026, 11, 18, 19, 0, 0, 0, time.UTC)
	rel := cardsRelease(t, asOf, fixtureCardLine(t))
	im, fs := intelImporter(t, rel, newFakeIntel())
	cards := &fakeCards{}
	im.WithCards(cards)
	im.syncIntel(context.Background(), rel.files, 9, 0)
	if len(cards.applied) != 1 || cards.applied[0][0].ID != "OCA-2026-9001" || cards.seq != 9 {
		t.Fatalf("%+v", cards.applied)
	}
	if fs.st.Metadata()["intel_error"] != nil || fs.st.Metadata()["intel_skipped"] != nil {
		t.Fatalf("%v", fs.st.Metadata())
	}
	// Same data date again: not downloaded or applied.
	cards.asOf = asOf
	im.syncIntel(context.Background(), rel.files, 9, 0)
	if len(cards.applied) != 1 {
		t.Fatal("cards applied twice")
	}
}

func TestSyncIntel_CardsRefusedKeepsKEV(t *testing.T) {
	bad := strings.Replace(fixtureCardLine(t), `"state":"reviewed"`, `"state":"in_review"`, 1)
	rel := cardsRelease(t, time.Date(2026, 11, 18, 19, 0, 0, 0, time.UTC), bad)
	ap := newFakeIntel()
	im, fs := intelImporter(t, rel, ap)
	cards := &fakeCards{}
	im.WithCards(cards)
	im.syncIntel(context.Background(), rel.files, 9, 0)
	if len(cards.applied) != 0 || ap.kev != 2 {
		t.Fatalf("cards %d kev %d", len(cards.applied), ap.kev)
	}
	if e, _ := fs.st.Metadata()["intel_error"].(string); !strings.HasPrefix(e, "cards:") {
		t.Fatalf("intel_error %q", e)
	}
}

func TestSyncIntel_NoCardStoreSkipsStream(t *testing.T) {
	rel := cardsRelease(t, time.Date(2026, 11, 18, 19, 0, 0, 0, time.UTC), fixtureCardLine(t))
	ap := newFakeIntel()
	im, fs := intelImporter(t, rel, ap)
	im.syncIntel(context.Background(), rel.files, 9, 0)
	if ap.kev != 2 || fs.st.Metadata()["intel_skipped"] != "cards" {
		t.Fatalf("kev %d meta %v", ap.kev, fs.st.Metadata())
	}
}
