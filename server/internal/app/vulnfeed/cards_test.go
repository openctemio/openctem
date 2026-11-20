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
	file    string
	applied [][]*advisory.Card
	seq     uint64
}

func (f *fakeCards) AppliedFile(context.Context) (string, error) { return f.file, nil }
func (f *fakeCards) Apply(_ context.Context, cs []*advisory.Card, st advisory.StreamApplied, _ time.Time) (advisory.Applied, error) {
	f.applied, f.seq, f.file = append(f.applied, cs), st.Sequence, st.FileSHA256
	return advisory.Applied{Published: len(cs)}, nil
}
func (f *fakeCards) ExploitationFor(context.Context, []string) (map[string]advisory.Exploitation, error) {
	return nil, nil
}

func cardsRelease(t *testing.T, asOf time.Time, line string) intelRelease {
	t.Helper()
	gz, f, _ := gzFile(line)
	return cardsReleaseOf(t, asOf, gz, f)
}

func cardsReleaseOf(t *testing.T, asOf time.Time, gz []byte, f vulnbundle.File) intelRelease {
	t.Helper()
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
	// The same file again: not applied.
	im.syncIntel(context.Background(), rel.files, 9, 0)
	if len(cards.applied) != 1 {
		t.Fatal("cards applied twice")
	}
}

// The stream is applied whenever its file changes, whatever its data date:
// a card reviewed earlier but merged later, or a withdrawal published
// without a later timestamp, keeps the stream's date the same.
func TestSyncIntel_CardsAppliedByContentNotDate(t *testing.T) {
	asOf := time.Date(2026, 11, 18, 19, 0, 0, 0, time.UTC)
	first := fixtureCardLine(t)
	rel := cardsRelease(t, asOf, first)
	im, _ := intelImporter(t, rel, newFakeIntel())
	cards := &fakeCards{}
	im.WithCards(cards)
	im.syncIntel(context.Background(), rel.files, 9, 0)

	// Card B, reviewed an hour before card A, merged after it: the newest
	// date stays A's.
	b := strings.Replace(strings.Replace(first, "OCA-2026-9001", "OCA-2026-9002", 1),
		`"reviewed_at":"2026-11-18T19:00:00Z"`, `"reviewed_at":"2026-11-18T18:00:00Z"`, 1)
	gz, f, _ := gzFile(first, b)
	rel2 := cardsReleaseOf(t, asOf, gz, f)
	im2, _ := intelImporter(t, rel2, newFakeIntel())
	im2.WithCards(cards)
	im2.syncIntel(context.Background(), rel2.files, 9, 0)
	if len(cards.applied) != 2 || len(cards.applied[1]) != 2 || cards.applied[1][1].ID != "OCA-2026-9002" {
		t.Fatalf("a new card with an equal data date was not applied: %d", len(cards.applied))
	}

	// A withdrawal without a timestamp change.
	w := strings.Replace(first, `"state":"reviewed"`, `"state":"withdrawn","withdrawn_reason":"Retracted."`, 1)
	gz, f, _ = gzFile(w, b)
	rel3 := cardsReleaseOf(t, asOf, gz, f)
	im3, _ := intelImporter(t, rel3, newFakeIntel())
	im3.WithCards(cards)
	im3.syncIntel(context.Background(), rel3.files, 9, 0)
	if len(cards.applied) != 3 || !cards.applied[2][0].Withdrawn() {
		t.Fatalf("a withdrawal without a later timestamp was not applied: %d", len(cards.applied))
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
