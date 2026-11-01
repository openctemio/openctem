package vulnmatch

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fixedClosing tenant.ClosureSettings

func (f fixedClosing) GetClosureSettings(context.Context, string) (*tenant.ClosureSettings, error) {
	cs := tenant.ClosureSettings(f)
	return &cs, nil
}

// proposalWriter is the finding writer that also records closure proposals.
type proposalWriter struct {
	fakeWriter
	vulnerability.ClosureProposalRepository
	recs []vulnerability.ClosureProposalRecord
}

func (p *proposalWriter) RecordClosureProposals(_ context.Context, _ shared.ID, recs []vulnerability.ClosureProposalRecord) (int, error) {
	p.recs = append(p.recs, recs...)
	return len(recs), nil
}

// A version-change close (the inventory reports another version) goes
// through the organization's closing mode: off keeps the finding open, review
// proposes it (method source_reported), auto closes it.
func TestReconcile_VersionChangeClosesUnderClosingMode(t *testing.T) {
	asset, product := shared.NewID(), shared.NewID()
	cases := []struct {
		name     string
		settings tenant.ClosureSettings
		unwired  bool
		closed   int
		proposed int
	}{
		{"off", tenant.ClosureSettings{Mode: tenant.ClosingModeOff}, false, 0, 0},
		{"review", tenant.ClosureSettings{Mode: tenant.ClosingModeReview}, false, 0, 1},
		{"unset mode is review", tenant.ClosureSettings{}, false, 0, 1},
		{"no reader wired is review", tenant.ClosureSettings{}, true, 0, 1},
		{"auto", tenant.ClosureSettings{Mode: tenant.ClosingModeAuto}, false, 1, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := newFakeStore()
			v, id := shared.NewID(), shared.NewID()
			store.existing = []softwarematch.MatcherFinding{{ID: id, AssetID: asset, CVEID: "CVE-1", Fingerprint: "gone",
				Status: "new", ProductID: &product, VersionID: &v, Location: "tcp/443"}}
			store.links[softwarematch.LinkKey{AssetID: asset, ProductID: product, VersionID: v, Location: "tcp/443"}] =
				softwarematch.LinkInfo{State: softwarematch.LinkUpgraded, VersionEvaluated: true}
			w := &proposalWriter{}
			svc := NewService(store, fakePolicy{tenant.VulnMatchingSettings{Enabled: true}}, w, logger.NewNop())
			if !c.unwired {
				svc.SetClosureSettings(fixedClosing(c.settings))
			}
			var st Stats
			if err := svc.ReconcileTenant(context.Background(), shared.NewID(), &st); err != nil {
				t.Fatal(err)
			}
			if got := len(store.closed[softwarematch.CloseVersionChanged]); got != c.closed || st.Closed != c.closed {
				t.Fatalf("closed %d (stats %d), want %d", got, st.Closed, c.closed)
			}
			if len(w.recs) != c.proposed {
				t.Fatalf("proposals %d, want %d", len(w.recs), c.proposed)
			}
			for _, r := range w.recs {
				if r.FindingID != id || r.Method != vulnerability.ClosureMethodSourceReported {
					t.Fatalf("proposal %+v", r)
				}
			}
		})
	}
}

// The proposal of a version-change close names what changed: product, the
// finding's version, the established version, its source, evidence class,
// confidence and sightings, and dates evidence_at at the version's latest
// reading.
func TestReconcile_VersionChangeProposalCarriesEvidence(t *testing.T) {
	asset, product, v, id := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	store := newFakeStore()
	store.existing = []softwarematch.MatcherFinding{{ID: id, AssetID: asset, CVEID: "CVE-2026-119977", Fingerprint: "gone",
		Status: "new", ProductID: &product, VersionID: &v}}
	last := time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
	store.links[softwarematch.LinkKey{AssetID: asset, ProductID: product, VersionID: v}] = softwarematch.LinkInfo{
		State: softwarematch.LinkUpgraded, VersionEvaluated: true, Product: "WordPress", FromVersion: "7.1.3",
		Now: &softwarematch.VersionSighting{VersionID: shared.NewID(), Version: "7.1.4", Source: "technology",
			Class: "probe", Confidence: 85, Sightings: 3, FirstSeen: last.Add(-36 * time.Hour), LastSeen: last},
	}
	w := &proposalWriter{}
	svc := NewService(store, fakePolicy{tenant.VulnMatchingSettings{Enabled: true}}, w, logger.NewNop())
	svc.now = func() time.Time { return last.Add(5 * time.Hour) }
	var st Stats
	if err := svc.ReconcileTenant(context.Background(), shared.NewID(), &st); err != nil {
		t.Fatal(err)
	}
	if len(w.recs) != 1 {
		t.Fatalf("proposals %d, want 1", len(w.recs))
	}
	ev := w.recs[0].Evidence
	want := map[string]any{"source": "software_inventory", "kind": "version_changed", "product": "WordPress",
		"from_version": "7.1.3", "to_version": "7.1.4", "to_source": "technology", "to_evidence_class": "probe",
		"to_confidence": 85, "to_sightings": 3, "observed_at": last.Format(time.RFC3339)}
	for k, v := range want {
		if ev[k] != v {
			t.Errorf("evidence[%s] = %v, want %v", k, ev[k], v)
		}
	}
	if !w.recs[0].EvidenceAt.Equal(last) {
		t.Fatalf("evidence_at = %s, want the version's latest reading %s", w.recs[0].EvidenceAt, last)
	}
}

// A finding whose identity matches again (the version it was built on is
// established again, or the change never got confirmed) has its pending
// version-change proposal canceled; findings no longer matched do not.
func TestReconcile_MatchedAgainCancelsVersionProposal(t *testing.T) {
	asset := shared.NewID()
	m := match(asset, "CVE-1", 80)
	store := newFakeStore()
	store.matches = []softwarematch.Match{m}
	open, closedOne, gone := shared.NewID(), shared.NewID(), shared.NewID()
	store.existing = []softwarematch.MatcherFinding{
		{ID: open, AssetID: asset, Fingerprint: fp(m), Status: "new"},
		{ID: closedOne, AssetID: asset, Fingerprint: "other-resolved", Status: "resolved"},
		{ID: gone, AssetID: asset, Fingerprint: "gone", Status: "new"},
	}
	svc, _ := newSvc(store, true)
	var st Stats
	if err := svc.ReconcileTenant(context.Background(), shared.NewID(), &st); err != nil {
		t.Fatal(err)
	}
	if len(store.canceled) != 1 || store.canceled[0] != open {
		t.Fatalf("canceled %v, want only the open matched finding", store.canceled)
	}
}

func TestVersionChangeEvidenceWithoutDetail(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	ev, evAt := VersionChangeEvidence(softwarematch.CloseVersionChanged, softwarematch.LinkInfo{}, at)
	if !evAt.Equal(at) || ev["to_version"] != nil || ev["kind"] != "version_changed" {
		t.Fatalf("evidence %+v at %s", ev, evAt)
	}
}
