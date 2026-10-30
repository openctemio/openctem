package vulnmatch

import (
	"context"
	"testing"

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
