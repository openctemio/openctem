package findingimport

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type coverageFake struct {
	fakeRepo
	assets   int
	stale    []shared.ID
	open     int
	resolved []shared.ID
	recorded []ingestreceipt.Delta
	// tiers: absent is standard. The proposals written are kept.
	tiers     map[shared.ID]vulnerability.RiskTier
	proposals []vulnerability.ClosureProposalRecord
	vulnerability.ClosureProposalRepository
	// candErr is what ImportCoverageCandidates returns (a truncated receipt).
	candErr error
}

func (c *coverageFake) CountTenantAssets(context.Context, shared.ID, []shared.ID) (int, error) {
	return c.assets, nil
}
func (c *coverageFake) ImportCoverageCandidates(context.Context, shared.ID, []shared.ID, string, shared.ID) ([]shared.ID, int, error) {
	if c.candErr != nil {
		return nil, 0, c.candErr
	}
	return c.stale, c.open, nil
}
func (c *coverageFake) ResolveImportCoverage(_ context.Context, _ shared.ID, _, ids []shared.ID, _ string, _ shared.ID) ([]shared.ID, error) {
	c.resolved = append(c.resolved, ids...)
	return ids, nil
}
func (c *coverageFake) ImportCoverageUntouched(context.Context, shared.ID, []shared.ID, string, shared.ID) (int, error) {
	return 0, nil
}
func (c *coverageFake) Record(_ context.Context, d *ingestreceipt.Delta) (shared.ID, error) {
	c.recorded = append(c.recorded, *d)
	return shared.NewID(), nil
}

func coverageReq() Request {
	return Request{TenantID: shared.NewID(), ReceiptID: shared.NewID(), Coverage: Coverage{Full: true, CanVerify: true, AssetIDs: []shared.ID{shared.NewID()}}}
}

// A full-coverage upload closes only when it is complete: a failed file or a
// finding that could not be stored closes nothing; the blinding guard holds a
// mass close; a request cut short never closes.
func TestCloseUncovered(t *testing.T) {
	ok := FileResult{Tool: "nessus", Ingest: &ingest.Output{}}
	cases := []struct {
		name     string
		results  []FileResult
		stale    int
		open     int
		candErr  error
		complete bool
		closed   int
		note     string
		coverage string
	}{
		{"complete", []FileResult{ok}, 1, 2, nil, true, 1, "resolved", ingestreceipt.CoverageFull},
		{"a failed file", []FileResult{ok, {Error: &FileError{Kind: KindMalformed}}}, 1, 2, nil, true, 0, "incomplete", ingestreceipt.CoveragePartial},
		{"a finding not stored", []FileResult{{Tool: "nessus", Ingest: &ingest.Output{FailedFindings: []ingest.FailedFinding{{}}}}}, 1, 2, nil, true, 0, "incomplete", ingestreceipt.CoveragePartial},
		{"blinding guard", []FileResult{ok}, 150, 160, nil, true, 0, "held", ingestreceipt.CoverageFull},
		{"request cut short", []FileResult{ok}, 1, 2, nil, false, 0, "incomplete", ingestreceipt.CoveragePartial},
		// A record the parser skipped (below min_severity, or unusable) may be
		// a finding that is still there.
		{"a skipped record", []FileResult{{Tool: "nessus", Ingest: &ingest.Output{}, Stats: importer.Stats{Skipped: 1}}}, 1, 2, nil, true, 0, "incomplete", ingestreceipt.CoveragePartial},
		// A file whose receipt write failed left its findings off the
		// receipt that decides absence; a receipt past its action cap no
		// longer lists everything the upload reported.
		{"a receipt write failed", []FileResult{ok, {Tool: "nessus", Ingest: &ingest.Output{ReceiptFailed: true}}}, 1, 2, nil, true, 0, "incomplete", ingestreceipt.CoveragePartial},
		{"a truncated receipt", []FileResult{ok}, 1, 2, ingestreport.ErrReceiptIncomplete, true, 0, "incomplete", ingestreceipt.CoveragePartial},
		{"a file naming no tool", []FileResult{{Ingest: &ingest.Output{}}}, 1, 2, nil, true, 0, "incomplete", ingestreceipt.CoveragePartial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo := &coverageFake{assets: 1, open: c.open, candErr: c.candErr}
			for range c.stale {
				repo.stale = append(repo.stale, shared.NewID())
			}
			svc := NewService(&fakeIngester{}, repo, repo, ingest.SourceResolveDryRun, logger.NewNop())
			svc.SetClosureSettings(fixedClosing{Mode: tenant.ClosingModeAuto})
			svc.FinishUpload(context.Background(), coverageReq(), c.results, c.complete)
			if len(repo.resolved) != c.closed || len(repo.finished) != 1 {
				t.Fatalf("closed %d, want %d", len(repo.resolved), c.closed)
			}
			f := repo.finished[0]
			if f.CoverageNote != c.note || f.Coverage != c.coverage {
				t.Fatalf("receipt coverage %q note %q", f.Coverage, f.CoverageNote)
			}
			if c.closed > 0 && (len(repo.recorded) != 1 || len(repo.recorded[0].Closed) != c.closed) {
				t.Fatalf("closed findings not recorded on the receipt: %+v", repo.recorded)
			}
		})
	}
}

// An upload through an import mapping closes nothing, even when a caller
// got coverage=full past the handler.
func TestCloseUncoveredMappedNeverCloses(t *testing.T) {
	repo := &coverageFake{assets: 1, open: 2, stale: []shared.ID{shared.NewID()}}
	svc := NewService(&fakeIngester{}, repo, repo, ingest.SourceResolveDryRun, logger.NewNop())
	req := coverageReq()
	req.Mapping = resolvedCSV(t)
	svc.FinishUpload(context.Background(), req, []FileResult{{Tool: "mapped:legacy-vm", Ingest: &ingest.Output{}}}, true)
	if len(repo.resolved) != 0 || len(repo.finished) != 1 {
		t.Fatalf("a mapped upload closed %d findings", len(repo.resolved))
	}
	if f := repo.finished[0]; f.Coverage != ingestreceipt.CoveragePartial {
		t.Fatalf("receipt coverage %q", f.Coverage)
	}
}

// The declaration is checked again when the close is due: an asset that
// left the uploader's scope while the upload ran closes nothing, and the
// receipt says why.
func TestCloseUncoveredScopeChanged(t *testing.T) {
	repo := &coverageFake{assets: 1, open: 2, stale: []shared.ID{shared.NewID()}}
	svc := NewService(&fakeIngester{}, repo, repo, ingest.SourceResolveDryRun, logger.NewNop())
	req := coverageReq()
	req.CoverageScope = onlyAssets{}
	svc.FinishUpload(context.Background(), req, []FileResult{{Tool: "nessus", Ingest: &ingest.Output{}}}, true)
	if len(repo.resolved) != 0 || len(repo.finished) != 1 {
		t.Fatalf("closed %d after the scope changed", len(repo.resolved))
	}
	if f := repo.finished[0]; f.CoverageNote != "scope_changed" || f.Coverage != ingestreceipt.CoveragePartial {
		t.Fatalf("receipt coverage %q note %q", f.Coverage, f.CoverageNote)
	}
	// The visibility check wins over the write scope.
	a := shared.NewID()
	err := svc.CheckCoverage(context.Background(), Request{Coverage: Coverage{Full: true, AssetIDs: []shared.ID{a}},
		Actor: onlyAssets{a: true}, CoverageScope: onlyAssets{}})
	if !errors.Is(err, ErrCoverageScope) {
		t.Fatalf("an asset hidden from the uploader: %v", err)
	}
}

// A declaration is checked before anything is imported: a scope without
// full coverage, too many or unknown assets, assets outside the uploader's
// scope.
func TestCheckCoverage(t *testing.T) {
	repo := &coverageFake{assets: 1}
	svc := NewService(&fakeIngester{}, repo, repo, ingest.SourceResolveDryRun, logger.NewNop())
	a := shared.NewID()
	if err := svc.CheckCoverage(context.Background(), Request{Coverage: Coverage{AssetIDs: []shared.ID{a}}}); !errors.Is(err, ErrCoverageScope) {
		t.Fatalf("scope without full: %v", err)
	}
	if err := svc.CheckCoverage(context.Background(), Request{Coverage: Coverage{Full: true}}); !errors.Is(err, ErrCoverageScope) {
		t.Fatalf("full without scope: %v", err)
	}
	many := make([]shared.ID, MaxCoverageAssets+1)
	for i := range many {
		many[i] = shared.NewID()
	}
	if err := svc.CheckCoverage(context.Background(), Request{Coverage: Coverage{Full: true, AssetIDs: many}}); !errors.Is(err, ErrCoverageScope) {
		t.Fatalf("too many assets: %v", err)
	}
	if err := svc.CheckCoverage(context.Background(), Request{Coverage: Coverage{Full: true, AssetIDs: []shared.ID{a}}, Actor: onlyAssets{}}); !errors.Is(err, ErrCoverageScope) {
		t.Fatalf("asset outside scope: %v", err)
	}
	if err := svc.CheckCoverage(context.Background(), Request{Coverage: Coverage{Full: true, AssetIDs: []shared.ID{a}}, Actor: onlyAssets{a: true}}); err != nil {
		t.Fatalf("valid declaration: %v", err)
	}
	repo.assets = 0
	if err := svc.CheckCoverage(context.Background(), Request{Coverage: Coverage{Full: true, AssetIDs: []shared.ID{a}}}); !errors.Is(err, ErrCoverageScope) {
		t.Fatalf("unknown asset: %v", err)
	}
	plain := NewService(&fakeIngester{}, &fakeRepo{}, &fakeRepo{}, ingest.SourceResolveDryRun, logger.NewNop())
	if err := plain.CheckCoverage(context.Background(), Request{Coverage: Coverage{Full: true, AssetIDs: []shared.ID{a}}}); !errors.Is(err, ErrCoverageUnsupported) {
		t.Fatalf("a repository without coverage support accepted full coverage: %v", err)
	}
}

// Closing by absence is a verification: without findings:verify the upload
// closes nothing and the receipt says why.
func TestCloseUncoveredNeedsVerify(t *testing.T) {
	repo := &coverageFake{assets: 1, open: 2, stale: []shared.ID{shared.NewID()}}
	svc := NewService(&fakeIngester{}, repo, repo, ingest.SourceResolveDryRun, logger.NewNop())
	req := coverageReq()
	req.Coverage.CanVerify = false
	svc.FinishUpload(context.Background(), req, []FileResult{{Tool: "nessus", Ingest: &ingest.Output{}}}, true)
	if len(repo.resolved) != 0 || len(repo.finished) != 1 {
		t.Fatalf("closed %d without findings:verify", len(repo.resolved))
	}
	if f := repo.finished[0]; f.CoverageNote != "needs_verify" || f.Coverage != ingestreceipt.CoveragePartial {
		t.Fatalf("receipt coverage %q note %q", f.Coverage, f.CoverageNote)
	}
}

type fixedClosing tenant.ClosureSettings

func (f fixedClosing) GetClosureSettings(context.Context, string) (*tenant.ClosureSettings, error) {
	cs := tenant.ClosureSettings(f)
	return &cs, nil
}

func (c *coverageFake) FindingRiskTiers(_ context.Context, _ shared.ID, ids []shared.ID) (map[shared.ID]vulnerability.RiskTier, error) {
	out := make(map[shared.ID]vulnerability.RiskTier, len(ids))
	for _, id := range ids {
		if t, ok := c.tiers[id]; ok {
			out[id] = t
		} else {
			out[id] = vulnerability.RiskTierStandard
		}
	}
	return out, nil
}

func (c *coverageFake) RecordClosureProposals(_ context.Context, _ shared.ID, recs []vulnerability.ClosureProposalRecord) (int, error) {
	c.proposals = append(c.proposals, recs...)
	return len(recs), nil
}

// A full-coverage upload closes under the organization's closing mode: off
// keeps the findings and proposes nothing, review (also unset, unwired)
// proposes them, auto closes them except a critical one, which is proposed.
func TestCloseUncoveredClosingMode(t *testing.T) {
	cases := []struct {
		name      string
		settings  ClosureSettingsFixture
		closed    int
		proposed  int
		wantNote  string
		unwired   bool
		heldStale int
	}{
		{name: "off", settings: ClosureSettingsFixture{Mode: tenant.ClosingModeOff}, wantNote: "resolved"},
		{name: "review", settings: ClosureSettingsFixture{Mode: tenant.ClosingModeReview}, proposed: 2, wantNote: noteProposed},
		{name: "unset is review", proposed: 2, wantNote: noteProposed},
		{name: "unwired is review", unwired: true, proposed: 2, wantNote: noteProposed},
		{name: "auto: the critical is proposed", settings: ClosureSettingsFixture{Mode: tenant.ClosingModeAuto}, closed: 1, proposed: 1, wantNote: "resolved"},
		{name: "auto with critical opt-in", settings: ClosureSettingsFixture{Mode: tenant.ClosingModeAuto, CriticalAutoClose: true}, closed: 2, wantNote: "resolved"},
		{name: "held run proposes, closes nothing", settings: ClosureSettingsFixture{Mode: tenant.ClosingModeAuto, CriticalAutoClose: true}, proposed: 150, wantNote: "held", heldStale: 150},
		{name: "held run under off proposes nothing", settings: ClosureSettingsFixture{Mode: tenant.ClosingModeOff}, wantNote: "held", heldStale: 150},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			critical, medium := shared.NewID(), shared.NewID()
			repo := &coverageFake{assets: 1, open: 10, stale: []shared.ID{critical, medium},
				tiers: map[shared.ID]vulnerability.RiskTier{critical: vulnerability.RiskTierCritical}}
			if c.heldStale > 0 {
				repo.stale, repo.open = nil, c.heldStale+10
				for range c.heldStale {
					repo.stale = append(repo.stale, shared.NewID())
				}
			}
			svc := NewService(&fakeIngester{}, repo, repo, ingest.SourceResolveDryRun, logger.NewNop())
			if !c.unwired {
				svc.SetClosureSettings(fixedClosing(c.settings))
			}
			svc.FinishUpload(context.Background(), coverageReq(), []FileResult{{Tool: "nessus", Ingest: &ingest.Output{}}}, true)
			if len(repo.resolved) != c.closed || len(repo.proposals) != c.proposed {
				t.Fatalf("closed %d proposed %d, want %d / %d", len(repo.resolved), len(repo.proposals), c.closed, c.proposed)
			}
			for _, p := range repo.proposals {
				if p.Method != vulnerability.ClosureMethodCoveredScan {
					t.Fatalf("method %q", p.Method)
				}
			}
			if c.name == "auto: the critical is proposed" && (repo.resolved[0] != medium || repo.proposals[0].FindingID != critical) {
				t.Fatalf("closed %v proposed %v", repo.resolved, repo.proposals)
			}
			if f := repo.finished[0]; f.CoverageNote != c.wantNote {
				t.Fatalf("receipt note %q, want %q", f.CoverageNote, c.wantNote)
			}
		})
	}
}

// ClosureSettingsFixture is tenant.ClosureSettings, spelled short for the table.
type ClosureSettingsFixture = tenant.ClosureSettings
