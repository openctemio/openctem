package refingerprint

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// fakeStore keeps findings in memory and applies the same rules as the
// postgres store: earliest-created survives, never across assets.
type fakeStore struct {
	rows    []vulnerability.RekeyCandidate
	holders map[string]vulnerability.RekeyHolder // keys already held outside the candidates
	writes  int
	started bool
}

func (s *fakeStore) ListCandidates(_ context.Context, _ shared.ID, _ int, after string, limit int) ([]vulnerability.RekeyCandidate, error) {
	var out []vulnerability.RekeyCandidate
	for _, r := range s.rows {
		if r.ID > after && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *fakeStore) Holders(_ context.Context, _ shared.ID, keys []string) (map[string]vulnerability.RekeyHolder, error) {
	out := map[string]vulnerability.RekeyHolder{}
	for _, k := range keys {
		if h, ok := s.holders[k]; ok {
			out[k] = h
		}
	}
	return out, nil
}

func (s *fakeStore) Rekey(_ context.Context, _ shared.ID, id, _ string, k vulnerability.IdentityKey) (vulnerability.RekeyResult, error) {
	s.writes++
	fp := k.Fingerprint()
	var me vulnerability.RekeyCandidate
	for _, r := range s.rows {
		if r.ID == id {
			me = r
		}
	}
	h, ok := s.holders[fp]
	if !ok {
		s.holders[fp] = vulnerability.RekeyHolder{ID: id, AssetID: me.Input.AssetID, CreatedAt: me.CreatedAt}
		return vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeRekeyed}, nil
	}
	if h.AssetID != me.Input.AssetID {
		return vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeSkipped, Reason: vulnerability.RekeySkipOtherAsset}, nil
	}
	if me.CreatedAt.Before(h.CreatedAt) {
		s.holders[fp] = vulnerability.RekeyHolder{ID: id, AssetID: me.Input.AssetID, CreatedAt: me.CreatedAt}
		return vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeMerged, SurvivorID: id, LoserID: h.ID}, nil
	}
	return vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeMerged, SurvivorID: h.ID, LoserID: id}, nil
}

func (s *fakeStore) StartRun(context.Context, shared.ID, int) (*vulnerability.RekeyRun, error) {
	s.started = true
	return &vulnerability.RekeyRun{Status: "running"}, nil
}
func (s *fakeStore) SaveProgress(context.Context, shared.ID, string, int, int, int) error { return nil }
func (s *fakeStore) FinishRun(context.Context, shared.ID) error                           { return nil }

func sca(id, asset, version, cve string, created time.Time) vulnerability.RekeyCandidate {
	return vulnerability.RekeyCandidate{ID: id, Fingerprint: "v1-" + id, CreatedAt: created,
		Input: vulnerability.StoredIdentityInput{AssetID: asset, Source: "sca", FindingType: "vulnerability",
			RuleID: cve, CVEID: cve, ComponentPURL: "pkg:npm/lodash@" + version}}
}

func newStore() *fakeStore {
	now := time.Now()
	const a, b = "aaaaaaaa-0000-0000-0000-000000000000", "bbbbbbbb-0000-0000-0000-000000000000"
	s := &fakeStore{holders: map[string]vulnerability.RekeyHolder{}, rows: []vulnerability.RekeyCandidate{
		sca("1", a, "1.0.0", "CVE-1", now),                                                 // newer twin of 2
		sca("2", a, "2.0.0", "CVE-1", now.Add(-time.Hour)),                                 // older: survives
		sca("3", a, "1.0.0", "CVE-2", now),                                                 // unique
		sca("4", a, "1.0.0", "CVE-3", now),                                                 // key held on another asset
		{ID: "5", Input: vulnerability.StoredIdentityInput{AssetID: a, Source: "pentest"}}, // human
	}}
	k, _ := vulnerability.SCAIdentity(a, "pkg:npm/lodash", "", "", "CVE-3", "")
	s.holders[k.Fingerprint()] = vulnerability.RekeyHolder{ID: "9", AssetID: b, CreatedAt: now.Add(-48 * time.Hour)}
	return s
}

func TestRun_DryRunPredictsTheRealRunAndWritesNothing(t *testing.T) {
	tenant := shared.NewID()
	dryStore := newStore()
	dry, err := NewService(dryStore).Run(context.Background(), tenant, Options{BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if dryStore.writes != 0 || dryStore.started {
		t.Fatalf("the dry run wrote (%d re-keys, run started %v)", dryStore.writes, dryStore.started)
	}
	real, err := NewService(newStore()).Run(context.Background(), tenant, Options{Apply: true, BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Rekeyed != real.Rekeyed || dry.Merged != real.Merged || len(dry.Merges) != len(real.Merges) {
		t.Fatalf("dry %+v != real %+v", dry, real)
	}
	for i := range dry.Merges {
		if dry.Merges[i] != real.Merges[i] {
			t.Fatalf("merge %d: dry %+v real %+v", i, dry.Merges[i], real.Merges[i])
		}
	}
	for k, v := range real.Skipped {
		if dry.Skipped[k] != v {
			t.Fatalf("skipped %q: dry %d real %d", k, dry.Skipped[k], v)
		}
	}
	if real.Rekeyed != 2 || real.Merged != 1 || real.Merges[0].SurvivorID != "2" || real.Merges[0].LoserID != "1" {
		t.Fatalf("real run: %+v", real)
	}
	if real.Skipped[vulnerability.RekeySkipOtherAsset] != 1 || real.Skipped[vulnerability.RecomputeSkipHumanFinding] != 1 {
		t.Fatalf("skips: %+v", real.Skipped)
	}
	if !real.Completed || real.Scanned != 5 {
		t.Fatalf("progress: %+v", real)
	}
}

func TestRun_RequiresTenant(t *testing.T) {
	if _, err := NewService(newStore()).Run(context.Background(), shared.ID{}, Options{}); err == nil {
		t.Fatal("a run without a tenant must fail")
	}
}
