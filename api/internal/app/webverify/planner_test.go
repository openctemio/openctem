package webverify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

type fakeStore struct {
	cands   []Candidate
	used    int
	planned []Planned
	limit   int
}

func (f *fakeStore) TenantsWithCandidates(context.Context, []string, int) ([]shared.ID, error) {
	return nil, nil
}

func (f *fakeStore) Candidates(_ context.Context, _ shared.ID, _ []string, limit int) ([]Candidate, error) {
	f.limit = limit
	return f.cands, nil
}

func (f *fakeStore) RunPlannedSince(context.Context, shared.ID, time.Time) (int, error) {
	return f.used, nil
}

func (f *fakeStore) RecordPlanned(_ context.Context, _ shared.ID, rows []Planned) error {
	f.planned = append(f.planned, rows...)
	return nil
}

type fakeDisp struct {
	calls []scanapp.WebVerifyInput
	err   error
	deny  map[string]bool
}

func (d *fakeDisp) StartWebVerification(_ context.Context, in scanapp.WebVerifyInput) (*scanapp.WebVerifyResult, error) {
	d.calls = append(d.calls, in)
	if d.err != nil {
		return nil, d.err
	}
	run := shared.NewID()
	res := &scanapp.WebVerifyResult{RunID: &run}
	for _, u := range in.Targets {
		if !d.deny[strings.ToLower(u)] {
			res.Kept = append(res.Kept, u)
		}
	}
	return res, nil
}

type blocker struct{ prefix string }

func (b blocker) Blocking(_, _, path string) *scopedom.Exclusion {
	if b.prefix != "" && strings.HasPrefix(path, b.prefix) {
		return &scopedom.Exclusion{}
	}
	return nil
}

type rules struct {
	b   Blocker
	err error
}

func (r rules) LoadBlocker(context.Context, shared.ID) (Blocker, error) { return r.b, r.err }

func cand(origin, path, key string) Candidate {
	return Candidate{EndpointID: shared.NewID(), OriginAssetID: shared.NewID(), OriginName: origin, Method: "GET",
		PathTemplate: path, ExamplePath: path, CatalogKey: key, ResponseSig: "sig-" + path}
}

func newPlanner(s *fakeStore, d *fakeDisp, r Rules) *Planner {
	return NewPlanner(s, d, r, Config{DailyBudget: 10, PassCap: 5}, nil)
}

func TestPlansMappedTemplatesAndRecordsLedger(t *testing.T) {
	s := &fakeStore{cands: []Candidate{cand("https://a.example.com", "/.git/config", "vcs.git"), cand("https://b.example.com:8443", "/.git/config", "vcs.git")}}
	d := &fakeDisp{}
	res, err := newPlanner(s, d, rules{b: blocker{}}).RunTenant(context.Background(), shared.NewID())
	if err != nil || res.Planned != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(d.calls) != 1 || d.calls[0].TemplateIDs[0] != "git-config" || len(d.calls[0].Targets) != 2 {
		t.Fatalf("calls = %+v", d.calls)
	}
	if d.calls[0].Targets[0] != "https://a.example.com/.git/config" {
		t.Fatalf("target = %s", d.calls[0].Targets[0])
	}
	if len(s.planned) != 2 || s.planned[0].RunID == nil {
		t.Fatalf("ledger = %+v", s.planned)
	}
}

func TestExcludedPathIsNeverDispatched(t *testing.T) {
	s := &fakeStore{cands: []Candidate{cand("https://a.example.com", "/.git/config", "vcs.git"), cand("https://a.example.com", "/.env", "config.env")}}
	d := &fakeDisp{}
	res, err := newPlanner(s, d, rules{b: blocker{prefix: "/.git"}}).RunTenant(context.Background(), shared.NewID())
	if err != nil || res.Excluded != 1 || res.Planned != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	for _, c := range d.calls {
		for _, u := range c.Targets {
			if strings.Contains(u, ".git") {
				t.Fatalf("excluded path dispatched: %s", u)
			}
		}
	}
}

func TestFailsClosedWithoutExclusions(t *testing.T) {
	s := &fakeStore{cands: []Candidate{cand("https://a.example.com", "/.env", "config.env")}}
	d := &fakeDisp{}
	if _, err := newPlanner(s, d, rules{err: errors.New("db down")}).RunTenant(context.Background(), shared.NewID()); err == nil {
		t.Fatal("a failed exclusion load must stop the pass")
	}
	if _, err := newPlanner(s, d, nil).RunTenant(context.Background(), shared.NewID()); err == nil {
		t.Fatal("no rules wired must stop the pass")
	}
	if len(d.calls) != 0 || len(s.planned) != 0 {
		t.Fatal("something was planned without exclusions")
	}
}

func TestBudgetIsRespected(t *testing.T) {
	s := &fakeStore{used: 10, cands: []Candidate{cand("https://a.example.com", "/.env", "config.env")}}
	d := &fakeDisp{}
	res, _ := newPlanner(s, d, rules{b: blocker{}}).RunTenant(context.Background(), shared.NewID())
	if res.Planned != 0 || len(d.calls) != 0 || s.limit != 0 {
		t.Fatalf("budget spent but planned: %+v", res)
	}
	s = &fakeStore{used: 8}
	_, _ = newPlanner(s, d, rules{b: blocker{}}).RunTenant(context.Background(), shared.NewID())
	if s.limit != 2 {
		t.Fatalf("limit = %d, want the 2 left of the daily budget", s.limit)
	}
	s = &fakeStore{}
	_, _ = newPlanner(s, d, rules{b: blocker{}}).RunTenant(context.Background(), shared.NewID())
	if s.limit != 5 {
		t.Fatalf("limit = %d, want the pass cap 5", s.limit)
	}
}

func TestRefusedByGateIsLedgeredWithoutRunAndBusyIsNot(t *testing.T) {
	c1, c2 := cand("https://a.example.com", "/.env", "config.env"), cand("https://b.example.com", "/.env", "config.env")
	s := &fakeStore{cands: []Candidate{c1, c2}}
	d := &fakeDisp{deny: map[string]bool{"https://b.example.com/.env": true}}
	res, _ := newPlanner(s, d, rules{b: blocker{}}).RunTenant(context.Background(), shared.NewID())
	if res.Planned != 1 || res.Refused != 1 {
		t.Fatalf("res = %+v", res)
	}
	runs := 0
	for _, p := range s.planned {
		if p.RunID != nil {
			runs++
		}
	}
	if runs != 1 || len(s.planned) != 2 {
		t.Fatalf("ledger = %+v", s.planned)
	}
	s = &fakeStore{cands: []Candidate{c1}}
	d = &fakeDisp{err: scanapp.ErrWebVerifyBusy}
	res, _ = newPlanner(s, d, rules{b: blocker{}}).RunTenant(context.Background(), shared.NewID())
	if res.Busy != 1 || len(s.planned) != 0 {
		t.Fatalf("busy group recorded: %+v %+v", res, s.planned)
	}
}

func TestInvalidOriginsAreSkipped(t *testing.T) {
	s := &fakeStore{cands: []Candidate{
		cand("javascript:alert(1)", "/.env", "config.env"),
		cand("https://u:p@a.example.com", "/.env", "config.env"),
		cand("https://a.example.com/x?y=1", "/.env", "config.env"),
		cand("https://a.example.com", "/.env", "no.such.key"),
	}}
	d := &fakeDisp{}
	res, _ := newPlanner(s, d, rules{b: blocker{}}).RunTenant(context.Background(), shared.NewID())
	if res.Invalid != 4 || len(d.calls) != 0 {
		t.Fatalf("res=%+v calls=%d", res, len(d.calls))
	}
}

func TestDepthNeverPlansIntrusive(t *testing.T) {
	for _, depth := range scanworkflow.Depths() {
		p := ForDepth(depth)
		if p.Tier >= scopedom.TierIntrusive {
			t.Errorf("%s plans tier %v", depth, p.Tier)
		}
		if depth == scanworkflow.DepthPassive && p.Enabled {
			t.Error("a passive depth must not verify")
		}
	}
	st, _ := stage.Lookup(stage.VulnTemplates)
	if st.Tier >= stage.TierIntrusive {
		t.Fatal("the verification stage must be below T2")
	}
	if dast, _ := stage.Lookup(stage.DASTWeb); dast.Tier != stage.TierIntrusive {
		t.Fatal("dast.web is expected to be T2, never planned by verification")
	}
}
