package vulnmatch

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func match(asset shared.ID, cve string, linkConf int) softwarematch.Match {
	return softwarematch.Match{
		AssetID: asset, LinkConfidence: linkConf, Port: 443, Transport: "tcp", Location: "tcp/443",
		ProductID: shared.NewID(), Product: "nginx", Vendor: "F5", VersionID: shared.NewID(), Version: "1.18.0",
		Result: softwarematch.VersionVuln{CVEID: cve, RangeText: "< 1.20.1"},
		CVE:    softwarematch.CVEInfo{ID: cve, Severity: "high", Description: "d"},
	}
}

func TestPasses(t *testing.T) {
	on := tenant.VulnMatchingSettings{Enabled: true}
	base := match(shared.NewID(), "CVE-2021-23017", 65)
	res := vulnmatch.Result{VulnID: base.Result.CVEID}
	cases := []struct {
		name   string
		policy tenant.VulnMatchingSettings
		mut    func(*softwarematch.Match, *vulnmatch.Result) int
		want   bool
	}{
		{"default passes", on, func(*softwarematch.Match, *vulnmatch.Result) int { return 65 }, true},
		{"below confidence", on, func(*softwarematch.Match, *vulnmatch.Result) int { return 64 }, false},
		{"custom confidence", tenant.VulnMatchingSettings{Enabled: true, MinConfidence: 80}, func(*softwarematch.Match, *vulnmatch.Result) int { return 79 }, false},
		{"all versions never", on, func(_ *softwarematch.Match, r *vulnmatch.Result) int { r.AllVersions = true; return 95 }, false},
		{"distro build excluded", on, func(m *softwarematch.Match, _ *vulnmatch.Result) int { m.Qualifier = "ubuntu"; return 90 }, false},
		{"distro build included", tenant.VulnMatchingSettings{Enabled: true, IncludeDistroBuilds: true}, func(m *softwarematch.Match, _ *vulnmatch.Result) int { m.Qualifier = "ubuntu"; return 90 }, true},
		{"medium below high", on, func(m *softwarematch.Match, _ *vulnmatch.Result) int { m.CVE.Severity = "medium"; return 90 }, false},
		{"medium with kev", on, func(m *softwarematch.Match, _ *vulnmatch.Result) int {
			m.CVE.Severity = "medium"
			m.CVE.InKEV = true
			return 90
		}, true},
		{"low with epss", on, func(m *softwarematch.Match, _ *vulnmatch.Result) int {
			m.CVE.Severity = "low"
			m.CVE.EPSS = 0.2
			return 90
		}, true},
		{"medium allowed", tenant.VulnMatchingSettings{Enabled: true, MinSeverity: "medium"}, func(m *softwarematch.Match, _ *vulnmatch.Result) int { m.CVE.Severity = "medium"; return 90 }, true},
		{"internal asset when internet only", tenant.VulnMatchingSettings{Enabled: true, InternetFacingOnly: true}, func(*softwarematch.Match, *vulnmatch.Result) int { return 90 }, false},
		{"internet asset when internet only", tenant.VulnMatchingSettings{Enabled: true, InternetFacingOnly: true}, func(m *softwarematch.Match, _ *vulnmatch.Result) int { m.InternetFacing = true; return 90 }, true},
		{"muted", tenant.VulnMatchingSettings{Enabled: true, MutedProducts: []string{"NGINX"}}, func(*softwarematch.Match, *vulnmatch.Result) int { return 90 }, false},
		{"no severity", on, func(m *softwarematch.Match, _ *vulnmatch.Result) int { m.CVE.Severity = ""; return 90 }, false},
	}
	for _, c := range cases {
		m, r := base, res
		conf := c.mut(&m, &r)
		if got := Passes(c.policy, m, r, conf); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestEvaluateVersion(t *testing.T) {
	cond := shared.NewID()
	ranges := []vulnmatch.Range{
		{ID: "11", VulnID: "CVE-1", Scheme: vulnmatch.SchemeGeneric, End: "1.20.1"},
		{ID: "12", VulnID: "CVE-2", Scheme: vulnmatch.SchemeGeneric, Condition: cond.String()},
		{ID: "13", VulnID: "CVE-3", Scheme: vulnmatch.SchemeGeneric, End: "1.0"},
	}
	got := EvaluateVersion(softwarematch.Version{Raw: "1.18.0", Scheme: vulnmatch.SchemeGeneric}, ranges)
	if len(got) != 2 || got[0].AffectedID != 11 || got[0].RangeText != "< 1.20.1" || got[0].AllVersions {
		t.Fatalf("got %+v", got)
	}
	if !got[1].AllVersions || got[1].ConditionProductID == nil || *got[1].ConditionProductID != cond {
		t.Fatalf("got %+v", got[1])
	}
	if got := EvaluateVersion(softwarematch.Version{Raw: "latest", Scheme: vulnmatch.SchemeGeneric}, ranges); len(got) != 0 {
		t.Fatalf("unparseable version matched: %+v", got)
	}
}

func TestCapPotentialPriority(t *testing.T) {
	mk := func(conf int, class vulnerability.PriorityClass, kev bool) *vulnerability.Finding {
		f, _ := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceVA, softwarematch.ToolName, vulnerability.SeverityHigh, "m")
		c := conf
		_ = f.SetConfidence(&c)
		f.SetPriorityClassification(class, "x")
		if kev {
			f.SetIsInKEV(true)
		}
		return f
	}
	cases := []struct {
		conf  int
		class vulnerability.PriorityClass
		kev   bool
		want  vulnerability.PriorityClass
	}{
		{65, vulnerability.PriorityP0, false, vulnerability.PriorityP2},
		{65, vulnerability.PriorityP1, false, vulnerability.PriorityP2},
		{65, vulnerability.PriorityP3, false, vulnerability.PriorityP3},
		{65, vulnerability.PriorityP0, true, vulnerability.PriorityP0},
		{80, vulnerability.PriorityP0, false, vulnerability.PriorityP0},
	}
	for i, c := range cases {
		f := mk(c.conf, c.class, c.kev)
		CapPotentialPriority(f)
		if got := *f.PriorityClass(); got != c.want {
			t.Errorf("case %d: %s, want %s", i, got, c.want)
		}
	}
}

// fakeStore is an in-memory softwarematch.Store for the reconcile logic.
type fakeStore struct {
	matches    []softwarematch.Match
	existing   []softwarematch.MatcherFinding
	openCVEs   map[shared.ID]map[string]bool
	taken      map[string]bool
	links      map[softwarematch.LinkKey]softwarematch.LinkInfo
	closed     map[softwarematch.CloseKind][]shared.ID
	reopened   []shared.ID
	queued     []shared.ID
	defs       int
	pending    []softwarematch.Version
	replaced   map[shared.ID][]softwarematch.VersionVuln
	dequeueIDs []shared.ID
	state      map[string]time.Time
}

func newFakeStore() *fakeStore {
	return &fakeStore{closed: map[softwarematch.CloseKind][]shared.ID{}, replaced: map[shared.ID][]softwarematch.VersionVuln{},
		state: map[string]time.Time{}, links: map[softwarematch.LinkKey]softwarematch.LinkInfo{}}
}

func (f *fakeStore) PendingVersions(context.Context, int) ([]softwarematch.Version, error) {
	p := f.pending
	f.pending = nil
	return p, nil
}
func (f *fakeStore) RangesForProduct(context.Context, shared.ID) ([]softwarematch.AffectedRange, error) {
	return []softwarematch.AffectedRange{{ID: 7, Range: vulnmatch.Range{ID: "7", VulnID: "CVE-9", Scheme: vulnmatch.SchemeGeneric, End: "2"}}}, nil
}
func (f *fakeStore) ReplaceVersionVulns(_ context.Context, id shared.ID, v []softwarematch.VersionVuln) (bool, error) {
	f.replaced[id] = v
	return len(v) > 0, nil
}
func (f *fakeStore) ResetVersionsForCVEsSince(_ context.Context, since time.Time, _ int) (time.Time, int, error) {
	return since, 0, nil
}
func (f *fakeStore) State(_ context.Context, n string) (time.Time, error) { return f.state[n], nil }
func (f *fakeStore) SetState(_ context.Context, n string, at time.Time) error {
	f.state[n] = at
	return nil
}
func (f *fakeStore) QueueTenants(_ context.Context, ids []shared.ID) error {
	f.queued = append(f.queued, ids...)
	return nil
}
func (f *fakeStore) QueueAllTenantsWithSoftware(context.Context) (int, error) { return 0, nil }
func (f *fakeStore) DequeueTenants(context.Context, int) ([]shared.ID, error) {
	ids := f.dequeueIDs
	f.dequeueIDs = nil
	return ids, nil
}
func (f *fakeStore) TenantMatches(context.Context, shared.ID, time.Time, int) ([]softwarematch.Match, error) {
	return f.matches, nil
}
func (f *fakeStore) MatcherFindings(context.Context, shared.ID) ([]softwarematch.MatcherFinding, error) {
	return f.existing, nil
}
func (f *fakeStore) OpenCVEsOnAssets(context.Context, shared.ID, []shared.ID) (map[shared.ID]map[string]bool, error) {
	return f.openCVEs, nil
}
func (f *fakeStore) ExistingFingerprints(context.Context, shared.ID, []string) (map[string]bool, error) {
	return f.taken, nil
}
func (f *fakeStore) LinkStates(_ context.Context, _ shared.ID, keys []softwarematch.LinkKey, _ time.Time) (map[softwarematch.LinkKey]softwarematch.LinkInfo, error) {
	out := map[softwarematch.LinkKey]softwarematch.LinkInfo{}
	for _, k := range keys {
		out[k] = f.links[k]
	}
	return out, nil
}
func (f *fakeStore) CloseFindings(_ context.Context, _ shared.ID, ids []shared.ID, kind softwarematch.CloseKind) ([]shared.ID, error) {
	f.closed[kind] = append(f.closed[kind], ids...)
	return ids, nil
}
func (f *fakeStore) ReopenFindings(_ context.Context, _ shared.ID, ids []shared.ID) ([]shared.ID, error) {
	f.reopened = append(f.reopened, ids...)
	return ids, nil
}
func (f *fakeStore) EnsureDefinitions(_ context.Context, cves []softwarematch.CVEInfo) (map[string]shared.ID, error) {
	f.defs += len(cves)
	out := map[string]shared.ID{}
	for _, c := range cves {
		out[c.ID] = shared.NewID()
	}
	return out, nil
}

type fakePolicy struct{ s tenant.VulnMatchingSettings }

func (p fakePolicy) VulnMatchingPolicy(context.Context, shared.ID) (tenant.VulnMatchingSettings, error) {
	return p.s, nil
}

type fakeWriter struct{ created []*vulnerability.Finding }

func (w *fakeWriter) CreateBatchWithResult(_ context.Context, fs []*vulnerability.Finding) (*vulnerability.BatchCreateResult, error) {
	w.created = append(w.created, fs...)
	return &vulnerability.BatchCreateResult{Created: len(fs)}, nil
}

func newSvc(store *fakeStore, enabled bool) (*Service, *fakeWriter) {
	w := &fakeWriter{}
	return NewService(store, fakePolicy{tenant.VulnMatchingSettings{Enabled: enabled}}, w, logger.NewNop()), w
}

func fp(m softwarematch.Match) string {
	k, _ := vulnerability.NetworkIdentity(m.AssetID.String(), m.Result.CVEID, "", m.Port, m.Transport)
	return k.Fingerprint()
}

func TestReconcile_CreatesFindingWithEvidence(t *testing.T) {
	store := newFakeStore()
	asset := shared.NewID()
	m := match(asset, "CVE-2021-23017", 80)
	store.matches = []softwarematch.Match{m}
	svc, w := newSvc(store, true)
	var st Stats
	if err := svc.ReconcileTenant(context.Background(), shared.NewID(), &st); err != nil {
		t.Fatal(err)
	}
	if len(w.created) != 1 || st.Created != 1 || store.defs != 1 {
		t.Fatalf("created %d", len(w.created))
	}
	f := w.created[0]
	if f.ToolName() != softwarematch.ToolName || f.Source() != vulnerability.FindingSourceVA || f.CVEID() != "CVE-2021-23017" ||
		f.Fingerprint() != fp(m) || *f.Confidence() != 80 || f.AssetID() != asset {
		t.Fatalf("finding %+v", f)
	}
	vm, _ := f.Metadata()["version_match"].(map[string]any)
	if vm["range"] != "< 1.20.1" || vm["label"] != "likely" || vm["version"] != "1.18.0" {
		t.Fatalf("evidence %+v", vm)
	}
}

func TestReconcile_DisabledDoesNothing(t *testing.T) {
	store := newFakeStore()
	store.matches = []softwarematch.Match{match(shared.NewID(), "CVE-1", 80)}
	store.existing = []softwarematch.MatcherFinding{{ID: shared.NewID(), Status: "new", Fingerprint: "x"}}
	svc, w := newSvc(store, false)
	var st Stats
	_ = svc.ReconcileTenant(context.Background(), shared.NewID(), &st)
	if len(w.created) != 0 || len(store.closed) != 0 {
		t.Fatal("acted while disabled")
	}
}

func TestReconcile_NoDuplicates(t *testing.T) {
	asset := shared.NewID()
	m := match(asset, "CVE-2021-23017", 80)
	for name, setup := range map[string]func(*fakeStore){
		"open finding of another tool on the asset": func(s *fakeStore) {
			s.openCVEs = map[shared.ID]map[string]bool{asset: {"CVE-2021-23017": true}}
		},
		"identity owned by another tool": func(s *fakeStore) { s.taken = map[string]bool{fp(m): true} },
		"already open": func(s *fakeStore) {
			s.existing = []softwarematch.MatcherFinding{{ID: shared.NewID(), Fingerprint: fp(m), Status: "new"}}
		},
		"dismissed by a person": func(s *fakeStore) {
			s.existing = []softwarematch.MatcherFinding{{ID: shared.NewID(), Fingerprint: fp(m), Status: "false_positive"}}
		},
	} {
		store := newFakeStore()
		store.matches = []softwarematch.Match{m}
		setup(store)
		svc, w := newSvc(store, true)
		var st Stats
		if err := svc.ReconcileTenant(context.Background(), shared.NewID(), &st); err != nil {
			t.Fatal(err)
		}
		if len(w.created) != 0 || len(store.reopened) != 0 {
			t.Errorf("%s: created %d reopened %d", name, len(w.created), len(store.reopened))
		}
	}
}

func TestReconcile_ReopensWhatItClosed(t *testing.T) {
	m := match(shared.NewID(), "CVE-2021-23017", 80)
	store := newFakeStore()
	store.matches = []softwarematch.Match{m}
	id := shared.NewID()
	store.existing = []softwarematch.MatcherFinding{{ID: id, Fingerprint: fp(m), Status: "resolved"}}
	svc, w := newSvc(store, true)
	var st Stats
	_ = svc.ReconcileTenant(context.Background(), shared.NewID(), &st)
	if len(store.reopened) != 1 || store.reopened[0] != id || len(w.created) != 0 {
		t.Fatalf("reopened %v created %d", store.reopened, len(w.created))
	}
}

func TestReconcile_ClosesByReason(t *testing.T) {
	asset, product := shared.NewID(), shared.NewID()
	mk := func(state softwarematch.LinkState, evaluated, rejected bool) (*fakeStore, shared.ID) {
		store := newFakeStore()
		v := shared.NewID()
		id := shared.NewID()
		store.existing = []softwarematch.MatcherFinding{{ID: id, AssetID: asset, CVEID: "CVE-1", Fingerprint: "gone",
			Status: "new", ProductID: &product, VersionID: &v, Location: "tcp/443", CVERejected: rejected}}
		store.links[softwarematch.LinkKey{AssetID: asset, ProductID: product, VersionID: v, Location: "tcp/443"}] =
			softwarematch.LinkInfo{State: state, VersionEvaluated: evaluated}
		return store, id
	}
	cases := []struct {
		name      string
		state     softwarematch.LinkState
		evaluated bool
		rejected  bool
		want      softwarematch.CloseKind
	}{
		{"upgraded", softwarematch.LinkUpgraded, true, false, softwarematch.CloseVersionChanged},
		{"gone", softwarematch.LinkGone, true, false, softwarematch.CloseNotObserved},
		{"advisory changed", softwarematch.LinkCurrent, true, false, softwarematch.CloseAdvisoryUpdated},
		{"not yet re-evaluated", softwarematch.LinkCurrent, false, false, ""},
		{"rejected CVE", softwarematch.LinkCurrent, true, true, ""},
	}
	for _, c := range cases {
		store, id := mk(c.state, c.evaluated, c.rejected)
		svc, _ := newSvc(store, true)
		var st Stats
		if err := svc.ReconcileTenant(context.Background(), shared.NewID(), &st); err != nil {
			t.Fatal(err)
		}
		total := 0
		for _, ids := range store.closed {
			total += len(ids)
		}
		if c.want == "" {
			if total != 0 {
				t.Errorf("%s: closed %v", c.name, store.closed)
			}
			continue
		}
		if got := store.closed[c.want]; len(got) != 1 || got[0] != id || total != 1 {
			t.Errorf("%s: closed %v", c.name, store.closed)
		}
	}
}

// A finding whose match is still there (even below the policy now) stays.
func TestReconcile_KeepsMatchedBelowPolicy(t *testing.T) {
	m := match(shared.NewID(), "CVE-1", 30) // below min confidence
	store := newFakeStore()
	store.matches = []softwarematch.Match{m}
	store.existing = []softwarematch.MatcherFinding{{ID: shared.NewID(), Fingerprint: fp(m), Status: "new",
		ProductID: &m.ProductID, VersionID: &m.VersionID}}
	svc, w := newSvc(store, true)
	var st Stats
	_ = svc.ReconcileTenant(context.Background(), shared.NewID(), &st)
	if len(store.closed) != 0 || len(w.created) != 0 {
		t.Fatalf("closed %v created %d", store.closed, len(w.created))
	}
}

func TestRun_EvaluatesQueuesAndReconciles(t *testing.T) {
	store := newFakeStore()
	v := softwarematch.Version{ID: shared.NewID(), ProductID: shared.NewID(), Raw: "1.0", Scheme: vulnmatch.SchemeGeneric}
	store.pending = []softwarematch.Version{v}
	t1 := shared.NewID()
	store.dequeueIDs = []shared.ID{t1}
	store.matches = []softwarematch.Match{match(shared.NewID(), "CVE-1", 80)}
	svc, w := newSvc(store, true)
	st, err := svc.Run(context.Background(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if st.VersionsEvaluated != 1 || len(store.replaced[v.ID]) != 1 || store.replaced[v.ID][0].CVEID != "CVE-9" {
		t.Fatalf("evaluation %+v %+v", st, store.replaced)
	}
	if st.Tenants != 1 || len(w.created) != 1 || store.state[stateLastSweep].IsZero() {
		t.Fatalf("stats %+v", st)
	}
}

func TestSoftwareChangedQueues(t *testing.T) {
	store := newFakeStore()
	svc, _ := newSvc(store, true)
	id := shared.NewID()
	svc.SoftwareChanged(id, nil)
	if len(store.queued) != 1 || store.queued[0] != id {
		t.Fatal(store.queued)
	}
}
