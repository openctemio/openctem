package scan

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	freshdom "github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// evidence answers fixed observations per tenant and name.
type evidence struct {
	by    map[shared.ID]map[string]time.Time
	ids   map[string]shared.ID
	err   error
	asked []string
}

func (e *evidence) FreshestByName(_ context.Context, tenant shared.ID, names []string, classes []freshdom.Class) ([]freshdom.NameEvidence, error) {
	e.asked = names
	if e.err != nil {
		return nil, e.err
	}
	if !slices.Equal(classes, freshdom.ResolveEvidenceClasses) {
		return nil, errors.New("wrong classes")
	}
	var out []freshdom.NameEvidence
	for _, n := range names {
		if at, ok := e.by[tenant][n]; ok {
			out = append(out, freshdom.NameEvidence{AssetID: e.ids[n], Name: n, ObservedAt: at})
		}
	}
	return out, nil
}

type refreshes struct{ ids []shared.ID }

func (r *refreshes) RequestStale(_ context.Context, _ shared.ID, ids []shared.ID) {
	r.ids = append(r.ids, ids...)
}

func evidenceFixture(tenant shared.ID) (*evidence, *refreshes, *Service) {
	ev := &evidence{by: map[shared.ID]map[string]time.Time{tenant: {
		"fresh.example.com": time.Now().Add(-time.Hour),
		"dead.example.com":  time.Now().Add(-10 * 24 * time.Hour),
	}}, ids: map[string]shared.ID{"dead.example.com": shared.NewID(), "fresh.example.com": shared.NewID()}}
	rf := &refreshes{}
	s := &Service{}
	s.SetResolveEvidence(ev, rf)
	return ev, rf, s
}

// An active stage takes a name only with recent resolution evidence; a
// name the platform knows nothing about is handed on (the sensor resolves
// it); addresses and URLs are not names. A stale name's enrichment is asked
// for again.
func TestDropStaleNames(t *testing.T) {
	tenant := shared.NewID()
	ev, rf, s := evidenceFixture(tenant)
	targets := []string{"fresh.example.com", "DEAD.example.com.", "new.example.com", "198.51.100.7", "https://dead.example.com/", "198.51.100.0/24"}
	kept, stale, err := s.DropStaleNames(context.Background(), tenant, targets)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stale, []string{"DEAD.example.com."}) {
		t.Fatalf("stale = %v", stale)
	}
	if !slices.Equal(kept, []string{"fresh.example.com", "new.example.com", "198.51.100.7", "https://dead.example.com/", "198.51.100.0/24"}) {
		t.Fatalf("kept = %v", kept)
	}
	if !slices.Equal(ev.asked, []string{"fresh.example.com", "dead.example.com", "new.example.com"}) {
		t.Fatalf("asked for %v, want the names only, normalised", ev.asked)
	}
	if len(rf.ids) != 1 || rf.ids[0] != ev.ids["dead.example.com"] {
		t.Fatalf("refresh requested for %v", rf.ids)
	}
}

// Another tenant's evidence never decides: the same name stale in tenant
// B is handed on for tenant A, which has no evidence for it.
func TestDropStaleNames_CrossTenant(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	_, rf, s := evidenceFixture(tenantB)
	kept, stale, err := s.DropStaleNames(context.Background(), tenantA, []string{"dead.example.com"})
	if err != nil || len(stale) != 0 || len(kept) != 1 || len(rf.ids) != 0 {
		t.Fatalf("tenant A: kept %v stale %v refresh %v err %v", kept, stale, rf.ids, err)
	}
}

// A failed evidence read refuses the dispatch; without a reader every name
// is handed on.
func TestDropStaleNames_FailClosedAndUnwired(t *testing.T) {
	tenant := shared.NewID()
	ev, _, s := evidenceFixture(tenant)
	ev.err = errors.New("db down")
	if _, _, err := s.DropStaleNames(context.Background(), tenant, []string{"dead.example.com"}); err == nil {
		t.Fatal("a failed evidence read was ignored")
	}
	kept, stale, err := (&Service{}).DropStaleNames(context.Background(), tenant, []string{"dead.example.com"})
	if err != nil || len(stale) != 0 || len(kept) != 1 {
		t.Fatalf("unwired: %v %v %v", kept, stale, err)
	}
}

// A single-scanner run records what it left out and refuses a run left
// with nothing to scan.
func TestDropStaleRunNames(t *testing.T) {
	tenant := shared.NewID()
	_, _, s := evidenceFixture(tenant)
	sc := &scan.Scan{TenantID: tenant, Name: "web"}
	r := &resolvedTargets{Targets: []string{"fresh.example.com", "dead.example.com"}}
	rc := map[string]any{}
	if err := s.dropStaleRunNames(context.Background(), sc, r, rc); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.Targets, []string{"fresh.example.com"}) || rc[RunContextKeyNotResolving] != 1 || len(r.Warnings) != 1 ||
		!strings.Contains(r.Warnings[0], "dead.example.com") {
		t.Fatalf("targets %v context %v warnings %v", r.Targets, rc, r.Warnings)
	}
	r = &resolvedTargets{Targets: []string{"dead.example.com"}}
	err := s.dropStaleRunNames(context.Background(), sc, r, map[string]any{})
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != CodeNoResolvingTargets {
		t.Fatalf("err = %v, want %s", err, CodeNoResolvingTargets)
	}
}

// The platform turns the wildcard-DNS filter on for dnsx jobs that do not
// set it; a step's own choice is kept; other tools are untouched.
func TestWildcardFilterDefault(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{}}
	cfg := func(tool string, caps []string, c map[string]any) map[string]any {
		t.Helper()
		p, err := StepCommandPayload(run, &scanworkflow.Step{ID: shared.NewID(), StepKey: "s", Capabilities: caps, Config: c},
			tool, shared.NewID().String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := p[scanworkflow.PayloadKeyConfig].(map[string]any)
		return out
	}
	if got := cfg("dnsx", []string{"resolve.dns"}, nil); got["wildcard_filter"] != true {
		t.Fatalf("dnsx config = %v, want the filter on", got)
	}
	if got := cfg("dnsx", []string{"resolve.dns"}, map[string]any{"wildcard_filter": false}); got["wildcard_filter"] != false {
		t.Fatalf("dnsx config = %v, want the step's choice kept", got)
	}
	if got := cfg("naabu", nil, nil); got["wildcard_filter"] != nil {
		t.Fatalf("naabu config = %v", got)
	}
}

// A name a selector or an asset group added is taken by an active scanner
// only with proof that it resolves; a typed name without evidence is still
// handed on; the scan's option to include names that do not resolve hands
// every inventory name on.
func TestDropStaleRunNames_InventoryNamesNeedProof(t *testing.T) {
	tenant := shared.NewID()
	_, rf, s := evidenceFixture(tenant)
	neverID := shared.NewID()
	newResolved := func() *resolvedTargets {
		return &resolvedTargets{
			Targets:   []string{"fresh.example.com", "never.example.com", "typed.example.com", "198.51.100.7"},
			Inventory: map[string]shared.ID{"fresh.example.com": shared.NewID(), "never.example.com": neverID},
		}
	}
	sc := &scan.Scan{TenantID: tenant, Name: "web"}
	r := newResolved()
	rc := map[string]any{}
	if err := s.dropStaleRunNames(context.Background(), sc, r, rc); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.Targets, []string{"fresh.example.com", "typed.example.com", "198.51.100.7"}) ||
		!slices.Equal(r.NotResolving, []string{"never.example.com"}) || rc[RunContextKeyNotResolving] != 1 {
		t.Fatalf("targets %v not resolving %v context %v", r.Targets, r.NotResolving, rc)
	}
	if !slices.Contains(rf.ids, neverID) {
		t.Fatalf("enrichment of the name without proof not requested: %v", rf.ids)
	}

	sc.TargetOptions.IncludeUnresolved = true
	r = newResolved()
	if err := s.dropStaleRunNames(context.Background(), sc, r, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if len(r.Targets) != 4 || len(r.NotResolving) != 0 {
		t.Fatalf("include unresolved: targets %v not resolving %v", r.Targets, r.NotResolving)
	}
}

// Another tenant's proof never counts: a name that resolves in tenant B is
// still a name without proof in tenant A.
func TestDropStaleRunNames_InventoryProofIsPerTenant(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	_, _, s := evidenceFixture(tenantB)
	r := &resolvedTargets{Targets: []string{"fresh.example.com", "a.example.com"}, Inventory: map[string]shared.ID{"fresh.example.com": shared.NewID()}}
	if err := s.dropStaleRunNames(context.Background(), &scan.Scan{TenantID: tenantA}, r, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.Targets, []string{"a.example.com"}) || !slices.Equal(r.NotResolving, []string{"fresh.example.com"}) {
		t.Fatalf("tenant A: targets %v not resolving %v", r.Targets, r.NotResolving)
	}
}
