package attack

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakePathFindings struct {
	byAsset map[string]vulnerability.AssetPathFindings
	asked   []string
}

func (f *fakePathFindings) AttackPathFindings(_ context.Context, _ shared.ID, ids []string) (map[string]vulnerability.AssetPathFindings, error) {
	f.asked = append(f.asked, ids...)
	out := map[string]vulnerability.AssetPathFindings{}
	for _, id := range ids {
		if v, ok := f.byAsset[id]; ok {
			out[id] = v
		}
	}
	return out, nil
}

func fptr(v float64) *float64 { return &v }

func lead(title, sev string, epss *float64, kev bool) vulnerability.AssetPathFindings {
	return vulnerability.AssetPathFindings{
		OpenCount: 3, KEVCount: map[bool]int{true: 1}[kev],
		Lead: &vulnerability.PathLeadFinding{ID: shared.NewID().String(), Title: title, Severity: sev, EPSS: epss, KEV: kev},
	}
}

// pathFixture is the graph of the attack-path mockup: vpn (internet-facing)
// reaches billing-db through jump-host or through ci-runner.
type pathFixture struct {
	vpn, jump, ci, db asset.AssetNode
	svc               *SurfaceService
	findings          *fakePathFindings
}

func newPathFixture(t *testing.T) *pathFixture {
	t.Helper()
	f := &pathFixture{
		vpn:  uuidNode("vpn-gw-hq", "public", 50),
		jump: uuidNode("jump-host-02", "private", 40),
		ci:   uuidNode("ci-runner-3", "private", 30),
		db:   uuidNode("billing-db", "private", 90),
	}
	f.db.IsCrownJewel = true
	edges := []asset.RelationshipEdge{
		edge(f.vpn.ID, f.jump.ID, asset.RelTypeHasAccessTo),
		edge(f.jump.ID, f.db.ID, asset.RelTypeAuthenticatesTo),
		edge(f.vpn.ID, f.ci.ID, asset.RelTypeHasAccessTo),
		edge(f.ci.ID, f.db.ID, asset.RelTypeHasAccessTo),
	}
	f.findings = &fakePathFindings{byAsset: map[string]vulnerability.AssetPathFindings{
		f.vpn.ID:  lead("CVE-2026-30112", "critical", fptr(0.88), true),
		f.jump.ID: lead("SSH key reuse", "high", fptr(0.6), false),
		f.ci.ID:   lead("Runner token", "medium", fptr(0.3), false),
		f.db.ID:   lead("DB admin reachable", "high", fptr(0.4), false),
	}}
	f.svc = NewSurfaceService(&fakeGraphNodes{nodes: []asset.AssetNode{f.vpn, f.jump, f.ci, f.db}}, &fakeGraphEdges{edges: edges}, logger.NewNop())
	f.svc.SetPathFindingReader(f.findings)
	f.svc.SetDataScope(ownerEnforcer())
	return f
}

func nodeByKey(d *PathDetail, key string) PathNode {
	for _, n := range d.Nodes {
		if n.Key == key {
			return n
		}
	}
	return PathNode{}
}

func TestPathDetail_RoutesLikelihoodAndChokePoints(t *testing.T) {
	f := newPathFixture(t)
	d, err := f.svc.PathDetailForCaller(context.Background(), shared.NewID(), f.db.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 2 || d.TotalPaths != 2 || d.Capped {
		t.Fatalf("paths = %d total = %d capped = %v, want 2, 2, false", len(d.Paths), d.TotalPaths, d.Capped)
	}
	// The most likely route of the shortest length comes first.
	first := d.Paths[0]
	names := []string{}
	for _, k := range first.Nodes {
		names = append(names, nodeByKey(d, k).Name)
	}
	if fmt.Sprint(names) != "[vpn-gw-hq jump-host-02 billing-db]" {
		t.Fatalf("first route = %v", names)
	}
	if first.Likelihood == nil || math.Abs(*first.Likelihood-0.9*0.6*0.4) > 1e-9 {
		t.Fatalf("likelihood = %v, want the product of the step weights", first.Likelihood)
	}
	if first.Length != 2 || first.KEVSteps != 1 {
		t.Fatalf("length %d kev steps %d, want 2 and 1", first.Length, first.KEVSteps)
	}
	tgt := nodeByKey(d, d.Target)
	if tgt.Role != PathRoleTarget || !tgt.IsCrownJewel || tgt.AssetID != f.db.ID {
		t.Fatalf("target node = %+v", tgt)
	}
	// Choke points: the entry cuts both routes; then the hops by weight; the
	// target is never one.
	got := []string{}
	for _, c := range d.ChokePoints {
		got = append(got, fmt.Sprintf("%s:%d", nodeByKey(d, c.Node).Name, c.Breaks))
	}
	if fmt.Sprint(got) != "[vpn-gw-hq:2 jump-host-02:1 ci-runner-3:1]" {
		t.Fatalf("choke points = %v", got)
	}
	// The step from the internet onto the entry is used by both routes.
	var internet *PathEdge
	for i := range d.Edges {
		if d.Edges[i].From == "" {
			internet = &d.Edges[i]
		}
	}
	if internet == nil || len(internet.Paths) != 2 || nodeByKey(d, internet.To).Name != "vpn-gw-hq" {
		t.Fatalf("internet edge = %+v", internet)
	}
	if len(d.Edges) != 5 {
		t.Fatalf("edges = %d, want 5 (internet + 4 relationships)", len(d.Edges))
	}
	entry := nodeByKey(d, first.Nodes[0])
	if entry.Role != PathRoleEntry || entry.Basis != PathBasisKEV || *entry.Weight != vulnerability.PathWeightKEV {
		t.Fatalf("entry basis %q weight %v, want the KEV floor (0.9 > EPSS 0.88)", entry.Basis, entry.Weight)
	}
	if entry.Finding == nil || !entry.Finding.KEV || entry.OpenFindings != 3 {
		t.Fatalf("entry finding = %+v open %d", entry.Finding, entry.OpenFindings)
	}
}

func TestStepWeight_Bases(t *testing.T) {
	cases := []struct {
		name  string
		in    vulnerability.AssetPathFindings
		w     float64
		basis string
	}{
		{"no finding is assumed", vulnerability.AssetPathFindings{OpenCount: 2}, 1, PathBasisAssumed},
		{"epss above floors", lead("x", "low", fptr(0.7), false), 0.7, PathBasisEPSS},
		{"kev floor", lead("x", "medium", fptr(0.2), true), vulnerability.PathWeightKEV, PathBasisKEV},
		{"severity floor without epss", lead("x", "critical", nil, false), 0.5, PathBasisSeverity},
	}
	for _, c := range cases {
		w, b := stepWeight(c.in)
		if w != c.w || b != c.basis {
			t.Errorf("%s: got %v/%s, want %v/%s", c.name, w, b, c.w, c.basis)
		}
	}
}

// A route through a second internet-facing asset is the shorter route from
// that asset, so it is not listed twice.
func TestEnumeratePaths_NoRouteThroughAnotherEntry(t *testing.T) {
	a := node("a", "public", "low", false)
	b := node("b", "public", "low", false)
	db := node("db", "private", "critical", true)
	edges := []asset.RelationshipEdge{
		edge("a", "b", asset.RelTypeHasAccessTo),
		edge("b", "db", asset.RelTypeHasAccessTo),
	}
	routes, total, capped, ok := enumeratePaths([]asset.AssetNode{a, b, db}, edges, "db")
	if !ok || capped || total != 1 || fmt.Sprint(routes[0].nodes) != "[b db]" {
		t.Fatalf("routes = %v total %d capped %v ok %v", routes, total, capped, ok)
	}
}

// Control relationships (protected_by, monitors) are not routes.
func TestEnumeratePaths_OnlyAttackRelationships(t *testing.T) {
	a := node("a", "public", "low", false)
	db := node("db", "private", "critical", false)
	edges := []asset.RelationshipEdge{edge("a", "db", asset.RelTypeMonitors)}
	routes, _, _, ok := enumeratePaths([]asset.AssetNode{a, db}, edges, "db")
	if !ok || len(routes) != 0 {
		t.Fatalf("routes = %v, want none", routes)
	}
}

func TestPathDetail_UnreachableAndUnknownTarget(t *testing.T) {
	f := newPathFixture(t)
	lone := uuidNode("lone", "private", 10)
	f.svc.assetRepo = &fakeGraphNodes{nodes: []asset.AssetNode{f.vpn, f.jump, f.ci, f.db, lone}}
	d, err := f.svc.PathDetailForCaller(context.Background(), shared.NewID(), lone.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 0 || len(d.Nodes) != 1 || nodeByKey(d, d.Target).Name != "lone" {
		t.Fatalf("unreachable target: %+v", d)
	}
	// An asset that is not in this tenant's graph is "not found" (404), the
	// same answer as an asset of another tenant.
	for _, id := range []string{shared.NewID().String(), "not-a-uuid"} {
		if _, err := f.svc.PathDetailForCaller(context.Background(), shared.NewID(), id); !errors.Is(err, ErrPathTargetNotFound) {
			t.Fatalf("target %q: err = %v, want ErrPathTargetNotFound", id, err)
		}
	}
}

func TestPathDetail_UnwiredEnforcerFailsClosed(t *testing.T) {
	svc := NewSurfaceService(nil, nil, logger.NewNop())
	if _, err := svc.PathDetailForCaller(context.Background(), shared.NewID(), shared.NewID().String()); !errors.Is(err, datascope.ErrNotConfigured) {
		t.Fatalf("err = %v, want datascope.ErrNotConfigured", err)
	}
}

// A restricted member: a target outside their scope is 404; inside it, steps
// outside the scope are hidden (no id, name, type, finding or weight), their
// findings are never read, they are no choke point, and the likelihood of a
// route through one is withheld.
func TestPathDetail_DataScope(t *testing.T) {
	f := newPathFixture(t)
	id := func(n asset.AssetNode) shared.ID { v, _ := shared.IDFromString(n.ID); return v }

	f.svc.SetDataScope(restrictedEnforcer(id(f.vpn), id(f.ci)))
	if _, err := f.svc.PathDetailForCaller(context.Background(), shared.NewID(), f.db.ID); !errors.Is(err, ErrPathTargetNotFound) {
		t.Fatalf("out-of-scope target: err = %v, want ErrPathTargetNotFound", err)
	}

	f.findings.asked = nil
	f.svc.SetDataScope(restrictedEnforcer(id(f.vpn), id(f.ci), id(f.db)))
	d, err := f.svc.PathDetailForCaller(context.Background(), shared.NewID(), f.db.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range f.findings.asked {
		if a == f.jump.ID {
			t.Fatal("findings were read for a hidden step")
		}
	}
	hidden := 0
	for _, n := range d.Nodes {
		if !n.Hidden {
			continue
		}
		hidden++
		if n.AssetID != "" || n.Name != "" || n.AssetType != "" || n.Finding != nil || n.Weight != nil || n.OpenFindings != 0 || n.Basis != "" {
			t.Fatalf("hidden node leaks: %+v", n)
		}
	}
	if hidden != 1 {
		t.Fatalf("hidden nodes = %d, want 1 (jump-host)", hidden)
	}
	for _, p := range d.Paths {
		through := false
		for _, k := range p.Nodes {
			through = through || nodeByKey(d, k).Hidden
		}
		if through != (p.Likelihood == nil) {
			t.Fatalf("route %v: hidden step %v but likelihood %v", p.Nodes, through, p.Likelihood)
		}
	}
	for _, c := range d.ChokePoints {
		if nodeByKey(d, c.Node).Hidden {
			t.Fatal("a hidden step is listed as a choke point")
		}
	}
	for _, e := range d.Edges {
		if (nodeByKey(d, e.From).Hidden || nodeByKey(d, e.To).Hidden) && e.Relationship != "" {
			t.Fatalf("edge to a hidden step names its relationship: %+v", e)
		}
	}
}

// A dense graph returns at most pathShowCap routes and says how many it found.
func TestPathDetail_CapsRoutes(t *testing.T) {
	entry := uuidNode("entry", "public", 1)
	target := uuidNode("target", "private", 1)
	nodes := []asset.AssetNode{entry, target}
	var edges []asset.RelationshipEdge
	var layer1 []asset.AssetNode
	for i := 0; i < 5; i++ {
		n := uuidNode(fmt.Sprintf("l1-%d", i), "private", 1)
		layer1 = append(layer1, n)
		nodes = append(nodes, n)
		edges = append(edges, edge(entry.ID, n.ID, asset.RelTypeHasAccessTo))
	}
	for i := 0; i < 5; i++ {
		n := uuidNode(fmt.Sprintf("l2-%d", i), "private", 1)
		nodes = append(nodes, n)
		for _, p := range layer1 {
			edges = append(edges, edge(p.ID, n.ID, asset.RelTypeHasAccessTo))
		}
		edges = append(edges, edge(n.ID, target.ID, asset.RelTypeHasAccessTo))
	}
	svc := NewSurfaceService(&fakeGraphNodes{nodes: nodes}, &fakeGraphEdges{edges: edges}, logger.NewNop())
	svc.SetDataScope(ownerEnforcer())
	d, err := svc.PathDetailForCaller(context.Background(), shared.NewID(), target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.TotalPaths != 25 || len(d.Paths) != pathShowCap {
		t.Fatalf("total %d shown %d, want 25 and %d", d.TotalPaths, len(d.Paths), pathShowCap)
	}
	// Every edge lists only shown routes.
	for _, e := range d.Edges {
		if !sort.IntsAreSorted(e.Paths) || e.Paths[len(e.Paths)-1] >= len(d.Paths) {
			t.Fatalf("edge paths = %v", e.Paths)
		}
	}
}
