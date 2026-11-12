package software

import (
	"strings"
	"testing"
)

func node(t *testing.T, purl, ref, rel string, deps ...string) PackageNode {
	t.Helper()
	p, err := ParsePURL(purl)
	if err != nil {
		t.Fatal(err)
	}
	return PackageNode{Ref: ref, PURL: p, Relationship: rel, DependsOn: deps}
}

func TestPlanGraph_DepthAndRelationship(t *testing.T) {
	nodes := []PackageNode{
		node(t, "pkg:npm/app@1", "app", RelationshipUnknown, "lib", "pkg:npm/util@3", "missing"),
		node(t, "pkg:npm/lib@2", "lib", RelationshipUnknown, "util"),
		node(t, "pkg:npm/util@3", "util", RelationshipUnknown, "lib", "util"), // cycle and self reference
		node(t, "pkg:npm/orphan@4", "orphan", RelationshipUnknown),
	}
	edges, depth := PlanGraph(nodes)
	if len(edges) != 4 {
		t.Fatalf("edges = %+v, want app->lib, app->util, lib->util, util->lib", edges)
	}
	if depth[0] != 0 || depth[1] != 1 || depth[2] != 1 || depth[3] != 0 {
		t.Fatalf("depth = %v", depth)
	}
	if nodes[0].Relationship != RelationshipDirect || nodes[1].Relationship != RelationshipTransitive || nodes[3].Relationship != RelationshipDirect {
		t.Fatalf("relationships = %s %s %s %s", nodes[0].Relationship, nodes[1].Relationship, nodes[2].Relationship, nodes[3].Relationship)
	}
}

func TestPlanGraph_DirectMarksRoots(t *testing.T) {
	nodes := []PackageNode{
		node(t, "pkg:npm/a@1", "a", RelationshipDirect, "b"),
		node(t, "pkg:npm/b@1", "b", RelationshipUnknown),
		node(t, "pkg:npm/c@1", "c", RelationshipUnknown), // unreachable
	}
	_, depth := PlanGraph(nodes)
	if depth[0] != 0 || depth[1] != 1 || depth[2] != -1 {
		t.Fatalf("depth = %v", depth)
	}
	if nodes[2].Relationship != RelationshipUnknown {
		t.Errorf("an unreachable entry stays unknown, got %s", nodes[2].Relationship)
	}
}

func TestPlanGraph_NoEdgesKeepsUnknown(t *testing.T) {
	nodes := []PackageNode{node(t, "pkg:npm/a@1", "a", ""), node(t, "pkg:npm/b@1", "b", "")}
	if edges, _ := PlanGraph(nodes); len(edges) != 0 {
		t.Fatal("no edges expected")
	}
	if nodes[0].Relationship != RelationshipUnknown {
		t.Errorf("without a graph a flat list says nothing about directness: %s", nodes[0].Relationship)
	}
}

func TestNormalizers(t *testing.T) {
	if NormalizeRelationship("Indirect") != RelationshipTransitive || NormalizeRelationship("direct") != RelationshipDirect ||
		NormalizeRelationship("root") != RelationshipUnknown {
		t.Error("relationship")
	}
	for in, want := range map[string]string{"required": ScopeRuntime, "excluded": ScopeDevelopment, "peer": ScopeOptional, "test": ScopeTest, "x": ""} {
		if got := NormalizeScope(in); got != want {
			t.Errorf("NormalizeScope(%q) = %q", in, got)
		}
	}
	got := NormalizeLicenses([]string{"MIT, Apache-2.0", "MIT", "NOASSERTION", "<script>", "GPL-2.0-only WITH Classpath-exception-2.0", strings.Repeat("A", 200)})
	want := map[string]bool{"MIT": true, "Apache-2.0": true, "GPL-2.0-only WITH Classpath-exception-2.0": true, strings.Repeat("A", MaxLicenseLen): true}
	if len(got) != len(want) {
		t.Fatalf("licenses = %v", got)
	}
	for _, l := range got {
		if !want[l] {
			t.Errorf("unexpected license %q", l)
		}
	}
	many := make([]string, 40)
	for i := range many {
		many[i] = "L" + strings.Repeat("x", i)
	}
	if len(NormalizeLicenses(many)) != MaxLinkLicenses {
		t.Error("licenses must be capped")
	}
}
