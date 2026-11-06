package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
)

// The preview tells the dialog how many names an address exclusion also
// stops, or that the address is a shared front end whose names stay in scans.
func TestPreviewItem_ResolvingNamesAndEdge(t *testing.T) {
	dedicated := previewItem(scope.ExclusionPreview{
		Item:  scope.BulkExclusionItem{ExclusionType: "ip_address", Pattern: "203.0.113.7"},
		Match: scope.ExclusionMatch{Matched: 1, Sample: []string{"203.0.113.7"}, Names: 2, NameSample: []string{"a.example.com", "b.example.com"}},
	})
	if dedicated.ResolvingNames != 2 || len(dedicated.ResolvingSample) != 2 || dedicated.Edge != nil || dedicated.NamesUnaffected {
		t.Fatalf("dedicated: %+v", dedicated)
	}
	r := edgeaddr.Result{Class: edgeaddr.Edge, Provider: "Cloudflare", Basis: edgeaddr.BasisRange}
	edge := previewItem(scope.ExclusionPreview{
		Item: scope.BulkExclusionItem{ExclusionType: "ip_address", Pattern: " 104.16.1.1 "},
		Edge: &r,
	})
	if !edge.NamesUnaffected || edge.Edge == nil || edge.Edge.Provider != "Cloudflare" || edge.Edge.Address != "104.16.1.1" || edge.ResolvingNames != 0 {
		t.Fatalf("edge: %+v", edge)
	}
	b, _ := json.Marshal(edge)
	for _, k := range []string{`"resolving_names":0`, `"resolving_sample":[]`, `"names_unaffected":true`, `"edge":{"class":"edge","provider":"Cloudflare","address":"104.16.1.1"}`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("json %s lacks %s", b, k)
		}
	}
}
