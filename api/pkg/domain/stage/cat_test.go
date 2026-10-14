package stage_test

import (
	"slices"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	. "github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/domain/stage/stagetest"
)

// toyweb is a tool only a reported contract describes: it implements
// dast.web@1 and maps the capability's max_duration_minutes to its own
// max_minutes setting.
var toyweb = ToolFacts{Name: "toyweb", Implements: []Key{DASTWeb},
	Params: map[Key]map[string]string{DASTWeb: {"max_duration_minutes": "max_minutes", "not_a_param": "x"}}}

// cat is the catalog of an organization whose sensors report the built-in
// tools' contracts and toyweb's.
var cat = stagetest.Catalog(toyweb)

// Stored pairs the tests name.
var (
	tDomain      = asset.TypeRef{Type: asset.AssetTypeDomain}
	tSubdomain   = asset.TypeRef{Type: asset.AssetTypeSubdomain}
	tIP          = asset.TypeRef{Type: asset.AssetTypeIPAddress}
	tNetwork     = asset.TypeRef{Type: asset.AssetTypeNetwork}
	tCertificate = asset.TypeRef{Type: asset.AssetTypeCertificate}
	tHTTPService = asset.TypeRef{Type: asset.AssetTypeService, SubType: "http"}
)

// plannedStages are the taxonomy's capabilities that are not catalog
// stages.
func plannedStages() []Stage {
	var out []Stage
	all := cat.All()
	for _, s := range cat.Taxonomy() {
		if !slices.ContainsFunc(all, func(r Stage) bool { return r.Key == s.Key }) {
			out = append(out, s)
		}
	}
	return out
}
