package asset

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// The registry is generated from api/configs/asset-types.yaml; these tests
// hold the generated data to the RFC-042 §6.3 contract independently of the
// generator's own validation.

func TestRegistry_CoversEveryAssetTypeExactlyOnce(t *testing.T) {
	seen := map[AssetType]int{}
	for _, d := range RegistryDocument().Types {
		seen[d.Type]++
	}
	for typ, n := range seen {
		if n != 1 {
			t.Errorf("type %q is declared %d times", typ, n)
		}
	}
	inputs := map[AssetType]bool{}
	for _, n := range registryTypeInputs {
		inputs[n] = true
	}
	for _, typ := range AllAssetTypes() {
		if inputs[typ] {
			continue // a legacy type input, no type of its own
		}
		if seen[typ] == 0 {
			t.Errorf("AllAssetTypes has %q but the registry does not", typ)
		}
		delete(seen, typ)
	}
	for typ := range seen {
		t.Errorf("registry has %q but AllAssetTypes does not", typ)
	}
}

// 37 classified types in 16 classes grouped into 8 lenses, plus
// `unclassified` in class `other`, which has no lens (All assets only).
func TestRegistry_ClassAndLensShape(t *testing.T) {
	reg := RegistryDocument()
	if len(reg.Lenses) != 8 {
		t.Errorf("lenses = %d, want 8", len(reg.Lenses))
	}
	if n := len(reg.Classes) - 1; n != 16 {
		t.Errorf("classes other than %q = %d, want 16", ClassOther, n)
	}
	lenses := map[Lens]bool{}
	for _, l := range reg.Lenses {
		lenses[l.ID] = true
		if len(l.Classes) == 0 {
			t.Errorf("lens %q has no classes", l.ID)
		}
		for _, c := range l.Classes {
			if LensForClass(c) != l.ID {
				t.Errorf("lens %q lists class %q, whose lens is %q", l.ID, c, LensForClass(c))
			}
		}
	}

	classified := 0
	for _, d := range reg.Types {
		if d.Type == AssetTypeUnclassified {
			if d.Class != ClassOther || d.Lens != "" {
				t.Errorf("unclassified: class %q lens %q, want %q and no lens", d.Class, d.Lens, ClassOther)
			}
			continue
		}
		classified++
		if d.Class == ClassOther || d.Class == "" {
			t.Errorf("%s: has no class", d.Type)
		}
		if !lenses[d.Lens] {
			t.Errorf("%s: lens %q is not one of the 8 lenses", d.Type, d.Lens)
		}
		if LensForClass(d.Class) != d.Lens {
			t.Errorf("%s: lens %q disagrees with its class %q (lens %q)", d.Type, d.Lens, d.Class, LensForClass(d.Class))
		}
	}
	if classified != 36 {
		t.Errorf("classified types = %d, want 36", classified)
	}
	for _, c := range reg.Classes {
		if len(c.Types) == 0 {
			t.Errorf("class %q has no types", c.ID)
		}
		for _, typ := range c.Types {
			if d, _ := LookupType(typ); d.Class != c.ID {
				t.Errorf("class %q lists %q, whose class is %q", c.ID, typ, d.Class)
			}
		}
	}
	if reg.Version == "" || reg.Version != RegistryVersion {
		t.Errorf("version %q, want RegistryVersion %q", reg.Version, RegistryVersion)
	}
}

func TestRegistry_EveryTypeHasValidIdentityKeys(t *testing.T) {
	for _, d := range RegistryDocument().Types {
		if len(d.IdentityKeys) == 0 {
			t.Errorf("%s: no identity keys", d.Type)
			continue
		}
		if last := d.IdentityKeys[len(d.IdentityKeys)-1]; last != "name" {
			t.Errorf("%s: identity keys end with %q, want the exact-name fallback", d.Type, last)
		}
		attrs := map[string]bool{}
		for _, a := range d.Attributes {
			attrs[a.Name] = true
		}
		for _, k := range d.IdentityKeys {
			attr, isAttr := strings.CutPrefix(k, "attr.")
			switch {
			case k == "name", IdentifierKind(k).IsValid():
			case isAttr && attrs[attr]:
			default:
				t.Errorf("%s: identity key %q is not an RFC-028 kind, name or a declared attribute", d.Type, k)
			}
		}
	}
}

func TestRegistry_AttributesColumnsSectionsAndCards(t *testing.T) {
	reg := RegistryDocument()
	sections := map[string]bool{}
	for _, s := range reg.Sections {
		sections[s.ID] = true
	}
	cards := map[string]bool{}
	for _, c := range reg.Cards {
		cards[c] = true
	}
	core := map[string]bool{}
	for _, f := range reg.CoreFields {
		core[f] = true
	}
	scalar := map[AttributeKind]bool{AttributeString: true, AttributeInt: true, AttributeEnum: true, AttributeBool: true}
	for _, d := range reg.Types {
		attrs := map[string]bool{}
		var facets, groups []string
		for _, a := range d.Attributes {
			attrs[a.Name] = true
			if (a.Facet || a.Group) && !scalar[a.Kind] {
				t.Errorf("%s.%s: a %s attribute cannot be a facet or group-by field", d.Type, a.Name, a.Kind)
			}
			if (a.Kind == AttributeEnum) != (len(a.Values) > 0) {
				t.Errorf("%s.%s: enum values and kind disagree", d.Type, a.Name)
			}
			if a.Facet {
				facets = append(facets, string(d.Type)+"."+a.Name)
			}
			if a.Group {
				groups = append(groups, string(d.Type)+"."+a.Name)
			}
		}
		if !slices.Equal(facets, d.Facets) && (len(facets) > 0 || len(d.Facets) > 0) {
			t.Errorf("%s: facets %v, attributes say %v", d.Type, d.Facets, facets)
		}
		if !slices.Equal(groups, d.GroupBy) && (len(groups) > 0 || len(d.GroupBy) > 0) {
			t.Errorf("%s: group_by %v, attributes say %v", d.Type, d.GroupBy, groups)
		}
		for _, c := range d.Columns {
			if !core[c] && !attrs[c] {
				t.Errorf("%s: column %q is neither a core field nor an attribute", d.Type, c)
			}
		}
		if len(d.Sections) == 0 || d.Sections[0] != "overview" {
			t.Errorf("%s: sections must start with overview, got %v", d.Type, d.Sections)
		}
		for _, s := range d.Sections {
			if !sections[s] {
				t.Errorf("%s: unknown section %q", d.Type, s)
			}
		}
		if !cards[d.Card] {
			t.Errorf("%s: unknown card %q", d.Type, d.Card)
		}
	}
}

// Relationship constraints may only name real types: the virtual frontend
// names of relationship-types.yaml are resolved to (type, sub_type) pairs.
func TestRegistry_RelationshipPeersAreRealTypes(t *testing.T) {
	valid := map[RelationshipType]bool{}
	for _, r := range AllRelationshipTypes() {
		valid[r] = true
	}
	for _, d := range RegistryDocument().Types {
		for dir, rules := range map[string][]RelationshipRule{"out": d.Relationships.Out, "in": d.Relationships.In} {
			for _, r := range rules {
				if !valid[r.Relationship] {
					t.Errorf("%s %s: unknown relationship %q", d.Type, dir, r.Relationship)
				}
				for _, p := range r.Peers {
					if _, ok := LookupType(p.Type); !ok {
						t.Errorf("%s %s %s: peer %q is not a registry type", d.Type, dir, r.Relationship, p.Type)
					}
				}
			}
		}
	}
	// repository -deployed_to-> kubernetes/workload was the virtual k8s_workload.
	repo, _ := LookupType(AssetTypeRepository)
	var found bool
	for _, r := range repo.Relationships.Out {
		if r.Relationship == RelTypeDeployedTo && slices.Contains(r.Peers, TypeRef{Type: AssetTypeKubernetes, SubType: "workload"}) {
			found = true
		}
	}
	if !found {
		t.Errorf("repository deployed_to does not reach kubernetes/workload: %+v", repo.Relationships.Out)
	}
}

func TestClassOf_AliasesKeepTheirOwnClass(t *testing.T) {
	tests := []struct {
		typ     AssetType
		subType string
		class   Class
		lens    Lens
	}{
		{AssetTypeHost, "", ClassHost, LensCloudInfra},
		{AssetTypeHost, "compute", ClassHost, LensCloudInfra},
		{AssetTypeHost, "serverless", ClassFunction, LensCloudInfra},
		{AssetTypeStorage, "container_registry", ClassArtifactRegistry, LensContainersK8s},
		{AssetTypeStorage, "s3_bucket", ClassDataStore, LensData},
		{AssetTypeService, "discovered_url", ClassWebEndpoint, LensExternalSurface},
		{AssetTypeService, "http", ClassService, LensExternalSurface},
		{AssetTypeService, "no_such_sub_type", ClassService, LensExternalSurface},
		{AssetTypeServerless, "", ClassFunction, LensCloudInfra},
		{AssetTypeRepository, "github", ClassCodeRepo, LensCode},
		{AssetTypeKubernetes, "cluster", ClassCluster, LensContainersK8s},
		{AssetTypeEndpoint, "", ClassHost, LensCloudInfra},
		{AssetTypeUnclassified, "", ClassOther, ""},
		{"ip_range", "", ClassOther, ""},
	}
	for _, tt := range tests {
		if got := ClassOf(tt.typ, tt.subType); got != tt.class {
			t.Errorf("ClassOf(%q, %q) = %q, want %q", tt.typ, tt.subType, got, tt.class)
		}
		if got := LensOf(tt.typ, tt.subType); got != tt.lens {
			t.Errorf("LensOf(%q, %q) = %q, want %q", tt.typ, tt.subType, got, tt.lens)
		}
	}
}

// TypeAliases moved from a hand-written map in value_objects.go into the
// generated file. Ingest depends on every entry, so it must not change
// unintentionally. RFC-042 §6.3.8 changed two on purpose: a sub-type is a
// kind, so s3_bucket is stored as (storage, bucket) + provider aws, and
// data_store as a database with no sub-type.
func TestTypeAliases_UnchangedByTheRegistry(t *testing.T) {
	type alias = struct {
		CoreType AssetType
		SubType  string
	}
	want := map[AssetType]alias{
		"firewall":             {AssetTypeNetwork, "firewall"},
		"load_balancer":        {AssetTypeNetwork, "load_balancer"},
		"vpc":                  {AssetTypeNetwork, "vpc"},
		"subnet":               {AssetTypeNetwork, "subnet"},
		"compute":              {AssetTypeHost, "compute"},
		"serverless":           {AssetTypeHost, "serverless"},
		"website":              {AssetTypeApplication, "website"},
		"web_application":      {AssetTypeApplication, "website"}, // O3
		"api":                  {AssetTypeApplication, "api"},
		"mobile_app":           {AssetTypeApplication, "mobile_app"},
		"iam_user":             {AssetTypeIdentity, "iam_user"},
		"iam_role":             {AssetTypeIdentity, "iam_role"},
		"service_account":      {AssetTypeIdentity, "service_account"},
		"data_store":           {AssetTypeDatabase, ""},
		"s3_bucket":            {AssetTypeStorage, "bucket"},
		"container_registry":   {AssetTypeStorage, "container_registry"},
		"kubernetes_cluster":   {AssetTypeKubernetes, "cluster"},
		"kubernetes_namespace": {AssetTypeKubernetes, "namespace"},
		"http_service":         {AssetTypeService, "http"},
		"open_port":            {AssetTypeService, "open_port"},
		"discovered_url":       {AssetTypeService, "discovered_url"},
		"endpoint":             {AssetTypeHost, "workstation"}, // T4a
	}
	got := map[AssetType]alias{}
	for k, v := range TypeAliases {
		got[k] = v
	}
	if !maps.Equal(got, want) {
		t.Errorf("TypeAliases changed:\n got  %v\n want %v", got, want)
	}
}

// The legacy category of every type, as the deleted category.go had it. The
// `category` field of asset responses must not change.
func TestCategoryForType_UnchangedByTheRegistry(t *testing.T) {
	want := map[AssetType]Category{
		AssetTypeDomain:              CategoryExternalSurface,
		AssetTypeSubdomain:           CategoryExternalSurface,
		AssetTypeCertificate:         CategoryExternalSurface,
		AssetTypeIPAddress:           CategoryExternalSurface,
		AssetTypeWebsite:             CategoryApplication,
		AssetTypeWebApplication:      CategoryApplication,
		AssetTypeAPI:                 CategoryApplication,
		AssetTypeMobileApp:           CategoryApplication,
		AssetTypeApplication:         CategoryApplication,
		AssetTypeHost:                CategoryInfrastructure,
		AssetTypeCompute:             CategoryInfrastructure,
		AssetTypeServerless:          CategoryInfrastructure,
		AssetTypeContainer:           CategoryInfrastructure,
		AssetTypeKubernetesCluster:   CategoryInfrastructure,
		AssetTypeKubernetesNamespace: CategoryInfrastructure,
		AssetTypeKubernetes:          CategoryInfrastructure,
		AssetTypeEndpoint:            CategoryInfrastructure,
		AssetTypeNetwork:             CategoryNetwork,
		AssetTypeVPC:                 CategoryNetwork,
		AssetTypeSubnet:              CategoryNetwork,
		AssetTypeFirewall:            CategoryNetwork,
		AssetTypeLoadBalancer:        CategoryNetwork,
		AssetTypeService:             CategoryNetwork,
		AssetTypeHTTPService:         CategoryNetwork,
		AssetTypeOpenPort:            CategoryNetwork,
		AssetTypeDiscoveredURL:       CategoryNetwork,
		AssetTypeCloudAccount:        CategoryCloud,
		AssetTypeStorage:             CategoryCloud,
		AssetTypeContainerRegistry:   CategoryCloud,
		AssetTypeDatabase:            CategoryData,
		AssetTypeDataStore:           CategoryData,
		AssetTypeS3Bucket:            CategoryData,
		AssetTypeRepository:          CategoryCode,
		AssetTypeIAMUser:             CategoryIdentity,
		AssetTypeIAMRole:             CategoryIdentity,
		AssetTypeServiceAccount:      CategoryIdentity,
		AssetTypeIdentity:            CategoryIdentity,
		AssetTypeUnclassified:        CategoryOther,
	}
	for _, typ := range AllAssetTypes() {
		if got := CategoryForType(typ); got != want[typ] {
			t.Errorf("CategoryForType(%q) = %q, want %q", typ, got, want[typ])
		}
	}
	if got := CategoryForType("no_such_type"); got != CategoryOther {
		t.Errorf("unknown type: %q, want other", got)
	}
	if got := CategoryExternalSurface.Label(); got != "External Surface" {
		t.Errorf("label %q", got)
	}
	if len(AllCategories()) != 9 || !slices.Contains(TypesInCategory(CategoryCode), AssetTypeRepository) {
		t.Errorf("AllCategories %v / TypesInCategory(code) %v", AllCategories(), TypesInCategory(CategoryCode))
	}
}
