package definition_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/definition"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestKinds(t *testing.T) {
	want := map[definition.Kind]int{
		definition.KindVulnerability:    2002,
		definition.KindExposure:         2002,
		definition.KindWeakness:         2007,
		definition.KindMisconfiguration: 2003,
		definition.KindCompliance:       2003,
		definition.KindSecret:           2006,
		definition.KindMalicious:        2004,
	}
	if len(definition.AllKinds()) != len(want) {
		t.Fatalf("AllKinds() = %v", definition.AllKinds())
	}
	for _, k := range definition.AllKinds() {
		if !k.IsValid() || k.OCSFClass() != want[k] {
			t.Errorf("%s: valid=%v ocsf=%d want %d", k, k.IsValid(), k.OCSFClass(), want[k])
		}
	}
	for _, bad := range []string{"", "web3", "Vulnerability"} {
		if _, err := definition.ParseKind(bad); !errors.Is(err, definition.ErrInvalid) {
			t.Errorf("ParseKind(%q) = %v, want ErrInvalid", bad, err)
		}
	}
}

func TestNormalizeID(t *testing.T) {
	cases := []struct {
		ns, in, want string
		ok           bool
	}{
		{"CVE", " cve-2021-44228 ", "CVE-2021-44228", true},
		{"CVE", "CVE-21-1", "", false},
		{"CVE", "GHSA-jfh8-c2jp-5v3q", "", false},
		{"GHSA", "ghsa-JFH8-C2JP-5V3Q", "GHSA-jfh8-c2jp-5v3q", true},
		{"GHSA", "GHSA-aaaa-bbbb-cccc", "", false}, // a, b not in GitHub's alphabet
		{"OSV:PYSEC", "pysec-2021-123", "PYSEC-2021-123", true},
		{"TENABLE", "156860", "156860", true},
		{"TENABLE", "plugin-1", "", false},
		{"CHECKOV", "ckv_aws_20", "CKV_AWS_20", true},
		{"SWC", "swc-107", "SWC-107", true},
		{"SEMGREP", "python.lang.security.audit.eval", "python.lang.security.audit.eval", true},
		{"NUCLEI", "", "", false},
		{"NUCLEI", strings.Repeat("x", 513), "", false},
		{"CUSTOM:acme", "Rule 7", "Rule 7", true},
		{"UNKNOWN", "x", "", false},
		{"lowercase", "x", "", false},
	}
	for _, c := range cases {
		got, err := definition.NormalizeID(c.ns, c.in)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("NormalizeID(%s, %q) = %q, %v; want %q ok=%v", c.ns, c.in, got, err, c.want, c.ok)
		}
	}
}

func TestLookup(t *testing.T) {
	cve, ok := definition.Lookup("CVE")
	if !ok || !cve.GlobalCapable || !cve.Advisory || cve.DefaultKind != definition.KindVulnerability {
		t.Errorf("CVE entry %+v", cve)
	}
	if got := cve.ReferenceURL("CVE-2021-44228"); got != "https://www.cve.org/CVERecord?id=CVE-2021-44228" {
		t.Errorf("CVE url %q", got)
	}
	mal, ok := definition.Lookup("OSV:MAL")
	if !ok || mal.DefaultKind != definition.KindMalicious || !mal.Advisory {
		t.Errorf("OSV:MAL entry %+v", mal)
	}
	custom, ok := definition.Lookup("CUSTOM:acme-scanner")
	if !ok || custom.GlobalCapable || custom.Advisory {
		t.Errorf("CUSTOM entry %+v: must be tenant-only", custom)
	}
	nuclei, _ := definition.Lookup("NUCLEI")
	if nuclei.Advisory || nuclei.DefaultKind != definition.KindExposure {
		t.Errorf("NUCLEI entry %+v: a rule namespace, not an advisory", nuclei)
	}
	for _, bad := range []string{"", "OTHER:x", "CUSTOM:", "CVE:x:y", "cve"} {
		if _, ok := definition.Lookup(bad); ok {
			t.Errorf("Lookup(%q) accepted", bad)
		}
	}
}

func TestDetectAdvisory(t *testing.T) {
	cases := []struct{ in, ns, id string }{
		{"cve-2021-44228", "CVE", "CVE-2021-44228"},
		{"GHSA-JFH8-C2JP-5V3Q", "GHSA", "GHSA-jfh8-c2jp-5v3q"},
		{"RUSTSEC-2021-0001", "OSV:RUSTSEC", "RUSTSEC-2021-0001"},
		{"USN-1234-1", "USN", "USN-1234-1"},
	}
	for _, c := range cases {
		ns, id, ok := definition.DetectAdvisory(c.in)
		if !ok || ns != c.ns || id != c.id {
			t.Errorf("DetectAdvisory(%q) = %s %s %v; want %s %s", c.in, ns, id, ok, c.ns, c.id)
		}
	}
	for _, nickname := range []string{"Log4Shell", "Spring4Shell", "Heartbleed", "", "CVE-"} {
		if _, _, ok := definition.DetectAdvisory(nickname); ok {
			t.Errorf("DetectAdvisory(%q) took a nickname for an advisory", nickname)
		}
	}
}

func TestCustomNamespace(t *testing.T) {
	cases := map[string]string{
		"Acme Scanner": "CUSTOM:acme-scanner",
		"  my_tool.v2": "CUSTOM:my_tool.v2",
		"!!!":          "",
		"":             "",
	}
	for in, want := range cases {
		if got := definition.CustomNamespace(in); got != want {
			t.Errorf("CustomNamespace(%q) = %q, want %q", in, got, want)
		}
	}
	if got := definition.CustomNamespace(strings.Repeat("a", 100)); len(got) != len("CUSTOM:")+64 {
		t.Errorf("long tool name not cut to 64: %q", got)
	}
}

func TestScope(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	g := definition.Global()
	if !g.IsGlobal() || g.Key() != definition.GlobalScopeKey || !g.VisibleTo(a) || g.WritableBy(a) {
		t.Errorf("global scope: visible to all, writable by no tenant")
	}
	s := definition.TenantScope(a)
	if !s.VisibleTo(a) || s.VisibleTo(b) || s.VisibleTo(shared.ID{}) {
		t.Errorf("tenant scope visible only to its tenant")
	}
	if !s.WritableBy(a) || s.WritableBy(b) || s.WritableBy(shared.ID{}) {
		t.Errorf("tenant scope writable only by its tenant")
	}
	back, err := definition.ScopeFromKey(s.Key())
	if err != nil || back != s {
		t.Errorf("ScopeFromKey(Key()) = %v, %v", back, err)
	}
	if back, _ := definition.ScopeFromKey(definition.GlobalScopeKey); !back.IsGlobal() {
		t.Errorf("nil key is global")
	}
}

func TestNewTenantDefinition(t *testing.T) {
	tenant := shared.NewID()
	d, err := definition.NewTenantDefinition(tenant, "", "NUCLEI", " internal-panel ", "", definition.SourceReport)
	if err != nil {
		t.Fatal(err)
	}
	if d.Scope().TenantID() != tenant || d.Kind() != definition.KindExposure || d.ExternalID() != "internal-panel" ||
		d.Title() != "internal-panel" || d.Lifecycle() != definition.LifecyclePublished || d.CVEID() != "" {
		t.Errorf("tenant definition %+v", d)
	}
	if !d.VisibleTo(tenant) || d.VisibleTo(shared.NewID()) {
		t.Errorf("tenant definition visible to another tenant")
	}

	bad := []struct {
		name   string
		tenant shared.ID
		ns     string
		origin definition.Source
	}{
		{"no tenant", shared.ID{}, "NUCLEI", definition.SourceReport},
		{"CVE is global only", tenant, "CVE", definition.SourceReport},
		{"feed origin", tenant, "NUCLEI", definition.SourceOSV},
		{"unknown namespace", tenant, "NOPE", definition.SourceTenant},
	}
	for _, c := range bad {
		if _, err := definition.NewTenantDefinition(c.tenant, "", c.ns, "x-1", "t", c.origin); !errors.Is(err, definition.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", c.name, err)
		}
	}
	if _, err := definition.NewTenantDefinition(tenant, "web3", "NUCLEI", "x", "t", definition.SourceTenant); err == nil {
		t.Error("unknown kind accepted")
	}
	custom, err := definition.NewTenantDefinition(tenant, definition.KindMisconfiguration, "CUSTOM:acme", "R1", "t", definition.SourceTenant)
	if err != nil || custom.Namespace() != "CUSTOM:acme" {
		t.Errorf("custom tool definition: %v", err)
	}
	long := strings.Repeat("é", 600)
	if d, _ := definition.NewTenantDefinition(tenant, "", "NUCLEI", "x", long, definition.SourceReport); len([]rune(d.Title())) != 500 {
		t.Errorf("title not cut to 500 characters: %d", len([]rune(d.Title())))
	}
}

func TestNewGlobalStub(t *testing.T) {
	d, err := definition.NewGlobalStub("CVE", "cve-2024-0001")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Scope().IsGlobal() || d.Origin() != definition.SourceReport || d.CVEID() != "CVE-2024-0001" ||
		d.Title() != "CVE-2024-0001" || d.Description() != "" {
		t.Errorf("stub %+v: identity only, no reporter text", d)
	}
	// A report never creates global content for a rule, a template or a
	// custom tool: those become tenant definitions.
	for _, ns := range []string{"NUCLEI", "SEMGREP", "TENABLE", "CUSTOM:acme", "PENTEST"} {
		if _, err := definition.NewGlobalStub(ns, "1"); !errors.Is(err, definition.ErrInvalid) {
			t.Errorf("global stub in %s: %v, want ErrInvalid", ns, err)
		}
	}
	if err := d.SetText("attacker title", "x", "y"); !errors.Is(err, definition.ErrNotWritable) {
		t.Errorf("SetText on a global definition: %v", err)
	}
	if err := d.SetSeverity("critical"); !errors.Is(err, definition.ErrNotWritable) {
		t.Errorf("SetSeverity on a global definition: %v", err)
	}
}

func TestIdentifierTrust(t *testing.T) {
	tenant := shared.NewID()
	def := shared.NewID()
	g, ts := definition.Global(), definition.TenantScope(tenant)
	ghsa := "GHSA-jfh8-c2jp-5v3q"
	cases := []struct {
		name  string
		ident definition.Identifier
		scope definition.Scope
		ok    bool
	}{
		{"OSV alias on a global definition", definition.Identifier{Namespace: "GHSA", ExternalID: ghsa, Scope: g, DefinitionID: def, AssertedBy: definition.SourceOSV}, g, true},
		{"report alias on a global definition", definition.Identifier{Namespace: "GHSA", ExternalID: ghsa, Scope: g, DefinitionID: def, AssertedBy: definition.SourceReport}, g, false},
		{"report primary of a global stub", definition.Identifier{Namespace: "GHSA", ExternalID: ghsa, Scope: g, DefinitionID: def, IsPrimary: true, AssertedBy: definition.SourceReport}, g, true},
		{"tenant primary of a global definition", definition.Identifier{Namespace: "GHSA", ExternalID: ghsa, Scope: g, DefinitionID: def, IsPrimary: true, AssertedBy: definition.SourceTenant}, g, false},
		{"tenant alias on its definition", definition.Identifier{Namespace: "NUCLEI", ExternalID: "x", Scope: ts, DefinitionID: def, AssertedBy: definition.SourceTenant}, ts, true},
		{"feed alias in a tenant scope", definition.Identifier{Namespace: "NUCLEI", ExternalID: "x", Scope: ts, DefinitionID: def, AssertedBy: definition.SourceOSV}, ts, false},
		{"tenant identifier on a global definition", definition.Identifier{Namespace: "NUCLEI", ExternalID: "x", Scope: ts, DefinitionID: def, AssertedBy: definition.SourceReport}, g, false},
		{"malformed id", definition.Identifier{Namespace: "GHSA", ExternalID: "nope", Scope: g, DefinitionID: def, AssertedBy: definition.SourceOSV}, g, false},
	}
	for _, c := range cases {
		if err := c.ident.Validate(c.scope); (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestRelationTrust(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	x, y := shared.NewID(), shared.NewID()
	g, sa, sb := definition.Global(), definition.TenantScope(a), definition.TenantScope(b)
	cases := []struct {
		name string
		rel  definition.Relation
		ok   bool
	}{
		{"OSV upstream between globals", definition.Relation{Scope: g, FromID: x, FromScope: g, ToID: y, ToScope: g, Type: definition.RelationUpstream, AssertedBy: definition.SourceOSV}, true},
		{"report relation between globals", definition.Relation{Scope: g, FromID: x, FromScope: g, ToID: y, ToScope: g, Type: definition.RelationDetects, AssertedBy: definition.SourceReport}, false},
		{"global relation to a tenant definition", definition.Relation{Scope: g, FromID: x, FromScope: g, ToID: y, ToScope: sa, Type: definition.RelationRelated, AssertedBy: definition.SourceOSV}, false},
		{"A's template detects a global CVE", definition.Relation{Scope: sa, FromID: x, FromScope: sa, ToID: y, ToScope: g, Type: definition.RelationDetects, AssertedBy: definition.SourceReport}, true},
		{"A's relation to B's definition", definition.Relation{Scope: sa, FromID: x, FromScope: sa, ToID: y, ToScope: sb, Type: definition.RelationRelated, AssertedBy: definition.SourceTenant}, false},
		{"self relation", definition.Relation{Scope: sa, FromID: x, FromScope: sa, ToID: x, ToScope: sa, Type: definition.RelationRelated, AssertedBy: definition.SourceTenant}, false},
		{"alias is not a relation", definition.Relation{Scope: sa, FromID: x, FromScope: sa, ToID: y, ToScope: sa, Type: "alias", AssertedBy: definition.SourceTenant}, false},
	}
	for _, c := range cases {
		if err := c.rel.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestTaxonomyTrust(t *testing.T) {
	tenant, def := shared.NewID(), shared.NewID()
	g, ts := definition.Global(), definition.TenantScope(tenant)
	link := func(scope definition.Scope, src definition.Source) definition.TaxonomyLink {
		return definition.TaxonomyLink{DefinitionID: def, Scope: scope, Namespace: "CWE", ExternalID: "CWE-79", AssertedBy: src}
	}
	if err := link(g, definition.SourceKEV).Validate(g); err != nil {
		t.Errorf("KEV CWE on a global definition: %v", err)
	}
	if err := link(g, definition.SourceReport).Validate(g); err == nil {
		t.Error("a report mapped a global definition")
	}
	if err := link(ts, definition.SourceReport).Validate(ts); err != nil {
		t.Errorf("a tenant mapping its own definition: %v", err)
	}
	if err := link(ts, definition.SourceReport).Validate(g); err == nil {
		t.Error("a tenant link on a global definition")
	}
}

func TestValidateFindingLinks(t *testing.T) {
	tenant, other, finding := shared.NewID(), shared.NewID(), shared.NewID()
	mk := func(def shared.ID, scope definition.Scope, role definition.Role, ord int) definition.FindingLink {
		return definition.FindingLink{FindingID: finding, TenantID: tenant, DefinitionID: def, DefinitionScope: scope,
			Role: role, Ord: ord, AssertedBy: definition.LinkSourceReport}
	}
	cve, rule, cwe := shared.NewID(), shared.NewID(), shared.NewID()
	good := []definition.FindingLink{
		mk(cve, definition.Global(), definition.RolePrimary, 0),
		mk(rule, definition.TenantScope(tenant), definition.RoleDetectedBy, 1),
		mk(cwe, definition.Global(), definition.RoleWeakness, 2),
	}
	if err := definition.ValidateFindingLinks(tenant, finding, good); err != nil {
		t.Fatalf("valid set: %v", err)
	}
	if p, ok := definition.PrimaryOf(good); !ok || p != cve {
		t.Errorf("PrimaryOf = %v %v", p, ok)
	}
	if err := definition.ValidateFindingLinks(tenant, finding, nil); err != nil {
		t.Errorf("empty set: %v", err)
	}

	foreign := []definition.FindingLink{mk(cve, definition.TenantScope(other), definition.RolePrimary, 0)}
	if err := definition.ValidateFindingLinks(tenant, finding, foreign); !errors.Is(err, definition.ErrNotFound) {
		t.Errorf("another tenant's definition: %v, want ErrNotFound", err)
	}

	bad := map[string][]definition.FindingLink{
		"no primary":          {mk(cve, definition.Global(), definition.RoleAdditional, 1)},
		"two primaries":       {mk(cve, definition.Global(), definition.RolePrimary, 0), mk(rule, definition.Global(), definition.RolePrimary, 1)},
		"primary not at 0":    {mk(cve, definition.Global(), definition.RolePrimary, 3)},
		"duplicate ord":       {mk(cve, definition.Global(), definition.RolePrimary, 0), mk(rule, definition.Global(), definition.RoleAdditional, 0)},
		"duplicate def":       {mk(cve, definition.Global(), definition.RolePrimary, 0), mk(cve, definition.Global(), definition.RoleAdditional, 1)},
		"negative ord":        {mk(cve, definition.Global(), definition.RolePrimary, 0), mk(rule, definition.Global(), definition.RoleAdditional, -1)},
		"unknown role":        {mk(cve, definition.Global(), definition.RolePrimary, 0), mk(rule, definition.Global(), "owner", 1)},
		"no definition":       {mk(shared.ID{}, definition.Global(), definition.RolePrimary, 0)},
		"another finding":     {{FindingID: shared.NewID(), TenantID: tenant, DefinitionID: cve, Role: definition.RolePrimary, AssertedBy: definition.LinkSourceReport}},
		"another tenant link": {{FindingID: finding, TenantID: other, DefinitionID: cve, Role: definition.RolePrimary, AssertedBy: definition.LinkSourceReport}},
	}
	for name, links := range bad {
		if err := definition.ValidateFindingLinks(tenant, finding, links); !errors.Is(err, definition.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}
