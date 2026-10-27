package issuelink

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNormalizeCWE(t *testing.T) {
	for in, want := range map[string]string{
		"CWE-89": "CWE-89", "cwe-089": "CWE-89", "89": "CWE-89", "CWE:89": "CWE-89", " CWE-79 ": "CWE-79",
		"": "", "CWE-": "", "CWE-0": "", "OWASP-A1": "", "CWE-89x": "",
	} {
		if got := NormalizeCWE(in); got != want {
			t.Errorf("NormalizeCWE(%q) = %q, want %q", in, got, want)
		}
	}
	if got := NormalizeCWEs([]string{"89", "CWE-89", "cwe-79", "junk"}); strings.Join(got, ",") != "CWE-79,CWE-89" {
		t.Errorf("NormalizeCWEs = %v", got)
	}
}

func sast(id, rule string, start, end int, cwes ...string) Finding {
	return Finding{ID: id, AssetID: "asset-1", Kind: "sast", Rule: rule, Path: "app/views.py", CWEs: cwes, StartLine: start, EndLine: end}
}

func TestKeys_SASTPerCWEAndNeverForAMaskOnlySecret(t *testing.T) {
	k := Keys(sast("a", "r1", 42, 42, "CWE-89", "89", "CWE-20"))
	if len(k) != 2 {
		t.Fatalf("want one key per distinct CWE, got %d", len(k))
	}
	if Keys(sast("a", "r1", 0, 0, "CWE-89")) != nil {
		t.Error("a SAST finding without a line has no key")
	}
	if Keys(sast("a", "r1", 1, 1)) != nil {
		t.Error("a SAST finding without a CWE has no key")
	}
	other := sast("b", "r2", 42, 42, "CWE-89")
	other.AssetID = "asset-2"
	if Keys(other)[0].Key == Keys(sast("b", "r2", 42, 42, "CWE-89"))[0].Key {
		t.Error("the asset must be part of the SAST key")
	}
	if Keys(Finding{ID: "s", Kind: "secret"}) != nil {
		t.Error("a secret without a keyed hash of its value has no key")
	}
	s := Keys(Finding{ID: "s", Kind: "secret", SecretHMAC: "abc"})
	if len(s) != 1 || strings.Contains(s[0].Key, "abc") {
		t.Fatalf("secret key: %+v", s)
	}
}

// holders builds the planner input from findings, as the repository does.
func plan(batch []Finding, stored []Finding, existing []Link) Plan {
	in := Input{Batch: batch, Holders: map[string][]Holder{}, KeyKinds: map[string]string{}, Existing: existing, Created: map[string]time.Time{}}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	all := append(append([]Finding{}, stored...), batch...)
	seen := map[string]bool{}
	for i, f := range all {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		c := f.CreatedAt
		if c.IsZero() {
			c = base.Add(time.Duration(i) * time.Minute)
		}
		in.Created[f.ID] = c
		for _, k := range Keys(f) {
			in.Holders[k.Key] = append(in.Holders[k.Key], Holder{FindingID: f.ID, Rule: f.Rule, StartLine: k.StartLine, EndLine: k.EndLine, CreatedAt: c, Kind: f.Kind, Locator: k.Locator})
			in.KeyKinds[k.Key] = k.Kind
		}
	}
	return PlanLinks(in)
}

func TestPlan_SASTOverlapSameCWEDifferentRulesLinks(t *testing.T) {
	a := sast("a", "python.django.security.injection.sql", 42, 42, "CWE-89")
	b := sast("b", "py/sql-injection", 40, 45, "CWE-89")
	p := plan([]Finding{b}, []Finding{a}, nil)
	if len(p.Make) != 1 || p.Make[0].PrimaryID != "a" || p.Make[0].MemberID != "b" || p.Make[0].Rule != RuleSASTOverlap {
		t.Fatalf("want a<-b sast_overlap, got %+v", p.Make)
	}
}

func TestPlan_SASTFalseLinksAreRefused(t *testing.T) {
	cases := map[string][2]Finding{
		"disjoint lines (two SQLi in one file)": {sast("a", "r1", 10, 12, "CWE-89"), sast("b", "r2", 40, 41, "CWE-89")},
		"different CWE on one line":             {sast("a", "r1", 42, 42, "CWE-89"), sast("b", "r2", 42, 42, "CWE-79")},
		"same rule (occurrences, not tools)":    {sast("a", "r1", 42, 42, "CWE-89"), sast("b", "r1", 42, 43, "CWE-89")},
	}
	for name, c := range cases {
		if p := plan([]Finding{c[1]}, []Finding{c[0]}, nil); len(p.Make) != 0 {
			t.Errorf("%s: linked %+v", name, p.Make)
		}
	}
	// Monorepo: same relative path on two assets.
	a, b := sast("a", "r1", 42, 42, "CWE-89"), sast("b", "r2", 42, 42, "CWE-89")
	b.AssetID = "asset-2"
	if p := plan([]Finding{b}, []Finding{a}, nil); len(p.Make) != 0 {
		t.Errorf("linked across assets: %+v", p.Make)
	}
}

func TestPlan_SecretSameValueAcrossFilesAndAssets(t *testing.T) {
	a := Finding{ID: "a", AssetID: "repo-1", Kind: "secret", SecretHMAC: "h1", Path: "config.go"}
	b := Finding{ID: "b", AssetID: "repo-1", Kind: "secret", SecretHMAC: "h1", Path: "deploy/env"}
	c := Finding{ID: "c", AssetID: "repo-2", Kind: "secret", SecretHMAC: "h1", Path: "x.yaml"}
	d := Finding{ID: "d", AssetID: "repo-1", Kind: "secret", SecretHMAC: "h2", Path: "config.go"}
	p := plan([]Finding{b, c, d}, []Finding{a}, nil)
	if len(p.Make) != 2 {
		t.Fatalf("want b and c in a's group, got %+v", p.Make)
	}
	for _, l := range p.Make {
		if l.PrimaryID != "a" || l.MemberID == "d" || l.Rule != RuleSecretValue {
			t.Errorf("unexpected link %+v", l)
		}
	}
}

func TestPlan_UnlinkedPairIsNeverRelinked(t *testing.T) {
	a := sast("a", "r1", 42, 42, "CWE-89")
	b := sast("b", "r2", 42, 42, "CWE-89")
	p := plan([]Finding{b}, []Finding{a}, []Link{{PrimaryID: "a", MemberID: "b", Rule: RuleSASTOverlap, State: StateUnlinked}})
	if len(p.Make) != 0 {
		t.Fatalf("relinked an unlinked pair: %+v", p.Make)
	}
}

func TestPlan_JoinsExistingGroupKeepsPrimaryAndDoesNotFuseGroups(t *testing.T) {
	a := Finding{ID: "a", AssetID: "r", Kind: "secret", SecretHMAC: "h1"}
	b := Finding{ID: "b", AssetID: "r", Kind: "secret", SecretHMAC: "h1"}
	n := Finding{ID: "n", AssetID: "r", Kind: "secret", SecretHMAC: "h1"}
	existing := []Link{{PrimaryID: "a", MemberID: "b", Rule: RuleSecretValue, State: StateActive}}
	p := plan([]Finding{n}, []Finding{a, b}, existing)
	if len(p.Make) != 1 || p.Make[0].PrimaryID != "a" || p.Make[0].MemberID != "n" {
		t.Fatalf("want n to join a's group, got %+v", p.Make)
	}
	if len(p.Release) != 0 {
		t.Fatalf("released a holding link: %+v", p.Release)
	}
}

// A wide range overlapping two separate issues must not chain them into one
// group: a SAST finding joins a group only by overlapping its primary.
func TestPlan_SASTWideRangeNeverChainsSeparateIssues(t *testing.T) {
	a := sast("a", "r1", 10, 12, "CWE-89")
	b := sast("b", "r2", 40, 41, "CWE-89")
	wide := sast("w", "r3", 1, 1000, "CWE-89")
	existing := []Link{{PrimaryID: "a", MemberID: "w", Rule: RuleSASTOverlap, State: StateActive}}
	p := plan([]Finding{b}, []Finding{a, wide}, existing)
	if len(p.Make) != 0 {
		t.Fatalf("b joined a's group through member w: %+v", p.Make)
	}
	// Derived again, a member that overlaps the primary keeps its link.
	p = plan([]Finding{wide}, []Finding{a, b}, existing)
	if len(p.Release) != 0 {
		t.Fatalf("released w's link to the primary it overlaps: %+v", p.Release)
	}
	// One batch: the wide finding pairs with the primary only.
	p = plan([]Finding{a, wide, b}, nil, nil)
	for _, l := range p.Make {
		if (l.PrimaryID == "a" && l.MemberID == "b") || (l.PrimaryID == "b" && l.MemberID == "a") {
			t.Fatalf("a and b (disjoint lines) ended up in one group: %+v", p.Make)
		}
		if l.MemberID == "b" && l.PrimaryID != "w" {
			t.Fatalf("b joined a group whose primary it does not overlap: %+v", p.Make)
		}
	}
}

func TestPlan_ReleasesALinkWhoseSignalIsGone(t *testing.T) {
	a := sast("a", "r1", 42, 42, "CWE-89")
	moved := sast("b", "r2", 90, 91, "CWE-89") // no longer overlaps
	existing := []Link{{PrimaryID: "a", MemberID: "b", Rule: RuleSASTOverlap, State: StateActive}}
	p := plan([]Finding{moved}, []Finding{a}, existing)
	if len(p.Release) != 1 || p.Release[0].MemberID != "b" {
		t.Fatalf("want the stale link released, got %+v", p.Release)
	}
	// A vuln_alias link is decided at re-key, never released here.
	p = plan([]Finding{moved}, []Finding{a}, []Link{{PrimaryID: "a", MemberID: "b", Rule: RuleVulnAlias, State: StateActive}})
	if len(p.Release) != 0 {
		t.Fatalf("released a vuln_alias link: %+v", p.Release)
	}
}

func TestPlan_CapsCrowdedKeysAndGroupSize(t *testing.T) {
	var stored []Finding
	for i := 0; i < MaxHolders+1; i++ {
		stored = append(stored, Finding{ID: fmt.Sprintf("s%04d", i), AssetID: "r", Kind: "secret", SecretHMAC: "fixture"})
	}
	p := plan([]Finding{{ID: "zz", AssetID: "r", Kind: "secret", SecretHMAC: "fixture"}}, stored, nil)
	if len(p.Make) != 0 || p.Crowded != 1 {
		t.Fatalf("crowded key linked: make=%d crowded=%d", len(p.Make), p.Crowded)
	}
	stored = stored[:MaxMembers+5]
	p = plan([]Finding{{ID: "zz", AssetID: "r", Kind: "secret", SecretHMAC: "fixture"}}, stored, nil)
	members := map[string]int{}
	for _, l := range p.Make {
		members[l.PrimaryID]++
	}
	for primary, n := range members {
		if n > MaxMembers {
			t.Fatalf("group %s has %d members", primary, n)
		}
	}
}

func TestBasisNamesNoValues(t *testing.T) {
	for _, r := range []string{RuleSASTOverlap, RuleSecretValue, RuleVulnAlias} {
		if len(Basis(r)) == 0 {
			t.Errorf("%s has no basis", r)
		}
	}
}

func vuln(id, kind, cve, locator string) Finding {
	return Finding{ID: id, AssetID: "asset-1", Kind: kind, CVE: cve, Locator: locator}
}

func TestVulnSignal(t *testing.T) {
	cases := []struct {
		name                                 string
		kind, vuln, rule, port, url, wantCVE string
		wantLoc                              string
	}{
		{"network port", "network", "cve-2023-44487", "", "443/tcp", "", "CVE-2023-44487", "443/tcp"},
		{"network host", "network", "CVE-2023-44487", "", "host", "", "CVE-2023-44487", "host"},
		{"sca is host level", "sca", "CVE-2023-44487", "", "", "", "CVE-2023-44487", "host"},
		{"dast https default port", "dast", "", "CVE-2023-44487", "", "https://a.example/x", "CVE-2023-44487", "443/tcp"},
		{"dast http default port", "dast", "", "CVE-2023-44487", "", "http://a.example/x", "CVE-2023-44487", "80/tcp"},
		{"dast explicit port", "dast", "", "CVE-2023-44487", "", "https://a.example:8443/x", "CVE-2023-44487", "8443/tcp"},
		{"advisory id is not a CVE", "network", "GHSA-aaaa-bbbb-cccc", "", "443/tcp", "", "", ""},
		{"scanner rule is not a CVE", "network", "rule:12345", "", "443/tcp", "", "", ""},
		{"dast rule that is no CVE", "dast", "", "exposed-panel", "", "https://a.example/", "", ""},
		{"dast without url", "dast", "", "CVE-2023-44487", "", "", "", ""},
		{"sast has no signal", "sast", "CVE-2023-44487", "", "", "", "", ""},
	}
	for _, c := range cases {
		cve, loc := VulnSignal(c.kind, c.vuln, c.rule, c.port, c.url)
		if cve != c.wantCVE || loc != c.wantLoc {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", c.name, cve, loc, c.wantCVE, c.wantLoc)
		}
	}
}

func TestKeys_VulnAssetNeedsACVEAnAssetAndALocator(t *testing.T) {
	k := Keys(vuln("a", "network", "CVE-2023-44487", "443/tcp"))
	if len(k) != 1 || k[0].Kind != KindVulnAsset || k[0].Locator != "443/tcp" || strings.Contains(k[0].Key, "CVE") {
		t.Fatalf("key: %+v", k)
	}
	if Keys(vuln("a", "dast", "GHSA-x", "443/tcp")) != nil || Keys(vuln("a", "dast", "CVE-2023-44487", "")) != nil {
		t.Error("a key without a CVE or a locator")
	}
	noAsset := vuln("a", "sca", "CVE-2023-44487", "host")
	noAsset.AssetID = ""
	if Keys(noAsset) != nil {
		t.Error("a key without an asset")
	}
	other := vuln("b", "network", "CVE-2023-44487", "443/tcp")
	other.AssetID = "asset-2"
	if Keys(other)[0].Key == k[0].Key {
		t.Error("the asset must be part of the key")
	}
	if Keys(vuln("c", "network", "CVE-2023-44488", "443/tcp"))[0].Key == k[0].Key {
		t.Error("the CVE must be part of the key")
	}
	if Keys(vuln("d", "dast", "cve-2023-44487", "80/tcp"))[0].Key != k[0].Key {
		t.Error("the port must not be part of the key (it is the locator)")
	}
}

func TestPlan_VulnAssetLinksTechniquesOnOneAsset(t *testing.T) {
	vm := vuln("vm", "network", "CVE-2023-44487", "443/tcp")
	nuclei := vuln("nu", "dast", "CVE-2023-44487", "443/tcp")
	p := plan([]Finding{nuclei}, []Finding{vm}, nil)
	if len(p.Make) != 1 || p.Make[0].PrimaryID != "vm" || p.Make[0].MemberID != "nu" || p.Make[0].Rule != RuleVulnAsset {
		t.Fatalf("want vm<-nu vuln_asset (the earliest is the original), got %+v", p.Make)
	}
	// The order of arrival does not change who the original is.
	p = plan([]Finding{vm}, []Finding{nuclei}, nil)
	if len(p.Make) != 1 || p.Make[0].PrimaryID != "nu" {
		t.Fatalf("the earlier-created finding is the original, got %+v", p.Make)
	}
}

func TestPlan_VulnAssetRefusals(t *testing.T) {
	cases := map[string][2]Finding{
		"different port":                 {vuln("a", "network", "CVE-2023-44487", "443/tcp"), vuln("b", "dast", "CVE-2023-44487", "8443/tcp")},
		"different CVE":                  {vuln("a", "network", "CVE-2023-44487", "443/tcp"), vuln("b", "dast", "CVE-2023-44488", "443/tcp")},
		"two SCA components, one host":   {vuln("a", "sca", "CVE-2023-44487", "host"), vuln("b", "sca", "CVE-2023-44487", "host")},
		"no locator on one side":         {vuln("a", "network", "CVE-2023-44487", "443/tcp"), vuln("b", "dast", "CVE-2023-44487", "")},
		"tcp and udp on the same number": {vuln("a", "network", "CVE-2023-44487", "443/udp"), vuln("b", "dast", "CVE-2023-44487", "443/tcp")},
	}
	for name, c := range cases {
		if p := plan([]Finding{c[1]}, []Finding{c[0]}, nil); len(p.Make) != 0 {
			t.Errorf("%s: linked %+v", name, p.Make)
		}
	}
	// The same CVE on two assets is never linked automatically.
	a, b := vuln("a", "network", "CVE-2023-44487", "443/tcp"), vuln("b", "dast", "CVE-2023-44487", "443/tcp")
	b.AssetID = "asset-2"
	if p := plan([]Finding{b}, []Finding{a}, nil); len(p.Make) != 0 {
		t.Errorf("linked across assets: %+v", p.Make)
	}
}

func TestPlan_VulnAssetHostLevelAgreesWithAPort(t *testing.T) {
	host := vuln("h", "network", "CVE-2023-44487", "host")
	nuclei := vuln("nu", "dast", "CVE-2023-44487", "443/tcp")
	if p := plan([]Finding{nuclei}, []Finding{host}, nil); len(p.Make) != 1 {
		t.Fatalf("host-level vs port-level: %+v", p.Make)
	}
	// A network report on a port and one at host level: one technique, two places.
	port := vuln("p", "network", "CVE-2023-44487", "443/tcp")
	if p := plan([]Finding{port}, []Finding{host}, nil); len(p.Make) != 1 {
		t.Fatalf("network host vs network port: %+v", p.Make)
	}
}

func TestPlan_VulnAssetThirdTechniqueJoinsTheGroupNeverDemotesTheOriginal(t *testing.T) {
	vm := vuln("vm", "network", "CVE-2023-44487", "443/tcp")
	nu := vuln("nu", "dast", "CVE-2023-44487", "443/tcp")
	existing := []Link{{PrimaryID: "vm", MemberID: "nu", Rule: RuleVulnAsset, State: StateActive}}
	// A scanner report created earlier than both (a backfill) still joins as a member.
	nessus := vuln("nx", "network", "CVE-2023-44487", "host")
	nessus.CreatedAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	p := plan([]Finding{nessus}, []Finding{vm, nu}, existing)
	if len(p.Make) != 1 || p.Make[0].PrimaryID != "vm" || p.Make[0].MemberID != "nx" {
		t.Fatalf("the original is never demoted: %+v", p.Make)
	}
}

func TestPlan_VulnAssetUnlinkedPairStaysApartAndAChangedSignalReleases(t *testing.T) {
	vm := vuln("vm", "network", "CVE-2023-44487", "443/tcp")
	nu := vuln("nu", "dast", "CVE-2023-44487", "443/tcp")
	if p := plan([]Finding{nu}, []Finding{vm}, []Link{{PrimaryID: "vm", MemberID: "nu", Rule: RuleVulnAsset, State: StateUnlinked}}); len(p.Make) != 0 {
		t.Fatalf("relinked an unlinked pair: %+v", p.Make)
	}
	moved := vuln("nu", "dast", "CVE-2023-44487", "8443/tcp")
	p := plan([]Finding{moved}, []Finding{vm}, []Link{{PrimaryID: "vm", MemberID: "nu", Rule: RuleVulnAsset, State: StateActive}})
	if len(p.Release) != 1 {
		t.Fatalf("a link whose ports no longer agree is released: %+v", p)
	}
}

func TestBasisOfVulnAsset(t *testing.T) {
	if got := strings.Join(Basis(RuleVulnAsset), ","); got != "asset,vuln,port" {
		t.Errorf("basis = %s", got)
	}
}
