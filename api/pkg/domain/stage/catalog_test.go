package stage

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// Every catalog entry is well formed: a key, inputs, a tier, exactly one
// default implementation, a fan-out cap within the run cap, and something
// it reports (assets or findings).
func TestCatalog_EntriesAreWellFormed(t *testing.T) {
	keys := map[Key]bool{}
	for _, s := range All() {
		if s.Key == "" || !strings.Contains(string(s.Key), ".") {
			t.Errorf("bad key %q", s.Key)
		}
		if keys[s.Key] {
			t.Errorf("%s: duplicate key", s.Key)
		}
		keys[s.Key] = true
		if len(s.Inputs) == 0 {
			t.Errorf("%s: no inputs", s.Key)
		}
		if len(s.Outputs) == 0 && !s.Findings {
			t.Errorf("%s: reports nothing", s.Key)
		}
		defaults := 0
		for _, i := range s.Implementations {
			if i.Default {
				defaults++
			}
			if i.Tool != strings.ToLower(i.Tool) {
				t.Errorf("%s: tool %q is not the registry spelling", s.Key, i.Tool)
			}
		}
		if defaults != 1 {
			t.Errorf("%s: %d default implementations, want 1", s.Key, defaults)
		}
		if s.MaxFanout <= 0 || s.MaxFanout > RunFanoutCap {
			t.Errorf("%s: max_fanout %d outside (0, %d]", s.Key, s.MaxFanout, RunFanoutCap)
		}
		if s.PerParentCap() > s.MaxFanout {
			t.Errorf("%s: per-parent cap above the stage cap", s.Key)
		}
	}
}

// Every input and output is a type the asset registry knows (F3: the outputs
// are real registry types, so a chain can be type-checked).
func TestCatalog_TypesAreRegistryTypes(t *testing.T) {
	for _, s := range All() {
		for _, typ := range append(slices.Clone(s.Inputs), s.Outputs...) {
			if _, ok := asset.LookupType(typ); !ok {
				t.Errorf("%s: %q is not a registry type", s.Key, typ)
			}
		}
	}
}

// Every shipped platform scanner maps to at least one stage, and each
// recon tool to exactly one (the planner and the router place its steps).
func TestCatalog_ShippedToolsHaveAStage(t *testing.T) {
	shipped := []string{
		"subfinder", "dnsx", "naabu", "httpx", "katana", "nuclei", "zap",
		"betterleaks", "trufflehog", "gitleaks", "semgrep", "trivy", "osv-scanner",
		"grype", "checkov", "kics", "tenable_sc",
	}
	for _, tool := range shipped {
		if len(ForTool(tool)) == 0 {
			t.Errorf("%s implements no stage", tool)
		}
	}
	for _, tool := range []string{"subfinder", "dnsx", "naabu", "httpx", "katana", "nuclei"} {
		if n := len(ForTool(tool)); n != 1 {
			t.Errorf("%s implements %d stages, want 1", tool, n)
		}
	}
	if ForTool("splunk") != nil {
		t.Error("a collector implements a stage")
	}
}

// The recon chain type-checks end to end: subfinder -> dnsx -> naabu ->
// httpx -> katana -> nuclei.
func TestCatalog_ReconChainFeeds(t *testing.T) {
	chain := []Key{DiscoverSubdomains, ResolveDNS, ScanPorts, ProbeHTTP, CrawlWeb, VulnTemplates}
	for i := 0; i+1 < len(chain); i++ {
		a, _ := Lookup(chain[i])
		b, _ := Lookup(chain[i+1])
		if !Feeds(a, b) {
			t.Errorf("%s does not feed %s", a.Key, b.Key)
		}
	}
	vuln, _ := Lookup(VulnTemplates)
	ports, _ := Lookup(ScanPorts)
	if Feeds(vuln, ports) {
		t.Error("a findings-only stage feeds another stage")
	}
	sast, _ := Lookup(SASTCode)
	if Feeds(sast, vuln) {
		t.Error("code analysis feeds a network stage")
	}
}

// Accepts and Produces compare canonical pairs: http_service is stored as
// service/http; a plain service (no sub-type) is not an http_service.
func TestStage_TypeMatchingUsesCanonicalPairs(t *testing.T) {
	crawl, _ := Lookup(CrawlWeb)
	if !crawl.Accepts(asset.TypeRef{Type: "service", SubType: "http"}) {
		t.Error("service/http is not accepted as http_service")
	}
	if !crawl.Accepts(asset.TypeRef{Type: asset.AssetTypeHTTPService}) {
		t.Error("http_service is not accepted")
	}
	if crawl.Accepts(asset.TypeRef{Type: "service", SubType: "open_port"}) {
		t.Error("an open port is accepted by the crawler")
	}
	if crawl.Accepts(asset.TypeRef{Type: asset.AssetTypeRepository}) {
		t.Error("a repository is accepted by the crawler")
	}
	dns, _ := Lookup(ResolveDNS)
	if !dns.Produces(asset.TypeRef{Type: asset.AssetTypeIPAddress}) || dns.Produces(asset.TypeRef{Type: asset.AssetTypeRepository}) {
		t.Error("resolve.dns outputs are wrong")
	}
	if !dns.MayReport(asset.TypeRef{Type: asset.AssetTypeSubdomain}) {
		t.Error("a re-observed input may not be reported")
	}
}

// The registry's output_types for a platform tool are the union of its
// stages' outputs, sorted; an unknown tool has none.
func TestOutputTypes(t *testing.T) {
	got := OutputTypes("dnsx")
	want := []string{"domain", "ip_address", "subdomain"}
	if !slices.Equal(got, want) {
		t.Errorf("dnsx outputs = %v, want %v", got, want)
	}
	if OutputTypes("nuclei") != nil {
		t.Errorf("nuclei creates assets: %v", OutputTypes("nuclei"))
	}
	if OutputTypes("not-a-tool") != nil {
		t.Error("an unknown tool has outputs")
	}
}

// A capability-only step names its stage by a catalog key or by a
// pre-catalog word that names exactly one stage; qualifier words name
// none, and two stages is ambiguous (F1: the planner must not guess).
func TestForCapabilities(t *testing.T) {
	cases := []struct {
		caps []string
		want Key
		err  error
	}{
		{[]string{"recon", "portscan"}, ScanPorts, nil},
		{[]string{"probe.http"}, ProbeHTTP, nil},
		{[]string{"Recon", " DNS "}, ResolveDNS, nil},
		{[]string{"recon", "subdomain"}, DiscoverSubdomains, nil},
		{[]string{"crawler", "url_discovery"}, CrawlWeb, nil},
		{[]string{"recon"}, "", ErrUnknownCapability},
		{[]string{"tech_detect", "web"}, "", ErrUnknownCapability},
		{nil, "", ErrUnknownCapability},
		{[]string{"portscan", "dns"}, "", ErrAmbiguousCapability},
	}
	for _, c := range cases {
		got, err := ForCapabilities(c.caps)
		if !errors.Is(err, c.err) {
			t.Errorf("%v: err = %v, want %v", c.caps, err, c.err)
			continue
		}
		if got.Key != c.want {
			t.Errorf("%v: stage = %s, want %s", c.caps, got.Key, c.want)
		}
	}
}

// A step's stage: the pinned tool's single stage; for a tool with several
// stages, the one its capabilities name; a tool the catalog does not
// know never chains.
func TestForStep(t *testing.T) {
	if s, ok := ForStep("naabu", []string{"recon"}); !ok || s.Key != ScanPorts {
		t.Errorf("naabu -> %s %v", s.Key, ok)
	}
	if s, ok := ForStep("trivy", []string{"iac"}); !ok || s.Key != IaCMisconfig {
		t.Errorf("trivy iac -> %s %v", s.Key, ok)
	}
	if _, ok := ForStep("trivy", []string{"recon"}); ok {
		t.Error("trivy without a naming capability was placed")
	}
	if _, ok := ForStep("my-custom-tool", []string{"portscan"}); ok {
		t.Error("an unknown tool was placed by its capabilities")
	}
	if s, ok := ForStep("", []string{"portscan"}); !ok || s.Key != ScanPorts {
		t.Errorf("capability-only step -> %s %v", s.Key, ok)
	}
}

func TestDefaultToolAndTools(t *testing.T) {
	s, _ := Lookup(SecretsCode)
	if s.DefaultTool() != "betterleaks" {
		t.Errorf("default = %s", s.DefaultTool())
	}
	if got := s.Tools(); got[0] != "betterleaks" || len(got) != 3 {
		t.Errorf("tools = %v", got)
	}
	if !s.Implements(" TruffleHog ") {
		t.Error("tool names are not normalized")
	}
}

// The catalog cannot be changed through what All or Lookup return.
func TestCatalog_ReturnsCopies(t *testing.T) {
	a := All()
	a[0].Outputs[0] = asset.AssetTypeRepository
	a[0].Implementations[0].Tool = "evil"
	s, _ := Lookup(a[0].Key)
	if s.Outputs[0] == asset.AssetTypeRepository || s.Implementations[0].Tool == "evil" {
		t.Fatal("the catalog was mutated through All")
	}
}

func TestTier(t *testing.T) {
	if TierPassive.String() != "T0" || !TierPassive.Passive() || TierActive.Passive() {
		t.Error("tier labels")
	}
	for _, k := range []Key{DiscoverSubdomains, ResolveDNS, SecretsCode, SASTCode} {
		s, _ := Lookup(k)
		if s.Tier != TierPassive {
			t.Errorf("%s is not T0", k)
		}
	}
	for _, k := range []Key{ScanPorts, ProbeHTTP, CrawlWeb, VulnTemplates} {
		s, _ := Lookup(k)
		if s.Tier != TierActive {
			t.Errorf("%s is not T1", k)
		}
	}
}

func TestValidateChain(t *testing.T) {
	ok := []ChainStage{
		{ID: "subdomains", Stage: DiscoverSubdomains, From: []string{FromSeeds}},
		{ID: "resolve", Stage: ResolveDNS, From: []string{FromSeeds, "subdomains"}},
		{ID: "ports", Stage: ScanPorts, From: []string{"resolve"}},
		{ID: "http", Stage: ProbeHTTP, From: []string{"ports"}},
		{ID: "crawl", Stage: CrawlWeb, From: []string{"http"}},
		{ID: "vulns", Stage: VulnTemplates, From: []string{"http", "crawl"}},
	}
	if err := ValidateChain(ok); err != nil {
		t.Fatalf("U2 rejected: %v", err)
	}
	bad := map[string][]ChainStage{
		"empty":       nil,
		"unknown":     {{ID: "a", Stage: "scan.everything"}},
		"duplicate":   {{ID: "a", Stage: ScanPorts}, {ID: "a", Stage: ProbeHTTP}},
		"forward ref": {{ID: "a", Stage: ProbeHTTP, From: []string{"b"}}, {ID: "b", Stage: ScanPorts}},
		"self ref":    {{ID: "a", Stage: ProbeHTTP, From: []string{"a"}}},
		"unreachable": {{ID: "v", Stage: VulnTemplates}, {ID: "c", Stage: CrawlWeb, From: []string{"v"}}},
		"code to net": {{ID: "s", Stage: SASTCode}, {ID: "p", Stage: ScanPorts, From: []string{"s"}}},
		"intrusive":   {{ID: "z", Stage: DASTWeb}},
		"seeds id":    {{ID: FromSeeds, Stage: ScanPorts}},
	}
	for name, chain := range bad {
		if err := ValidateChain(chain); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	err := ValidateChain(bad["unreachable"])
	if err == nil || !strings.Contains(err.Error(), "nothing it takes targets from produces") {
		t.Errorf("unreachable error = %v", err)
	}
}
