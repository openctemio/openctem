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
		for _, ref := range append(slices.Clone(s.Inputs), s.Outputs...) {
			if _, ok := asset.LookupType(ref.Type); !ok {
				t.Errorf("%s: %q is not a registry type", s.Key, ref.Type)
			}
			if c := asset.CanonicalPair(ref.Type, ref.SubType); c != ref {
				t.Errorf("%s: %s is an input name; the catalog names stored pairs (%s)", s.Key, Label(ref), Label(c))
			}
			if ref.SubType != "" && !asset.IsValidSubType(ref.Type, ref.SubType) {
				t.Errorf("%s: %s is not a sub-type of %s", s.Key, ref.SubType, ref.Type)
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
	if !crawl.Accepts(asset.TypeRef{Type: "http_service"}) {
		t.Error("the input name http_service is not accepted")
	}
	if !crawl.Accepts(asset.TypeRef{Type: "discovered_url"}) {
		t.Error("the input name discovered_url is not accepted")
	}
	ports, _ := Lookup(ScanPorts)
	if !ports.Accepts(asset.TypeRef{Type: asset.AssetTypeIPAddress, SubType: "v4"}) {
		t.Error("a type without a sub-type in the catalog does not match its sub-types")
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
	if got := OutputTypes("httpx"); !slices.Equal(got, []string{"certificate", "ip_address", "service/http"}) {
		t.Errorf("httpx outputs = %v", got)
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
	a[0].Outputs[0] = asset.TypeRef{Type: "repository"}
	a[0].Implementations[0].Tool = "evil"
	s, _ := Lookup(a[0].Key)
	if s.Outputs[0].Type == "repository" || s.Implementations[0].Tool == "evil" {
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

func TestPassiveTools(t *testing.T) {
	passive := PassiveTools()
	for _, tool := range []string{"subfinder", "dnsx", "semgrep", "trivy", "gitleaks"} {
		if !slices.Contains(passive, tool) || !PassiveTool(tool) {
			t.Errorf("%s is a T0 tool but not passive", tool)
		}
	}
	for _, tool := range []string{"nuclei", "naabu", "httpx", "katana", "zap", "tenable_sc", "unknown-tool", ""} {
		if slices.Contains(passive, tool) || PassiveTool(tool) {
			t.Errorf("%s sends traffic to its targets (or is unknown) but counts as passive", tool)
		}
	}
	if !PassiveTool(" Subfinder ") {
		t.Error("tool names are compared in registry spelling")
	}
}
