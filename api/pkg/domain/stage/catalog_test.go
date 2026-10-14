package stage_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	. "github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/domain/stage/stagetest"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// Every catalog entry is well formed: a key, inputs, a tier, exactly one
// default implementation, a fan-out cap within the run cap, and something
// it reports (assets or findings).
func TestCatalog_EntriesAreWellFormed(t *testing.T) {
	keys := map[Key]bool{}
	for _, s := range cat.All() {
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
		if want := min(len(s.Implementations), 1); defaults != want {
			t.Errorf("%s: %d default implementations, want %d", s.Key, defaults, want)
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
	for _, s := range cat.All() {
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

// Every built-in tool maps to at least one stage, and each recon tool to
// exactly one (the planner and the router place its steps). A tool no
// reported contract names implements nothing.
func TestCatalog_ShippedToolsHaveAStage(t *testing.T) {
	for _, f := range stagetest.Builtins() {
		if len(cat.ForTool(f.Name)) == 0 {
			t.Errorf("%s implements no stage", f.Name)
		}
	}
	for _, tool := range []string{"zap", "gitleaks", "tenable_sc"} {
		if len(cat.ForTool(tool)) != 0 || len(Catalog{}.ForTool("naabu")) != 0 {
			t.Errorf("%s implements a stage without a reported contract", tool)
		}
	}
	for _, tool := range []string{"subfinder", "dnsx", "httpx", "katana", "nuclei"} {
		if n := len(cat.ForTool(tool)); n != 1 {
			t.Errorf("%s implements %d stages, want 1", tool, n)
		}
	}
	// naabu also runs host discovery, only when a step names it.
	if n := len(cat.ForTool("naabu")); n != 2 {
		t.Errorf("naabu implements %d stages, want 2 (port scan, host discovery)", n)
	}
	if cat.ForTool("splunk") != nil {
		t.Error("a collector implements a stage")
	}
}

// The recon chain type-checks end to end: subfinder -> dnsx -> naabu ->
// httpx -> katana -> nuclei.
func TestCatalog_ReconChainFeeds(t *testing.T) {
	chain := []Key{DiscoverSubdomains, ResolveDNS, ScanPorts, ProbeHTTP, CrawlWeb, VulnTemplates}
	for i := 0; i+1 < len(chain); i++ {
		a, _ := cat.Lookup(chain[i])
		b, _ := cat.Lookup(chain[i+1])
		if !Feeds(a, b) {
			t.Errorf("%s does not feed %s", a.Key, b.Key)
		}
	}
	vuln, _ := cat.Lookup(VulnTemplates)
	ports, _ := cat.Lookup(ScanPorts)
	if Feeds(vuln, ports) {
		t.Error("a findings-only stage feeds another stage")
	}
	sast, _ := cat.Lookup(SASTCode)
	if Feeds(sast, vuln) {
		t.Error("code analysis feeds a network stage")
	}
}

// Accepts and Produces compare canonical pairs: http_service is stored as
// service/http; a plain service (no sub-type) is not an http_service.
func TestStage_TypeMatchingUsesCanonicalPairs(t *testing.T) {
	crawl, _ := cat.Lookup(CrawlWeb)
	if !crawl.Accepts(asset.TypeRef{Type: "service", SubType: "http"}) {
		t.Error("service/http is not accepted as http_service")
	}
	if !crawl.Accepts(asset.TypeRef{Type: "http_service"}) {
		t.Error("the input name http_service is not accepted")
	}
	if !crawl.Accepts(asset.TypeRef{Type: "discovered_url"}) {
		t.Error("the input name discovered_url is not accepted")
	}
	ports, _ := cat.Lookup(ScanPorts)
	if !ports.Accepts(asset.TypeRef{Type: asset.AssetTypeIPAddress, SubType: "v4"}) {
		t.Error("a type without a sub-type in the catalog does not match its sub-types")
	}
	if crawl.Accepts(asset.TypeRef{Type: "service", SubType: "open_port"}) {
		t.Error("an open port is accepted by the crawler")
	}
	if crawl.Accepts(asset.TypeRef{Type: asset.AssetTypeRepository}) {
		t.Error("a repository is accepted by the crawler")
	}
	dns, _ := cat.Lookup(ResolveDNS)
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
	got := cat.OutputTypes("dnsx")
	want := []string{"domain", "ip_address", "subdomain"}
	if !slices.Equal(got, want) {
		t.Errorf("dnsx outputs = %v, want %v", got, want)
	}
	if got := cat.OutputTypes("httpx"); !slices.Equal(got, []string{"certificate", "ip_address", "service/http"}) {
		t.Errorf("httpx outputs = %v", got)
	}
	if cat.OutputTypes("nuclei") != nil {
		t.Errorf("nuclei creates assets: %v", cat.OutputTypes("nuclei"))
	}
	if cat.OutputTypes("not-a-tool") != nil {
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
		got, err := cat.ForCapabilities(c.caps)
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
	if s, ok := cat.ForStep("naabu", []string{"recon"}); !ok || s.Key != ScanPorts {
		t.Errorf("naabu -> %s %v", s.Key, ok)
	}
	// naabu runs host discovery only when the step names it; pinned
	// without a capability (every existing naabu step and quick scan), it
	// is a port scan.
	for _, caps := range [][]string{nil, {"recon"}, {"portscan"}, {"scan.ports"}} {
		if s, ok := cat.ForStep("naabu", caps); !ok || s.Key != ScanPorts {
			t.Errorf("naabu %v -> %s %v, want scan.ports", caps, s.Key, ok)
		}
	}
	if s, ok := cat.ForStep("naabu", []string{"discover.hosts"}); !ok || s.Key != DiscoverHosts {
		t.Errorf("naabu discover.hosts -> %s %v", s.Key, ok)
	}
	if s, ok := cat.ForStep("", []string{"discover.hosts"}); !ok || s.Key != DiscoverHosts || s.DefaultTool() != "naabu" {
		t.Errorf("discover.hosts -> %s %v", s.Key, ok)
	}
	if s, ok := cat.ForStep("trivy", []string{"iac"}); !ok || s.Key != IaCMisconfig {
		t.Errorf("trivy iac -> %s %v", s.Key, ok)
	}
	// Pinned without a capability naming one of its stages, a tool runs its
	// primary capability (the first its contract implements).
	if s, ok := cat.ForStep("trivy", []string{"recon"}); !ok || s.Key != SCADeps {
		t.Errorf("trivy recon -> %s %v, want sca.deps", s.Key, ok)
	}
	if _, ok := cat.ForStep("my-custom-tool", []string{"portscan"}); ok {
		t.Error("an unknown tool was placed by its capabilities")
	}
	if s, ok := cat.ForStep("", []string{"portscan"}); !ok || s.Key != ScanPorts {
		t.Errorf("capability-only step -> %s %v", s.Key, ok)
	}
}

func TestDefaultToolAndTools(t *testing.T) {
	s, _ := cat.Lookup(SASTCode)
	if s.DefaultTool() != "semgrep" {
		t.Errorf("default = %s", s.DefaultTool())
	}
	if got := s.Tools(); !slices.Equal(got, []string{"semgrep", "opengrep", "codeql"}) {
		t.Errorf("tools = %v", got)
	}
	if !s.Implements(" OpenGrep ") {
		t.Error("tool names are not normalized")
	}
}

// The catalog cannot be changed through what All or Lookup return.
func TestCatalog_ReturnsCopies(t *testing.T) {
	a := cat.All()
	a[0].Outputs[0] = asset.TypeRef{Type: "repository"}
	a[0].Implementations[0].Tool = "evil"
	s, _ := cat.Lookup(a[0].Key)
	if s.Outputs[0].Type == "repository" || s.Implementations[0].Tool == "evil" {
		t.Fatal("the catalog was mutated through All")
	}
}

func TestTier(t *testing.T) {
	if TierPassive.String() != "T0" || !TierPassive.Passive() || TierActive.Passive() {
		t.Error("tier labels")
	}
	for _, k := range []Key{DiscoverSubdomains, ResolveDNS, SecretsCode, SASTCode} {
		s, _ := cat.Lookup(k)
		if s.Tier != TierPassive {
			t.Errorf("%s is not T0", k)
		}
	}
	for _, k := range []Key{ScanPorts, ProbeHTTP, CrawlWeb, VulnTemplates} {
		s, _ := cat.Lookup(k)
		if s.Tier != TierActive {
			t.Errorf("%s is not T1", k)
		}
	}
}

func TestPassiveTools(t *testing.T) {
	passive := cat.PassiveTools()
	for _, tool := range []string{"subfinder", "dnsx", "semgrep", "trivy", "betterleaks"} {
		if !slices.Contains(passive, tool) || !cat.PassiveTool(tool) {
			t.Errorf("%s is a T0 tool but not passive", tool)
		}
	}
	for _, tool := range []string{"nuclei", "naabu", "httpx", "katana", "toyweb", "gitleaks", "unknown-tool", ""} {
		if slices.Contains(passive, tool) || cat.PassiveTool(tool) {
			t.Errorf("%s sends traffic to its targets (or is unknown) but counts as passive", tool)
		}
	}
	if !cat.PassiveTool(" Subfinder ") {
		t.Error("tool names are compared in registry spelling")
	}
}

func TestToolCanRun(t *testing.T) {
	for _, tc := range []struct {
		tool  string
		caps  []string
		word  string
		allow bool
	}{
		{"dnsx", []string{"recon", "dns"}, "resolve.dns", true},
		{"dnsx", []string{"recon", "dns"}, "dns", true},
		{"dnsx", nil, "resolve.dns", true}, // the catalog has dnsx implement it
		{"dnsx", []string{"recon", "dns"}, "scan", false},
		{"dnsx", []string{"recon", "dns"}, "scan.ports", false},
		{"custom", []string{"dns"}, "resolve.dns", true},
		{"custom", []string{"resolve.dns"}, "dns", true},
		{"custom", []string{"dns"}, "probe.http", false},
		{"custom", []string{"dns"}, "", false},
	} {
		if got := cat.ToolCanRun(tc.tool, tc.caps, tc.word); got != tc.allow {
			t.Errorf("cat.ToolCanRun(%s, %v, %q) = %v, want %v", tc.tool, tc.caps, tc.word, got, tc.allow)
		}
	}
	// The mapping never places a tool the catalog does not know on a stage:
	// such a tool gains no contract and never chains.
	if _, ok := cat.ForStep("custom", []string{"resolve.dns"}); ok {
		t.Error("a tool the catalog does not know was placed on a stage")
	}
}
