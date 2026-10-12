package sensor

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testContractDigest = "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"

func validContract() *ToolContract {
	return &ToolContract{
		APIVersion: ToolContractAPIVersion, Digest: testContractDigest, Version: "1.0.0",
		Class: "target-scan", Tier: "T1", Network: "targets",
		Consumes: []string{"domain", "http_service", "domain"},
		Produces: []string{"asset:http_service", "asset:certificate", "finding:vulnerability", "asset:http_service"},
	}
}

func TestSanitizeToolContract(t *testing.T) {
	got, why := SanitizeToolContract(validContract())
	if got == nil {
		t.Fatalf("valid contract refused: %s", why)
	}
	if !reflect.DeepEqual(got.Consumes, []string{"domain", "http_service"}) ||
		!reflect.DeepEqual(got.Produces, []string{"asset:http_service", "asset:certificate", "finding:vulnerability"}) {
		t.Fatalf("not deduplicated: %+v", got)
	}
	if c, _ := SanitizeToolContract(nil); c != nil {
		t.Fatal("nil contract kept")
	}

	long := strings.Repeat("a", 200)
	many := make([]string, MaxToolContractTypes+1)
	for i := range many {
		many[i] = "asset:domain"
	}
	for name, mut := range map[string]func(c *ToolContract){
		"api version":        func(c *ToolContract) { c.APIVersion = "openctem.io/tool/v9" },
		"digest":             func(c *ToolContract) { c.Digest = "sha256:XYZ" },
		"digest md5":         func(c *ToolContract) { c.Digest = "md5:" + strings.Repeat("a", 32) },
		"version":            func(c *ToolContract) { c.Version = "1.0.0; rm -rf /" },
		"version long":       func(c *ToolContract) { c.Version = long },
		"class":              func(c *ToolContract) { c.Class = "exploit" },
		"tier":               func(c *ToolContract) { c.Tier = "T9" },
		"network":            func(c *ToolContract) { c.Network = "anywhere" },
		"T2 parser":          func(c *ToolContract) { c.Class, c.Tier = "parser", "T2" },
		"produce kind":       func(c *ToolContract) { c.Produces = []string{"command:shell"} },
		"produce type":       func(c *ToolContract) { c.Produces = []string{"asset:Repo<script>"} },
		"produce long":       func(c *ToolContract) { c.Produces = []string{"asset:" + long} },
		"produce bare":       func(c *ToolContract) { c.Produces = []string{"asset"} },
		"too many produces":  func(c *ToolContract) { c.Produces = many },
		"too many consumes":  func(c *ToolContract) { c.Consumes = many },
		"consume control":    func(c *ToolContract) { c.Consumes = []string{"domain\n"} },
		"consume long":       func(c *ToolContract) { c.Consumes = []string{long} },
		"produce empty item": func(c *ToolContract) { c.Produces = []string{""} },
	} {
		c := validContract()
		mut(c)
		if got, why := SanitizeToolContract(c); got != nil || why == "" {
			t.Errorf("%s: kept %+v (why %q)", name, got, why)
		}
	}
	// Consumes may name file media types and finding types.
	c := validContract()
	c.Class, c.Tier, c.Network = "parser", "T0", "none"
	c.Consumes = []string{"file:application/sarif+json", "finding:vulnerability"}
	if got, why := SanitizeToolContract(c); got == nil {
		t.Fatalf("parser contract refused: %s", why)
	}
}

func TestToolContractDeclares(t *testing.T) {
	c, _ := SanitizeToolContract(validContract())
	if !c.Declares(ProduceAsset, "http_service") || !c.Declares(ProduceAsset, "HTTP_Service") || !c.Declares(ProduceFinding, "vulnerability") {
		t.Fatal("declared type not found")
	}
	if c.Declares(ProduceAsset, "repository") || c.Declares(ProduceFinding, "secret") || c.Declares(ProduceDependency, "") {
		t.Fatal("undeclared type found")
	}
	var nilC *ToolContract
	if nilC.Declares(ProduceAsset, "domain") {
		t.Fatal("nil contract declares")
	}
}

// A manifest's tool contract survives sanitizing; an invalid one is dropped
// whole with the reason recorded, and the tool itself is kept.
func TestManifestSanitizedContracts(t *testing.T) {
	good, _ := json.Marshal(validContract())
	bad := validContract()
	bad.Produces = []string{"asset:Repo<script>"}
	badRaw, _ := json.Marshal(bad)
	raw := `{"schema":1,"tools":[
	  {"name":"httpx","installed":true,"capabilities":["http"],"contract":` + string(good) + `},
	  {"name":"nuclei","installed":true,"capabilities":["dast"],"contract":` + string(badRaw) + `},
	  {"name":"trivy","installed":true}
	]}`
	m, _, _, err := ParseManifest([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	rep := m.CapabilityInput().Sanitize(map[string]bool{"httpx": true, "nuclei": true, "trivy": true},
		map[string]bool{"http": true, "dast": true})
	clean, ignored := m.Sanitized(rep, time.Now())
	if c := clean.ToolContract("HTTPX"); c == nil || c.Digest != testContractDigest || len(c.Produces) != 3 {
		t.Fatalf("httpx contract = %+v", c)
	}
	if clean.ToolContract("nuclei") != nil || clean.ToolContract("trivy") != nil || clean.ToolContract("zap") != nil {
		t.Fatal("an invalid or absent contract was kept")
	}
	if len(clean.Tools) != 3 {
		t.Fatalf("a tool with an invalid contract was dropped: %+v", clean.Tools)
	}
	want := []ManifestIgnored{{Path: "tools[1].contract", Value: "invalid produces entry", Reason: IgnoredInvalidContract}}
	if !reflect.DeepEqual(ignored, want) {
		t.Fatalf("ignored = %+v", ignored)
	}
	// The stored form round-trips and a contract change shows in the diff.
	next := clean
	next.Tools = append([]ManifestTool(nil), clean.Tools...)
	c2 := *next.Tools[0].Contract
	c2.Digest = "sha256:" + strings.Repeat("c", 64)
	next.Tools[0].Contract = &c2
	d := DiffManifests(clean, next)
	if len(d.Contracts) != 1 || d.Contracts[0].Tool != "httpx" || d.Contracts[0].To != c2.Digest || d.IsEmpty() ||
		!strings.Contains(d.Summary(), "tool contract of 1 changed") {
		t.Fatalf("diff = %+v / %q", d, d.Summary())
	}
}

// A sensor without contracts sanitizes exactly as before (no contract
// member appears in the stored document).
func TestManifestSanitizedWithoutContracts(t *testing.T) {
	m, _, _, err := ParseManifest([]byte(liveManifest))
	if err != nil {
		t.Fatal(err)
	}
	rep := m.CapabilityInput().Sanitize(map[string]bool{"nuclei": true, "semgrep": true, "trivy": true},
		map[string]bool{"dast": true, "sast": true, "sca": true})
	clean, _ := m.Sanitized(rep, time.Now())
	b, _ := json.Marshal(clean)
	if strings.Contains(string(b), "contract") {
		t.Fatalf("contract member in a manifest without contracts: %s", b)
	}
}
