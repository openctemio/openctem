package sensor

import (
	"os"
	"slices"
	"testing"
	"time"
)

// legacyCapabilityWords are the capability registry rows a platform holds
// before OC5 (the words sensors reported before the tool contract).
var legacyCapabilityWords = []string{"dast", "recon", "subdomain", "dns", "portscan", "http", "tech_detect", "crawler", "url_discovery"}

// The manifest sensor v0.11.0 sent (captured from the real image against a
// scratch API): each tool reports its legacy words and its ctis taxonomy
// capability ("vuln.templates"). Both are kept; nothing is ignored (before,
// the six taxonomy ids were ignored as unknown-capability).
func TestManifest_SensorV011TaxonomyCapabilitiesKept(t *testing.T) {
	raw, err := os.ReadFile("testdata/manifest-sensor-v0.11.0.json")
	if err != nil {
		t.Fatal(err)
	}
	m, _, ignoredMembers, err := ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	knownTools := map[string]bool{}
	for _, tl := range m.Tools {
		knownTools[tl.Name] = true
	}
	knownCaps := map[string]bool{}
	for _, w := range legacyCapabilityWords {
		knownCaps[w] = true
	}
	in := m.CapabilityInput()
	rep := in.Sanitize(knownTools, knownCaps)
	clean, ignored := m.Sanitized(rep, time.Now())
	if len(ignoredMembers)+len(ignored) != 0 {
		t.Fatalf("ignored: %+v %+v", ignoredMembers, ignored)
	}
	want := map[string]string{
		"nuclei": "vuln.templates", "subfinder": "discover.subdomains", "dnsx": "resolve.dns",
		"naabu": "scan.ports", "httpx": "probe.http", "katana": "crawl.web",
	}
	if len(clean.Tools) != len(want) {
		t.Fatalf("tools %d, want %d", len(clean.Tools), len(want))
	}
	for _, tl := range clean.Tools {
		if !slices.Contains(tl.Capabilities, want[tl.Name]) {
			t.Errorf("%s capabilities %v lack %s", tl.Name, tl.Capabilities, want[tl.Name])
		}
	}
}

// Taxonomy ids are accepted with or without their major; anything else
// that is not in the registry, the taxonomy or the tool list stays unknown.
func TestKnownCapabilityTaxonomy(t *testing.T) {
	for _, c := range []string{"scan.ports", "scan.ports@1", "verify.finding", "sbom.generate@1"} {
		if !validCapName(c) || !knownCapability(c, nil, nil) {
			t.Errorf("%s: not known", c)
		}
	}
	for _, c := range []string{"scan.everything", "scan.ports@9", "Scan.Ports", "portscan"} {
		if validCapName(c) && knownCapability(c, nil, nil) {
			t.Errorf("%s: known without a registry row", c)
		}
	}
}
