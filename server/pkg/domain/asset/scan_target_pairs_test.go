package asset

import (
	"os"
	"regexp"
	"testing"
)

func TestScanTargetPairsFollowScannableBy(t *testing.T) {
	pairs := ScanTargetPairs()
	if len(pairs) == 0 {
		t.Fatal("the registry declares scannable pairs")
	}
	seen := map[ScanTargetPair]bool{}
	for _, p := range pairs {
		if seen[p] {
			t.Fatalf("duplicate pair %+v", p)
		}
		seen[p] = true
	}
	if !seen[ScanTargetPair{TargetType: "domain", Type: AssetTypeDomain}] {
		t.Fatal("domain -> domain must be a registry pair")
	}
}

func TestRegistryCoversMapping(t *testing.T) {
	cases := []struct {
		target string
		name   AssetType
		want   bool
	}{
		{"url", "website", true},
		{"domain", "domain", true},
		{"cloud_account", "cloud_account", true},
		{"repository", "repository", true},
		// A target the registry does not list for the type.
		{"certificate", "domain", false},
		{"url", "no_such_type", false},
		// A mapping on a core type also reaches its alias sub-types, so it is
		// covered only when the registry lists the target for all of them.
		{"host", "host", false},
	}
	for _, c := range cases {
		if got := RegistryCoversMapping(c.target, c.name); got != c.want {
			t.Errorf("RegistryCoversMapping(%q, %q) = %v, want %v", c.target, c.name, got, c.want)
		}
	}
}

// The migration that removed the registry-covered seed rows names exactly the
// seeded pairs the registry covers: nothing it deletes goes beyond the
// registry, and nothing the registry covers is left behind.
func TestSeedMigrationRemovesExactlyTheCoveredRows(t *testing.T) {
	pair := regexp.MustCompile(`\('([a-z0-9_]+)', '([a-z0-9_]+)'\)`)
	seedRaw, err := os.ReadFile("../../../migrations/001146_baseline.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	insert := regexp.MustCompile(`INSERT INTO public\.target_asset_type_mappings \(.*?\) VALUES \('[^']*', '([^']*)', '([^']*)', \d+, NULL, (?:true|false), '[^']*', '[^']*', NULL\);`)
	seeded := map[[2]string]bool{}
	for _, m := range insert.FindAllStringSubmatch(string(seedRaw), -1) {
		seeded[[2]string{m[1], m[2]}] = true
	}
	if len(seeded) != 38 {
		t.Fatalf("baseline seeds %d mappings, want 38", len(seeded))
	}
	files, err := os.ReadDir("../../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	var upPath string
	for _, f := range files {
		if regexp.MustCompile(`^\d+_target_mappings_registry_covered_seed_rows\.up\.sql$`).MatchString(f.Name()) {
			upPath = "../../../migrations/" + f.Name()
		}
	}
	if upPath == "" {
		t.Fatal("migration target_mappings_registry_covered_seed_rows not found")
	}
	upRaw, err := os.ReadFile(upPath)
	if err != nil {
		t.Fatal(err)
	}
	deleted := map[[2]string]bool{}
	for _, m := range pair.FindAllStringSubmatch(string(upRaw), -1) {
		deleted[[2]string{m[1], m[2]}] = true
	}
	for p := range seeded {
		covered := RegistryCoversMapping(p[0], AssetType(p[1]))
		if covered && !deleted[p] {
			t.Errorf("seeded %v is covered by the registry but not removed", p)
		}
		if !covered && deleted[p] {
			t.Errorf("seeded %v goes beyond the registry but is removed", p)
		}
	}
	for p := range deleted {
		if !seeded[p] {
			t.Errorf("migration removes %v, which was never seeded", p)
		}
	}
}
