package main

import (
	"os"
	"strings"
	"testing"
)

// The committed Go and TypeScript catalogs match the YAML.
func TestGeneratedFilesUpToDate(t *testing.T) {
	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir("../.."); err != nil {
		t.Fatal(err)
	}
	if err := run(true); err != nil {
		t.Fatal(err)
	}
}

const good = `version: 1
types:
  - id: dns.takeover_check
    version: 1
    subject: asset
    likelihood: medium
    value_weight: 2
    max_attempts: 2
    reasons: [cname_dangling]
    settle: finding
    actions:
      - capability: check.takeover
        asset_types: [subdomain]
`

func TestValidate(t *testing.T) {
	if _, err := parse([]byte(good)); err != nil {
		t.Fatalf("good catalog refused: %v", err)
	}
	bad := map[string][2]string{
		"unknown capability":                        {"capability: check.takeover", "capability: run.shell"},
		"type the stage does not take":              {"asset_types: [subdomain]", "asset_types: [repository]"},
		"unknown asset type":                        {"asset_types: [subdomain]", "asset_types: [spaceship]"},
		"bad id":                                    {"id: dns.takeover_check", "id: Takeover"},
		"bad likelihood":                            {"likelihood: medium", "likelihood: certain"},
		"weight out of range":                       {"value_weight: 2", "value_weight: 50"},
		"attempts out of range":                     {"max_attempts: 2", "max_attempts: 0"},
		"bad reason":                                {"reasons: [cname_dangling]", "reasons: [Cname Dangling]"},
		"unknown field (a tier cannot be set here)": {"    max_attempts: 2\n", "    max_attempts: 2\n    tier: 0\n"},
	}
	for name, r := range bad {
		src := strings.Replace(good, r[0], r[1], 1)
		if src == good {
			t.Fatalf("%s: replacement did not apply", name)
		}
		if _, err := parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
