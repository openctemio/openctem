package remediation

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestFixedVersionsFromAdvice(t *testing.T) {
	for _, c := range []struct {
		pkg, advice string
		want        string
	}{
		{"django", "Upgrade Django to 1.11.28, 2.2.10, 3.0.3", "1.11.28,2.2.10,3.0.3"},
		{"jquery", "Upgrade jquery to v3.5.0 or later.", "3.5.0"},
		{"@babel/core", "Upgrade @babel/core to 7.23.2", "7.23.2"},
		{"django", "Upgrade Flask to 2.0.1", ""},               // another package
		{"django", "Apply the suggested fix code.", ""},        // boilerplate
		{"django", "Upgrade Django to the latest version", ""}, // no version
		{"", "Upgrade Django to 1.2.3", ""},
	} {
		got := strings.Join(vulnerability.FixedVersionsFromAdvice(c.pkg, c.advice), ",")
		if got != c.want {
			t.Errorf("%q / %q: got %q, want %q", c.pkg, c.advice, got, c.want)
		}
	}
}

// A package with many advisories is one upgrade group: every open finding of
// the installed version gets the highest target any of them needs.
func TestConsolidateUpgrades(t *testing.T) {
	src := func(name, installed, advice string, fixed []string, open bool) KeySource {
		return KeySource{FindingID: shared.NewID(), Open: open, Input: KeyInput{
			Source: "sca", Ecosystem: "pypi", PackageName: name, InstalledVersion: installed,
			FixedVersions: fixed, SolutionText: advice,
		}}
	}
	sources := []KeySource{
		src("Django", "1.8.3", "Upgrade Django to 1.11.28, 2.2.10, 3.0.3", nil, true), // own: 1.11.28
		src("Django", "1.8.3", "Upgrade Django to 1.11.29, 2.2.13, 3.0.7", nil, true), // own: 1.11.29
		src("Django", "1.8.3", "Upgrade Django to 5.2.8, 5.1.14, 4.2.26", nil, true),  // own: 4.2.26
		src("Django", "1.8.3", "Upgrade Django to 9.9.9", nil, false),                 // closed: does not raise the target
		src("Django", "3.2.0", "", []string{"3.2.25", "4.2.11"}, true),                // another installed version
		src("jquery", "2.1.4", "Upgrade jquery to 3.0.0", nil, true),
		src("jquery", "2.1.4", "Upgrade jquery to 3.4.0", nil, true),
		src("jquery", "2.1.4", "Upgrade jquery to 3.5.0", nil, true),
		{FindingID: shared.NewID(), Open: true, Input: KeyInput{Source: "dast", SolutionText: "Upgrade JBoss to 7.1"}}, // no package
	}
	ConsolidateUpgrades(sources, func(s KeySource) bool { return s.Open })
	keys := map[string]int{}
	titles := map[string]string{}
	for _, s := range sources {
		k, title, ok := DeriveKey(s.Input)
		if !ok {
			continue
		}
		keys[k]++
		titles[k] = title
	}
	want := map[string]int{
		"upgrade:pypi:django:4.2.26": 4, // the three open advisories and the closed one, one group
		"upgrade:pypi:django:3.2.25": 1,
		"upgrade:pypi:jquery:3.5.0":  3,
	}
	for k, n := range want {
		if keys[k] != n {
			t.Errorf("group %s: %d findings, want %d (all: %v)", k, keys[k], n, keys)
		}
	}
	if titles["upgrade:pypi:django:4.2.26"] != "Upgrade Django to 4.2.26" {
		t.Errorf("title %q", titles["upgrade:pypi:django:4.2.26"])
	}
	for k := range keys {
		if strings.HasPrefix(k, "upgrade:pypi:django:1.11") || strings.HasPrefix(k, "upgrade:pypi:jquery:3.0") ||
			strings.HasPrefix(k, "upgrade:pypi:jquery:3.4") || strings.HasPrefix(k, "upgrade:pypi:django:9") {
			t.Errorf("fragmented group %s left", k)
		}
	}
}
