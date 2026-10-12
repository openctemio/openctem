package webendpoint

import (
	"testing"

	"github.com/openctemio/ctis"
)

func TestCatalog_MostSpecificMatch(t *testing.T) {
	cases := map[string]string{
		"/actuator/env":             "spring.actuator.env",
		"/actuator/env/password":    "spring.actuator.env",
		"/actuator/health":          "spring.actuator",
		"/.git/config":              "vcs.git",
		"/.env":                     "config.env",
		"/phpinfo.php":              "config.phpinfo",
		"/admin/users/{int}":        "admin.admin",
		"/ADMIN":                    "admin.admin",
		"/api/v1/pods":              "k8s.api",
		"/products/{int}":           "",
		"/administrators":           "",
		"/phpinfo.php/x":            "",
		"/wp-json/wp/v2/users/{id}": "cms.wp_json_users",
	}
	for tmpl, want := range cases {
		got := ""
		if e := DefaultCatalog.Match(tmpl); e != nil {
			got = e.Key
		}
		if got != want {
			t.Errorf("Match(%q) = %q, want %q", tmpl, got, want)
		}
	}
	if DefaultCatalog.ByKey("vcs.git") == nil || DefaultCatalog.ByKey("nope") != nil {
		t.Fatal("ByKey")
	}
	if len(DefaultCatalog.Entries) < 100 || DefaultCatalog.Version == "" {
		t.Fatalf("catalog has %d entries, version %q", len(DefaultCatalog.Entries), DefaultCatalog.Version)
	}
	seen := map[string]bool{}
	for _, e := range DefaultCatalog.Entries {
		if seen[e.Key] || e.Path == "" || e.Path[0] != '/' || e.Severity == "" || e.Title == "" {
			t.Errorf("bad entry %+v", e)
		}
		seen[e.Key] = true
	}
}

func TestObserve_SetsCatalogKey(t *testing.T) {
	obs, err := Observe(ctis.Endpoint{Origin: "https://a.example.com", Path: "/actuator/heapdump"})
	if err != nil || obs.CatalogKey != "spring.actuator.heapdump" {
		t.Fatalf("catalog key = %q, err %v", obs.CatalogKey, err)
	}
}

func TestFillTemplate_UsesPlaceholdersNeverValues(t *testing.T) {
	if got := FillTemplate("/orders/{int}/reset/{token}/{uuid}"); got != "/orders/1/reset/test/00000000-0000-0000-0000-000000000001" {
		t.Fatalf("FillTemplate = %q", got)
	}
	if got := FillTemplate("/orders/42"); got != "/orders/42" {
		t.Fatalf("a concrete path changed: %q", got)
	}
}
