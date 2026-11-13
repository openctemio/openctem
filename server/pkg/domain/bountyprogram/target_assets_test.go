package bountyprogram

import (
	"strings"
	"testing"
)

func TestTargetAssets_EachTypeMaps(t *testing.T) {
	items, err := ParseScope(strings.Join([]string{
		"In scope:",
		"www.acme.example",
		"*.acme.example",
		"203.0.113.5",
		"198.51.100.0/24",
		"api.acme.example:8443/tcp",
		"10.9.8.7:22",
		"https://shop.acme.example/api/",
		"Out of scope:",
		"admin.acme.example",
	}, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Typed items a file or feed names.
	items = append(items,
		withType(ClassifyTyped("com.acme.app", "android_app"), true, ""),
		withType(ClassifyTyped("github.com/acme/app", "source_code"), true, ""),
		withType(ClassifyTyped("0xabc", "smart_contract"), true, ""),
		withType(ClassifyTyped("acme-model", "ai_model"), true, ""),
		withType(ClassifyTyped("acme.exe", "executable"), true, ""),
		withType(ClassifyTyped("https://graph.acme.example/graphql/", "api"), true, ""),
		// An inferred target nobody confirmed (not scannable): no asset.
		withType(Item{Raw: "guess.acme.example", Kind: KindOther}, true, ConfidenceInferred),
	)
	got := map[string]string{}
	for _, a := range TargetAssets(items) {
		got[a.Type+" "+a.Value] = a.Key
	}
	want := map[string]string{
		"domain www.acme.example":                       "www.acme.example",
		"domain acme.example":                           "*.acme.example",
		"ip_address 203.0.113.5":                        "203.0.113.5",
		"network 198.51.100.0/24":                       "198.51.100.0/24",
		"domain api.acme.example":                       "api.acme.example:8443/tcp",
		"service api.acme.example:8443/tcp":             "api.acme.example:8443/tcp",
		"ip_address 10.9.8.7":                           "10.9.8.7:22",
		"service 10.9.8.7:22/tcp":                       "10.9.8.7:22",
		"web_application https://shop.acme.example/api": "https://shop.acme.example/api/",
		"mobile_app com.acme.app":                       "com.acme.app",
		"repository github.com/acme/app":                "github.com/acme/app",
		"api https://graph.acme.example/graphql":        "https://graph.acme.example/graphql/",
	}
	for k, key := range want {
		if got[k] != key {
			t.Errorf("missing %q (key %q); got %v", k, key, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected assets: %v", got)
	}
	for k := range got {
		if strings.Contains(k, "admin.acme.example") || strings.Contains(k, "0xabc") || strings.Contains(k, "acme-model") ||
			strings.Contains(k, "acme.exe") || strings.Contains(k, "guess") {
			t.Errorf("%q must not become an asset", k)
		}
	}
}

func TestTargetAssets_PortRangesMakeNoServices(t *testing.T) {
	it := Classify("api.acme.example")
	it.InScope = true
	it = LimitItem(it, []string{"8000-8100", "443"}, "tcp")
	var services []string
	for _, a := range TargetAssets([]Item{it}) {
		if a.Type == TargetAssetService {
			services = append(services, a.Value)
		}
	}
	if strings.Join(services, ",") != "api.acme.example:443/tcp" {
		t.Fatalf("services = %v", services)
	}
}

func withType(it Item, in bool, confidence string) Item {
	it.InScope, it.Confidence = in, confidence
	return it
}
