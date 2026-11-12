package stage

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

func TestClassifyTarget(t *testing.T) {
	cases := map[string]TargetKind{
		"example.com":                    KindName,
		"*.example.com":                  KindName,
		"app-1.example.com":              KindName,
		"intranet":                       KindName,
		"203.0.113.9":                    KindAddr,
		"203.0.113.9/32":                 KindAddr,
		"2001:db8::1":                    KindAddr,
		"2001:db8::1/128":                KindAddr,
		"[2001:db8::1]":                  KindAddr,
		"203.0.113.0/24":                 KindRange,
		"203.0.113.9/30":                 KindRange,
		"2001:db8::/120":                 KindRange,
		"198.51.100.1-198.51.100.9":      KindRange,
		"198.51.100.1-198.51.100.1":      KindAddr,
		"https://app.example.com/login":  KindURL,
		"http://203.0.113.9:8080":        KindURL,
		"app.example.com:8443":           KindService,
		"203.0.113.9:443/tcp":            KindService,
		"[2001:db8::1]:443":              KindService,
		"github.com/acme/app":            KindPath,
		"gitlab.com/acme/sub/app":        KindPath,
		"git@github.com:acme/app":        KindPath,
		"example.com/login":              KindPath,
		"registry.example.com/app:1.2.3": KindPath,
		"intranet/app":                   KindOther,
		"example.com/":                   KindOther,
		"":                               KindOther,
	}
	for in, want := range cases {
		if got := ClassifyTarget(in); got != want {
			t.Errorf("ClassifyTarget(%q) = %s, want %s", in, got, want)
		}
	}
}

// The matrix of RFC-088 §5: a range reaches only stages that take networks
// and the port scan; never HTTP probing, crawling or templates.
func TestAcceptsKind(t *testing.T) {
	type row struct{ name, addr, rng, url, svc bool }
	want := map[Key]row{
		DiscoverSubdomains: {true, false, false, false, false},
		ResolveDNS:         {true, false, false, false, false},
		LookupRDAP:         {true, false, false, false, false},
		LookupASN:          {false, true, true, false, false},
		ScanPorts:          {true, true, true, false, true},
		ProbeHTTP:          {true, true, false, true, true},
		CrawlWeb:           {false, false, false, true, false},
		VulnTemplates:      {true, true, false, true, true},
		DASTWeb:            {false, false, false, true, false},
		NetworkVAConnector: {true, true, true, false, false},
	}
	for key, w := range want {
		st, ok := Lookup(key)
		if !ok {
			t.Fatalf("no stage %s", key)
		}
		got := row{st.AcceptsKind(KindName), st.AcceptsKind(KindAddr), st.AcceptsKind(KindRange), st.AcceptsKind(KindURL), st.AcceptsKind(KindService)}
		if got != w {
			t.Errorf("%s accepts %+v, want %+v", key, got, w)
		}
		if !st.AcceptsKind(KindOther) {
			t.Errorf("%s refuses an unclassified target", key)
		}
		if st.AcceptsKind(KindPath) {
			t.Errorf("%s takes a repository or path target", key)
		}
	}
	// Stages that take no network kind are not gated by kind.
	for _, key := range []Key{SecretsCode, SASTCode, SCADeps, IaCMisconfig, ContainerImage} {
		st, _ := Lookup(key)
		for _, k := range []TargetKind{KindName, KindAddr, KindRange, KindURL, KindService, KindPath} {
			if !st.AcceptsKind(k) {
				t.Errorf("%s refuses %s", key, k)
			}
		}
	}
}

func TestFilterKinds(t *testing.T) {
	st, _ := Lookup(VulnTemplates)
	kept, refused := st.FilterKinds([]string{"203.0.113.0/24", "app.example.com", "2001:db8::/120", "203.0.113.9"}, nil)
	if len(kept) != 2 || kept[0] != "app.example.com" || kept[1] != "203.0.113.9" {
		t.Fatalf("kept = %v", kept)
	}
	if refused[KindRange] != 2 {
		t.Fatalf("refused = %v", refused)
	}
	if msg := st.DescribeRefusedKinds(refused); msg != "2 range target(s): Vulnerability templates does not take them (a network range goes to port scans and network lookups only)" {
		t.Fatalf("reason = %q", msg)
	}
}

// A target with a stored type is left to the type gate, except a range.
func TestFilterKinds_TypedTargets(t *testing.T) {
	st, _ := Lookup(DASTWeb)
	typed := func(s string) (asset.TypeRef, bool) {
		return asset.TypeRef{Type: asset.AssetTypeNetwork}, s == "mystery" || s == "203.0.113.0/24"
	}
	kept, refused := st.FilterKinds([]string{"mystery", "plain", "203.0.113.0/24", "https://app.example.com"}, typed)
	if len(kept) != 2 || kept[0] != "mystery" || kept[1] != "https://app.example.com" {
		t.Fatalf("kept = %v", kept)
	}
	if refused[KindName] != 1 || refused[KindRange] != 1 {
		t.Fatalf("refused = %v", refused)
	}
}

// Every network stage refuses a repository: one in the path form whatever
// its stored type, and a repository asset whatever its name.
func TestFilterKinds_Repositories(t *testing.T) {
	repoNamed := map[string]bool{"acme-app": true, "github.com/acme/app": true}
	typeOf := func(s string) (asset.TypeRef, bool) {
		if repoNamed[s] {
			return asset.TypeRef{Type: asset.AssetTypeRepository}, true
		}
		if s == "example.com/login" {
			return asset.TypeRef{Type: asset.AssetTypeService, SubType: "discovered_url"}, true
		}
		return asset.TypeRef{}, false
	}
	in := []string{"github.com/acme/app", "acme-app", "git@gitlab.com:acme/app", "example.com/login", "app.example.com", "https://app.example.com"}
	for _, key := range []Key{DiscoverSubdomains, ResolveDNS, ScanPorts, ProbeHTTP, CrawlWeb, VulnTemplates, DASTWeb, NetworkVAConnector} {
		st, _ := Lookup(key)
		kept, refused := st.FilterKinds(in, typeOf)
		for _, k := range kept {
			if repoNamed[k] || ClassifyTarget(k) == KindPath {
				t.Errorf("%s kept %q", key, k)
			}
		}
		if refused[KindPath] != 4 {
			t.Errorf("%s refused %v, want 4 path targets", key, refused)
		}
		if msg := st.DescribeRefusedKinds(map[TargetKind]int{KindPath: 1}); msg != "1 path target(s): "+st.Name+" does not take them ("+ReasonPathTarget+")" {
			t.Errorf("%s reason = %q", key, msg)
		}
	}
	for _, key := range []Key{SecretsCode, SASTCode, SCADeps, IaCMisconfig} {
		st, _ := Lookup(key)
		if kept, refused := st.FilterKinds(in, typeOf); len(kept) != len(in) || len(refused) != 0 {
			t.Errorf("%s kept %v refused %v; a code stage takes repositories", key, kept, refused)
		}
	}
}

func TestTakesPathTargets(t *testing.T) {
	cases := []struct {
		tool      string
		caps      []string
		ok, known bool
	}{
		{"nuclei", nil, false, true},
		{"httpx", nil, false, true},
		{"naabu", nil, false, true},
		{"subfinder", nil, false, true},
		{"semgrep", nil, true, true},
		{"gitleaks", nil, true, true},
		{"", []string{"probe.http@1"}, false, true},
		{"", []string{"scan.ports"}, false, true},
		{"", []string{"sast.code@1"}, true, true},
		{"tenant-tool", []string{"secrets.code"}, true, true},
		{"tenant-tool", nil, false, false},
		{"", nil, false, false},
	}
	for _, c := range cases {
		ok, known := TakesPathTargets(c.tool, c.caps)
		if ok != c.ok || known != c.known {
			t.Errorf("TakesPathTargets(%q, %v) = %v, %v; want %v, %v", c.tool, c.caps, ok, known, c.ok, c.known)
		}
	}
}
