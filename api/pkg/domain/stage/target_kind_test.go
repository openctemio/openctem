package stage

import "testing"

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
		"github.com/acme/app":            KindOther,
		"registry.example.com/app:1.2.3": KindOther,
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
	}
	// Stages that take no network kind are not gated by kind.
	for _, key := range []Key{SecretsCode, SASTCode, ContainerImage} {
		st, _ := Lookup(key)
		for _, k := range []TargetKind{KindName, KindAddr, KindRange, KindURL, KindService} {
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
	typed := func(s string) bool { return s == "mystery" || s == "203.0.113.0/24" }
	kept, refused := st.FilterKinds([]string{"mystery", "plain", "203.0.113.0/24", "https://app.example.com"}, typed)
	if len(kept) != 2 || kept[0] != "mystery" || kept[1] != "https://app.example.com" {
		t.Fatalf("kept = %v", kept)
	}
	if refused[KindName] != 1 || refused[KindRange] != 1 {
		t.Fatalf("refused = %v", refused)
	}
}
