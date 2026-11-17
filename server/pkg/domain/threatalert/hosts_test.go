package threatalert

import (
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func hostView(tenant shared.ID, name string, kind MatchKind) AssetView {
	return AssetView{TenantID: tenant, Asset: Asset{AssetID: shared.NewID(), Name: name, Type: "service", Kind: kind}}
}

// rowsOf flattens the groups to "kind host [labels]" lines.
func rowsOf(groups []HostGroup) []string {
	var out []string
	for _, g := range groups {
		for _, h := range g.Hosts {
			line := string(g.Kind) + " " + h.Host + " ["
			for i, s := range h.Services {
				if i > 0 {
					line += " "
				}
				line += s.Label
			}
			out = append(out, line+"]")
		}
	}
	return out
}

func TestGroupByHost(t *testing.T) {
	tn := shared.NewID()
	cases := []struct {
		name  string
		names []string
		want  []string
	}{
		{"http and https of one host are one row",
			[]string{"http://192.0.2.20", "https://192.0.2.20", "https://example.com.vn"},
			[]string{"confirmed 192.0.2.20 [http https]", "confirmed example.com.vn [https]"}},
		{"an explicit port stays in the service label, a default port does not",
			[]string{"https://example.com:8443", "https://example.com:443", "http://example.com:80", "http://example.com:8080"},
			[]string{"confirmed example.com [https:8443 https http http:8080]"}},
		{"scheme and host compare case-insensitively",
			[]string{"HTTPS://Example.COM", "http://example.com"},
			[]string{"confirmed example.com [https http]"}},
		{"a trailing slash is ignored",
			[]string{"https://example.com/", "http://example.com"},
			[]string{"confirmed example.com [https http]"}},
		{"an IPv6 literal keeps its brackets and loses the port",
			[]string{"http://[2001:db8::1]", "https://[2001:DB8::1]:8443/"},
			[]string{"confirmed [2001:db8::1] [http https:8443]"}},
		{"a path is part of the service, not of the host",
			[]string{"https://example.com/app/", "https://example.com"},
			[]string{"confirmed example.com [https/app https]"}},
		{"an asset not named by a URL is a row of its own",
			[]string{"web-01", "example.com", "https://example.com", "web-01"},
			[]string{"confirmed web-01 []", "confirmed example.com []", "confirmed example.com [https]", "confirmed web-01 []"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := make([]AssetView, 0, len(c.names))
			for _, n := range c.names {
				in = append(in, hostView(tn, n, MatchConfirmed))
			}
			if got := rowsOf(GroupByHost(in)); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %q\nwant %q", got, c.want)
			}
		})
	}
}

func TestGroupByHost_TiersStayApartAndOrdered(t *testing.T) {
	tn := shared.NewID()
	got := rowsOf(GroupByHost([]AssetView{
		hostView(tn, "http://example.com", MatchPossible),
		hostView(tn, "https://example.com", MatchLikely),
		hostView(tn, "https://example.com:8443", MatchConfirmed),
		hostView(tn, "http://example.com:8080", MatchLikely),
	}))
	want := []string{"confirmed example.com [https:8443]", "likely example.com [https http:8080]", "possible example.com [http]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestGroupByHost_TwoTenantsNeverShareARow(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	groups := GroupByHost([]AssetView{
		hostView(a, "http://example.com", MatchConfirmed),
		hostView(b, "https://example.com", MatchConfirmed),
	})
	if len(groups) != 1 || len(groups[0].Hosts) != 2 {
		t.Fatalf("want two rows in one group, got %q", rowsOf(groups))
	}
	for _, h := range groups[0].Hosts {
		if len(h.Services) != 1 {
			t.Fatalf("a row mixes tenants: %q", rowsOf(groups))
		}
	}
}

func TestGroupByHost_RowValues(t *testing.T) {
	tn := shared.NewID()
	f1, f2, task := shared.NewID(), shared.NewID(), shared.NewID()
	plain := hostView(tn, "http://example.com", MatchConfirmed)
	plain.Criticality, plain.Product, plain.Version, plain.FindingID = "low", "nginx", "1.24", &f1
	tls := hostView(tn, "https://example.com", MatchConfirmed)
	tls.InternetFacing, tls.Criticality, tls.Product, tls.Version = true, "critical", "nginx", "1.25"
	tls.FindingID, tls.TaskID, tls.FindingStatus = &f2, &task, "confirmed"
	admin := hostView(tn, "https://example.com:8443", MatchConfirmed)
	admin.Criticality, admin.Product = "medium", "Tomcat"

	groups := GroupByHost([]AssetView{plain, tls, admin})
	if len(groups) != 1 || len(groups[0].Hosts) != 1 {
		t.Fatalf("want one row, got %q", rowsOf(groups))
	}
	h := groups[0].Hosts[0]
	if h.AssetID != nil {
		t.Fatalf("a row of URL-named services names no asset of its own")
	}
	if !h.InternetFacing || h.Criticality != "critical" {
		t.Fatalf("internet-facing if any is, highest criticality: got %v %q", h.InternetFacing, h.Criticality)
	}
	if !reflect.DeepEqual(h.Products, []string{"nginx", "Tomcat"}) || !reflect.DeepEqual(h.Versions, []string{"1.24", "1.25"}) {
		t.Fatalf("distinct products and versions: got %q %q", h.Products, h.Versions)
	}
	// Every service keeps its own asset, finding and task.
	if len(h.Services) != 3 || h.Services[0].FindingID != &f1 || h.Services[1].FindingID != &f2 ||
		h.Services[1].TaskID != &task || h.Services[1].FindingStatus != "confirmed" || h.Services[2].FindingID != nil {
		t.Fatalf("a finding or task link was lost: %+v", h.Services)
	}
	if h.Services[0].AssetID != plain.AssetID || h.Services[2].AssetID != admin.AssetID {
		t.Fatalf("a service lost its asset")
	}
}

func TestGroupByHost_NonURLRowLinksItsAsset(t *testing.T) {
	v := hostView(shared.NewID(), "web-01", MatchPossible)
	v.Type, v.Product = "host", "widget"
	groups := GroupByHost([]AssetView{v})
	h := groups[0].Hosts[0]
	if h.AssetID == nil || *h.AssetID != v.AssetID || h.Host != "web-01" || len(h.Services) != 1 || h.Services[0].Label != "" {
		t.Fatalf("got %+v", h)
	}
	if GroupByHost(nil) == nil || len(GroupByHost(nil)) != 0 {
		t.Fatalf("no assets: an empty, non-nil list")
	}
}

func TestServiceOfName(t *testing.T) {
	for name, want := range map[string][2]string{
		"https://example.com":           {"example.com", "https"},
		"https://example.com.":          {"example.com", "https"},
		"https://example.com/a/b/?x=1":  {"example.com", "https/a/b?x=1"},
		"tcp://192.0.2.7:5432":          {"192.0.2.7", "tcp:5432"},
		"https://user@example.com:8443": {"example.com", "https:8443"},
		"example.com":                   {"", ""},
		"example.com:8443":              {"", ""},
		"https://":                      {"", ""},
		"http://exa mple.com":           {"", ""},
		"":                              {"", ""},
	} {
		host, label, ok := serviceOfName(name)
		if host != want[0] || label != want[1] || ok != (want[0] != "") {
			t.Errorf("%q: got %q %q %v, want %q", name, host, label, ok, want)
		}
	}
}

func hostAsset(name string, kind MatchKind, internet bool, criticality string) Asset {
	return Asset{AssetID: shared.NewID(), Name: name, Type: "service", Kind: kind, InternetFacing: internet, Criticality: criticality}
}

func TestCountHosts(t *testing.T) {
	cases := []struct {
		name   string
		assets []Asset
		want   HostCounts
	}{
		{"nothing", nil, HostCounts{}},
		{"two ports of one host are one confirmed host",
			[]Asset{hostAsset("http://192.0.2.20", MatchConfirmed, true, ""), hostAsset("https://192.0.2.20", MatchConfirmed, true, "")},
			HostCounts{Confirmed: 1, InternetFacing: 1}},
		{"likely is its own number, never part of confirmed",
			[]Asset{hostAsset("https://example.com", MatchLikely, false, ""), hostAsset("https://example.org", MatchConfirmed, false, "")},
			HostCounts{Confirmed: 1, Likely: 1}},
		{"many ports, default ports, case, trailing slash and dot: still one host",
			[]Asset{hostAsset("http://example.com:8080", MatchPossible, false, ""), hostAsset("HTTPS://Example.COM:443/", MatchPossible, false, ""),
				hostAsset("https://example.com./app", MatchPossible, false, ""), hostAsset("http://example.com:80", MatchPossible, false, "")},
			HostCounts{Possible: 1}},
		{"a host in two tiers is a row in each, and one internet-facing, one critical host",
			[]Asset{hostAsset("https://example.com", MatchConfirmed, true, "critical"), hostAsset("http://example.com", MatchPossible, true, "critical")},
			HostCounts{Confirmed: 1, Possible: 1, InternetFacing: 1, Critical: 1}},
		{"an asset not named by a URL is a host of its own, even with the name of another",
			[]Asset{hostAsset("web-01", MatchConfirmed, false, "Critical"), hostAsset("web-01", MatchConfirmed, false, ""),
				hostAsset("example.com", MatchConfirmed, false, ""), hostAsset("https://example.com", MatchConfirmed, false, "")},
			HostCounts{Confirmed: 4, Critical: 1}},
		{"IPv6 literals fold like names",
			[]Asset{hostAsset("http://[2001:db8::1]", MatchConfirmed, false, ""), hostAsset("https://[2001:DB8::1]:8443/", MatchConfirmed, true, "")},
			HostCounts{Confirmed: 1, InternetFacing: 1}},
	}
	for _, c := range cases {
		if got := CountHosts(c.assets); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

// The counts are the rows GroupByHost lists: the number in a header is the
// number of rows under it, for any mix of names and tiers.
func TestCountHostsEqualsGroupRows(t *testing.T) {
	names := []string{"http://192.0.2.20", "https://192.0.2.20", "https://192.0.2.20:8443", "HTTP://EXAMPLE.COM", "https://example.com/",
		"https://example.com./x?y=1", "example.com", "web-01", "http://[2001:db8::1]", "https://[2001:db8::1]:9443", "ftp://files.example.org",
		"https://user@files.example.org", "//no-scheme.example.com", "https://", "http://192.0.2.21:80", " https://192.0.2.21 "}
	kinds := []MatchKind{MatchConfirmed, MatchLikely, MatchPossible}
	tn := shared.NewID()
	// Every subset pattern of a deterministic walk: asset i takes name
	// i*step mod len and tier (i*step+round) mod 3.
	for round := 0; round < 60; round++ {
		var assets []Asset
		var views []AssetView
		for i := 0; i < 3+round%14; i++ {
			a := hostAsset(names[(i*(round%5+1)+round)%len(names)], kinds[(i*(round%3+1)+round)%3], (i+round)%2 == 0, "")
			assets = append(assets, a)
			views = append(views, AssetView{Asset: a, TenantID: tn})
		}
		got := CountHosts(assets)
		rows := map[MatchKind]int{}
		for _, g := range GroupByHost(views) {
			rows[g.Kind] = len(g.Hosts)
		}
		want := HostCounts{Confirmed: rows[MatchConfirmed], Likely: rows[MatchLikely], Possible: rows[MatchPossible], InternetFacing: got.InternetFacing}
		if got != want {
			t.Fatalf("round %d: counts %+v, group rows %+v", round, got, rows)
		}
	}
}

// The key stored with an alert asset is the key the rows are grouped by.
func TestHostKey(t *testing.T) {
	id := shared.NewID()
	cases := map[string]string{
		"http://192.0.2.20":           "h:192.0.2.20",
		"HTTPS://Example.COM.:443/a/": "h:example.com",
		"https://[2001:DB8::1]:8443":  "h:[2001:db8::1]",
		"example.com":                 "a:" + id.String(),
		"web-01":                      "a:" + id.String(),
		"https://":                    "a:" + id.String(),
		"":                            "a:" + id.String(),
	}
	for name, want := range cases {
		if got := HostKey(Asset{AssetID: id, Name: name}); got != want {
			t.Errorf("HostKey(%q) = %q, want %q", name, got, want)
		}
	}
	long := HostKey(Asset{AssetID: id, Name: "https://" + strings.Repeat("a", 400) + ".example.com"})
	if len(long) != maxHostKey {
		t.Fatalf("a long host key has %d bytes, want it cut at %d", len(long), maxHostKey)
	}
}

func TestHostsGrew(t *testing.T) {
	known := []Asset{hostAsset("https://192.0.2.20", MatchLikely, false, ""), hostAsset("web-01", MatchConfirmed, false, "")}
	with := func(extra ...Asset) []Asset { return append(append([]Asset{}, known...), extra...) }
	cases := []struct {
		name   string
		before []Asset
		now    []Asset
		want   bool
	}{
		{"nothing changed", known, known, false},
		{"a second port of a known host", known, with(hostAsset("http://192.0.2.20", MatchLikely, false, "")), false},
		{"a second port of a known host, in a weaker tier", known, with(hostAsset("http://192.0.2.20:8080", MatchPossible, false, "")), false},
		{"a new host", known, with(hostAsset("https://192.0.2.21", MatchPossible, false, "")), true},
		{"a known host moves from likely to confirmed",
			known, []Asset{hostAsset("https://192.0.2.20", MatchConfirmed, false, ""), known[1]}, true},
		{"a second port of a known host is confirmed while the first is likely",
			known, with(hostAsset("http://192.0.2.20", MatchConfirmed, false, "")), true},
		{"a host left", known, known[:1], false},
		{"the first plan of an alert", nil, known, true},
		{"a host moves to a weaker tier", known, []Asset{hostAsset("https://192.0.2.20", MatchPossible, false, ""), known[1]}, false},
	}
	for _, c := range cases {
		if got := HostsGrew(c.before, c.now); got != c.want {
			t.Errorf("%s: grew = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestHostCountsSentence(t *testing.T) {
	cases := []struct {
		c    HostCounts
		want string
	}{
		{HostCounts{Confirmed: 3, Likely: 1}, "3 hosts confirmed, 1 likely"},
		{HostCounts{Confirmed: 1, Possible: 2, InternetFacing: 1}, "1 host confirmed, 2 possibly affected, 1 internet-facing"},
		{HostCounts{Likely: 2, Possible: 1}, "2 hosts likely, 1 possibly affected"},
		{HostCounts{Possible: 1}, "1 host possibly affected"},
		{HostCounts{Confirmed: 2, Likely: 1, Possible: 4, InternetFacing: 2}, "2 hosts confirmed, 1 likely, 4 possibly affected, 2 internet-facing"},
		{HostCounts{}, "no hosts affected"},
	}
	for _, c := range cases {
		got := c.c.Sentence()
		if got != c.want {
			t.Errorf("%+v: %q, want %q", c.c, got, c.want)
		}
		if strings.Contains(got, "asset") {
			t.Errorf("%q names assets for a host count", got)
		}
	}
}

func TestHostNames(t *testing.T) {
	assets := []Asset{hostAsset("http://192.0.2.20", MatchConfirmed, false, ""), hostAsset("https://192.0.2.20", MatchConfirmed, false, ""),
		hostAsset("web-01", MatchConfirmed, false, ""), hostAsset("https://example.com/app", MatchLikely, false, ""),
		hostAsset("https://<b>.example.org", MatchLikely, false, "")}
	got := HostNames(assets, 3)
	want := []string{"192.0.2.20", "web-01", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HostNames = %v, want %v", got, want)
	}
}
