package threatalert

import (
	"reflect"
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
