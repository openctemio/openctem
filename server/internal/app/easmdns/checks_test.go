package easmdns

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openctemio/openctem/api/pkg/dnsprobe"
	"github.com/openctemio/openctem/api/pkg/dnsprobe/dnstest"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
)

// fakeDNS starts the fake resolver with the given zone. Every registrable
// provider/root domain the tests rely on "existing" gets NS records.
func fakeDNS(t *testing.T, zone map[string]dnstest.Entry) Querier {
	t.Helper()
	base := map[string]dnstest.Entry{
		"azurewebsites.net":      {NS: []string{"ns1.azure-dns.com"}},
		"elasticbeanstalk.com":   {NS: []string{"ns1.aws.example"}},
		"github.io":              {NS: []string{"ns1.github.example"}},
		"example.com":            {NS: []string{"ns1.example.com"}},
		"example.net":            {NS: []string{"ns1.example.net"}},
		"ns1.example.com":        {A: []string{"192.0.2.53"}},
		"cloudfront.example.net": {A: []string{"192.0.2.80"}},
	}
	for k, v := range zone {
		base[k] = v
	}
	srv, err := dnstest.Start(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	c, err := dnsprobe.New(dnsprobe.Config{Server: srv.Addr, QPS: 1000, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFingerprints_Load(t *testing.T) {
	ps, sfx, err := loadProviders()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) < 20 || len(sfx) != len(ps) {
		t.Fatalf("loaded %d providers", len(ps))
	}
	p, ok := providerFor("Gone.AzureWebsites.net.")
	if !ok || p.Service != "Microsoft Azure" || !p.Takeoverable() || !p.NXDomain {
		t.Fatalf("azure = %+v %v", p, ok)
	}
	if _, ok := providerFor("notazurewebsites.net"); ok {
		t.Fatal("suffix match must be on a label boundary")
	}
	for s := range ps {
		if strings.ContainsAny(s, "/:") || isIPLiteral(s) {
			t.Fatalf("non-DNS suffix loaded: %q", s)
		}
	}
}

func TestCheckDangling(t *testing.T) {
	q := fakeDNS(t, map[string]dnstest.Entry{
		// CNAME to a takeoverable provider whose name is gone.
		"shop.acme.example.com": {CNAME: "acme-shop.azurewebsites.net"},
		// CNAME to a registrable domain nobody owns any more.
		"old.acme.example.com": {CNAME: "acme-campaign-2019.com"},
		// CNAME to an unknown provider's missing name.
		"cdn.acme.example.com": {CNAME: "missing.cloudfront.example.net"},
		// Healthy CNAME.
		"www.acme.example.com": {CNAME: "cloudfront.example.net"},
		// Plain A record.
		"api.acme.example.com": {A: []string{"192.0.2.7"}},
		// Delegation to name servers on an unregistered domain.
		"lab.acme.example.com": {NS: []string{"ns1.acme-lab-dns.com", "ns2.acme-lab-dns.com"}},
		// Delegation with one missing server out of two.
		"dev.acme.example.com": {NS: []string{"ns1.example.com", "gone.example.com"}},
		// Healthy delegation.
		"ops.acme.example.com": {NS: []string{"ns1.example.com"}},
		// Resolver failure.
		"flaky.acme.example.com": {RCode: dnsmessage.RCodeServerFailure},
	})
	ctx := context.Background()
	cases := []struct {
		name    string
		outcome string
		sev     exposuredom.Severity
		unreg   bool
	}{
		{"shop.acme.example.com", OutcomeDanglingCNAME, exposuredom.SeverityMedium, false},
		{"old.acme.example.com", OutcomeDanglingCNAME, exposuredom.SeverityHigh, true},
		{"cdn.acme.example.com", OutcomeDanglingCNAME, exposuredom.SeverityLow, false},
		{"www.acme.example.com", OutcomeOK, "", false},
		{"api.acme.example.com", OutcomeOK, "", false},
		{"lab.acme.example.com", OutcomeDanglingNS, exposuredom.SeverityHigh, true},
		{"dev.acme.example.com", OutcomeDanglingNS, exposuredom.SeverityLow, false},
		{"ops.acme.example.com", OutcomeOK, "", false},
		{"flaky.acme.example.com", OutcomeUnknown, "", false},
		{"nothing.acme.example.com", OutcomeOK, "", false}, // NXDOMAIN without CNAME: no record, nothing dangling
	}
	for _, tc := range cases {
		d, err := checkDangling(ctx, q, tc.name)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if d.Outcome != tc.outcome || d.Severity != tc.sev || d.Unregistered != tc.unreg {
			t.Errorf("%s = %+v, want %s/%s/unregistered=%v", tc.name, d, tc.outcome, tc.sev, tc.unreg)
		}
	}
	d, _ := checkDangling(ctx, q, "shop.acme.example.com")
	if d.Provider == nil || d.Provider.Service != "Microsoft Azure" || d.Target != "acme-shop.azurewebsites.net" {
		t.Errorf("provider/target = %+v", d)
	}
}

func TestRegistrableDomain(t *testing.T) {
	for in, want := range map[string]string{
		"gone.example.co.uk":          "example.co.uk",
		"acme-shop.azurewebsites.net": "azurewebsites.net", // private PSL suffix ignored
		"a.b.example.com.":            "example.com",
		"com":                         "",
		"example.com":                 "example.com",
	} {
		if got := registrableDomain(in); got != want {
			t.Errorf("registrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func issues(p EmailPosture) map[string]exposuredom.Severity {
	m := map[string]exposuredom.Severity{}
	for _, i := range p.Issues {
		m[i.Check] = i.Severity
	}
	return m
}

// Golden fixtures: correct domains are not flagged; each gap is.
func TestCheckEmail(t *testing.T) {
	spfInc := func(n int) [][]string {
		var parts []string
		for i := 0; i < n; i++ {
			parts = append(parts, "include:_s"+string(rune('a'+i))+".mail.example.net")
		}
		// A real record longer than 255 bytes is split into several strings,
		// which receivers concatenate without a separator (RFC 7208 §3.3).
		rec := "v=spf1 " + strings.Join(parts, " ") + " -all"
		var chunks []string
		for len(rec) > 200 {
			chunks, rec = append(chunks, rec[:200]), rec[200:]
		}
		return [][]string{append(chunks, rec)}
	}
	zone := map[string]dnstest.Entry{
		// Fully configured mail domain.
		"good.com":            {MX: []string{"mx.good.com"}, TXT: [][]string{{"v=spf1 mx -all"}, {"google-site-verification=x"}}},
		"_dmarc.good.com":     {TXT: [][]string{{"v=DMARC1; p=reject; ", "rua=mailto:d@good.com"}}},
		"_mta-sts.good.com":   {TXT: [][]string{{"v=STSv1; id=1"}}},
		"_smtp._tls.good.com": {TXT: [][]string{{"v=TLSRPTv1; rua=mailto:t@good.com"}}},
		// Parked domain done right: null MX, -all, reject.
		"parked.com":        {MX: []string{"."}, TXT: [][]string{{"v=spf1 -all"}}},
		"_dmarc.parked.com": {TXT: [][]string{{"v=DMARC1; p=reject; rua=mailto:d@parked.com"}}},
		// Mail domain with nothing.
		"bare.com": {MX: []string{"mx.bare.com"}},
		// Weak policies.
		"weak.com":        {MX: []string{"mx.weak.com"}, TXT: [][]string{{"v=spf1 a ?all"}}},
		"_dmarc.weak.com": {TXT: [][]string{{"v=DMARC1; p=none"}}},
		"open.com":        {MX: []string{"mx.open.com"}, TXT: [][]string{{"v=spf1 +all"}}},
		"_dmarc.open.com": {TXT: [][]string{{"v=DMARC1; p=quarantine; t=y; sp=none; rua=mailto:x@open.com"}}},
		"two.com":         {MX: []string{"mx.two.com"}, TXT: [][]string{{"v=spf1 -all"}, {"v=spf1 mx -all"}}},
		"_dmarc.two.com":  {TXT: [][]string{{"v=DMARC1; p=reject; pct=50; rua=mailto:x@two.com"}}},
		// 11 lookups through includes.
		"many.com":        {MX: []string{"mx.many.com"}, TXT: spfInc(11)},
		"_dmarc.many.com": {TXT: [][]string{{"v=DMARC1; p=reject; rua=mailto:x@many.com"}}},
		// Include loop: counted once, no hang.
		"loop.com":        {TXT: [][]string{{"v=spf1 include:loop.com -all"}}},
		"_dmarc.loop.com": {TXT: [][]string{{"v=DMARC1; p=reject; rua=mailto:x@loop.com"}}},
		"broken.com":      {RCode: dnsmessage.RCodeServerFailure},
	}
	for i := 0; i < 11; i++ {
		zone["_s"+string(rune('a'+i))+".mail.example.net"] = dnstest.Entry{TXT: [][]string{{"v=spf1 ip4:192.0.2.0/24 -all"}}}
	}
	q := fakeDNS(t, zone)
	ctx := context.Background()

	for _, d := range []string{"good.com", "parked.com"} {
		p, err := checkEmail(ctx, q, d)
		if err != nil {
			t.Fatal(err)
		}
		if p.Severity() != "" {
			t.Errorf("%s flagged: %+v", d, p.Issues)
		}
	}
	p, _ := checkEmail(ctx, q, "parked.com")
	if p.ReceivesMail {
		t.Error("null MX counted as receiving mail")
	}

	want := map[string]map[string]exposuredom.Severity{
		"bare.com": {"spf_missing": "medium", "dmarc_missing": "medium", "mta_sts_missing": "info", "tls_rpt_missing": "info"},
		"weak.com": {"spf_neutral_all": "low", "dmarc_p_none": "low", "dmarc_no_rua": "info"},
		"open.com": {"spf_pass_all": "high", "dmarc_test_mode": "low", "dmarc_subdomains_none": "low"},
		"two.com":  {"spf_multiple": "medium", "dmarc_partial": "low"},
		"many.com": {"spf_too_many_lookups": "medium"},
	}
	for d, w := range want {
		p, err := checkEmail(ctx, q, d)
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		got := issues(p)
		for check, sev := range w {
			if got[check] != sev {
				t.Errorf("%s: %s = %q, want %q (all: %v)", d, check, got[check], sev, got)
			}
		}
	}
	if p, _ := checkEmail(ctx, q, "loop.com"); p.Severity() != "" {
		t.Errorf("include loop flagged: %+v", p.Issues)
	}
	if _, err := checkEmail(ctx, q, "broken.com"); err == nil {
		t.Error("a SERVFAIL domain must be inconclusive, not reported")
	}
}
