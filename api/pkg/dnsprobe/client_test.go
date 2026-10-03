package dnsprobe_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openctemio/openctem/api/pkg/dnsprobe"
	"github.com/openctemio/openctem/api/pkg/dnsprobe/dnstest"
)

func client(t *testing.T, zone map[string]dnstest.Entry) (*dnsprobe.Client, *dnstest.Server) {
	t.Helper()
	srv, err := dnstest.Start(zone)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	c, err := dnsprobe.New(dnsprobe.Config{Server: srv.Addr, QPS: 1000, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

func TestQuery_DanglingCNAMEKeepsTheChain(t *testing.T) {
	c, _ := client(t, map[string]dnstest.Entry{
		"shop.example.com": {CNAME: "gone.azurewebsites.net"},
		"www.example.com":  {CNAME: "live.example.net"},
		"live.example.net": {A: []string{"192.0.2.10"}},
	})
	ctx := context.Background()

	a, err := c.Query(ctx, "shop.example.com", dnsprobe.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if a.RCode != dnsprobe.RCodeNXDomain || len(a.Records) != 1 || a.Records[0].Value != "gone.azurewebsites.net" {
		t.Fatalf("dangling answer = %+v", a)
	}
	a, err = c.Query(ctx, "WWW.Example.com.", dnsprobe.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if a.RCode != dnsprobe.RCodeSuccess || !a.Has(dnsprobe.TypeA) || !a.Has(dnsprobe.TypeCNAME) {
		t.Fatalf("live answer = %+v", a)
	}
	a, _ = c.Query(ctx, "nothing.example.com", dnsprobe.TypeA)
	if a.RCode != dnsprobe.RCodeNXDomain || len(a.Records) != 0 {
		t.Fatalf("nxdomain = %+v", a)
	}
}

func TestQuery_TXTAndTCPFallback(t *testing.T) {
	c, srv := client(t, map[string]dnstest.Entry{
		"example.com":        {TXT: [][]string{{"v=spf1 -all"}}, Truncate: true},
		"_dmarc.example.com": {TXT: [][]string{{"v=DMARC1; ", "p=reject"}}},
		"broken.example.com": {RCode: dnsmessage.RCodeServerFailure},
	})
	a, err := c.Query(context.Background(), "example.com", dnsprobe.TypeTXT)
	if err != nil || len(a.Records) != 1 || a.Records[0].TXT[0] != "v=spf1 -all" {
		t.Fatalf("truncated → tcp: %+v %v (queries %v)", a, err, srv.Queries())
	}
	a, _ = c.Query(context.Background(), "_dmarc.example.com", dnsprobe.TypeTXT)
	if len(a.Records[0].TXT) != 2 {
		t.Fatalf("multi-string TXT = %+v", a)
	}
	a, _ = c.Query(context.Background(), "broken.example.com", dnsprobe.TypeA)
	if a.RCode != dnsprobe.RCodeServFail {
		t.Fatalf("servfail = %+v", a)
	}
}

func TestQuery_TimeoutAndBadName(t *testing.T) {
	// A UDP port nobody answers on: the query times out, it does not hang.
	c, err := dnsprobe.New(dnsprobe.Config{Server: "127.0.0.1:9", QPS: 1000, Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := c.Query(context.Background(), "example.com", dnsprobe.TypeA); err == nil {
		t.Fatal("no error from a dead resolver")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("query not bounded by the timeout")
	}
	if _, err := c.Query(context.Background(), "bad..name", dnsprobe.TypeA); err == nil {
		t.Fatal("invalid name accepted")
	}
}

func TestQuery_RateLimited(t *testing.T) {
	srv, err := dnstest.Start(map[string]dnstest.Entry{"example.com": {A: []string{"192.0.2.1"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	c, _ := dnsprobe.New(dnsprobe.Config{Server: srv.Addr, QPS: 10})
	start := time.Now()
	for i := 0; i < 25; i++ {
		if _, err := c.Query(context.Background(), "example.com", dnsprobe.TypeA); err != nil {
			t.Fatal(err)
		}
	}
	// burst 10, then 10/s: 25 queries take at least ~1.4 s.
	if el := time.Since(start); el < 1200*time.Millisecond {
		t.Fatalf("25 queries at 10 qps took %s", el)
	}
}

func TestNew_SystemResolver(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	_ = os.WriteFile(p, []byte("# c\nsearch lan\nnameserver 192.0.2.53\n"), 0o600)
	if s, err := dnsprobe.SystemResolverForTest(p); err != nil || s != "192.0.2.53:53" {
		t.Fatalf("got %q %v", s, err)
	}
	if c, err := dnsprobe.New(dnsprobe.Config{Server: "192.0.2.1"}); err != nil || c.Server() != "192.0.2.1:53" {
		t.Fatalf("port default: %v %v", c, err)
	}
}
