package proxypool

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestParseList(t *testing.T) {
	text := "# corporate exits\n\nsocks5://user:p%40ss@10.0.0.5:1080#dc1\r\nhttp://Proxy.Corp.Example.:3128\nhttps://••••@[2001:db8::1]:8443 # v6\n"
	got, err := ParseList(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries", len(got))
	}
	if e := got[0]; e.Scheme != "socks5" || e.Host != "10.0.0.5" || e.Port != 1080 || e.Label != "dc1" ||
		e.Username != "user" || e.Password != "p@ss" || e.Line != 3 {
		t.Fatalf("entry 0 %+v", e)
	}
	if e := got[1]; e.Host != "proxy.corp.example" || e.HasNewCredentials() || e.KeepCredentials {
		t.Fatalf("entry 1 %+v", e)
	}
	if e := got[2]; e.Host != "2001:db8::1" || !e.KeepCredentials || e.Label != "v6" || e.Address() != "https://[2001:db8::1]:8443" {
		t.Fatalf("entry 2 %+v", e)
	}
}

func TestParseListRefuses(t *testing.T) {
	cases := map[string]string{
		"loopback":         "http://127.0.0.1:3128",
		"v6 loopback":      "http://[::1]:3128",
		"metadata":         "http://169.254.169.254:80",
		"v6 metadata":      "http://[fd00:ec2::254]:80",
		"alibaba metadata": "http://100.100.100.200:80",
		"host agent":       "http://168.63.129.16:80",
		"metadata name":    "http://metadata.google.internal:80",
		"localhost":        "socks5://localhost:1080",
		"sub localhost":    "socks5://a.localhost:1080",
		"multicast":        "socks5://224.0.0.1:1080",
		"unspecified":      "socks5://0.0.0.0:1080",
		"broadcast":        "socks5://255.255.255.255:1080",
		"mapped loopback":  "socks5://[::ffff:127.0.0.1]:1080",
		"bad scheme":       "ftp://10.0.0.5:21",
		"tor-like scheme":  "socks4://10.0.0.5:1080",
		"no port":          "http://10.0.0.5",
		"port zero":        "http://10.0.0.5:0",
		"path":             "http://10.0.0.5:3128/x",
		"query":            "http://10.0.0.5:3128?a=b",
		"bad host":         "http://bad_host:3128",
		"spaces":           "http://10.0.0.5:3128 extra",
		"keep and new":     "http://••••@u:p@10.0.0.5:3128",
		"duplicate":        "socks5://10.0.0.5:1080\nsocks5h://10.0.0.5:1080",
		"no user":          "http://:secret@10.0.0.5:3128",
		"hash in password": "http://proxyuser:1234#rest@10.0.0.5:3128",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseList(text)
			var le *ListError
			if !errors.As(err, &le) || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v", err)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "u:p") {
				t.Fatalf("error repeats a credential: %v", err)
			}
		})
	}
}

func TestParseListPrivateAllowed(t *testing.T) {
	for _, line := range []string{"http://10.1.2.3:3128", "socks5://192.168.1.1:1080", "socks5://[fd12::1]:1080", "http://100.64.0.1:3128", "http://proxy:3128"} {
		if _, err := ParseList(line); err != nil {
			t.Errorf("%s: %v", line, err)
		}
	}
}

func TestParseListBounds(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= MaxEndpointsPerPool; i++ {
		b.WriteString("http://10.0.0.1:" + strconv.Itoa(1000+i) + "\n")
	}
	if _, err := ParseList(b.String()); err == nil {
		t.Fatal("more than the endpoint limit accepted")
	}
	if _, err := ParseList(strings.Repeat("#", MaxListBytes+1)); err == nil {
		t.Fatal("oversized list accepted")
	}
}

func TestRenderListMasksCredentials(t *testing.T) {
	eps := []*Endpoint{
		{Scheme: "socks5", Host: "10.0.0.5", Port: 1080, Label: "dc1", CredentialsEncrypted: "ciphertext"},
		{Scheme: "http", Host: "2001:db8::1", Port: 3128},
	}
	got := RenderList(eps)
	want := "socks5://••••@10.0.0.5:1080#dc1\nhttp://[2001:db8::1]:3128"
	if got != want {
		t.Fatalf("got %q", got)
	}
	parsed, err := ParseList(got)
	if err != nil || len(parsed) != 2 || !parsed[0].KeepCredentials || parsed[1].KeepCredentials {
		t.Fatalf("round trip %+v %v", parsed, err)
	}
}

func TestPoolValidation(t *testing.T) {
	tid := shared.NewID()
	if _, err := NewPool(tid, " ", "", "", true, false, nil); err == nil {
		t.Fatal("empty name accepted")
	}
	if _, err := NewPool(tid, "a", "", "random", true, false, nil); err == nil {
		t.Fatal("unknown strategy accepted")
	}
	p, err := NewPool(tid, " Corp ", "", "", true, true, nil)
	if err != nil || p.Name != "Corp" || p.Strategy != StrategySticky || p.Revision != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	s := StrategyPriority
	if err := p.Update(nil, nil, &s, nil, nil); err != nil || p.Revision != 2 {
		t.Fatalf("strategy change: rev %d %v", p.Revision, err)
	}
}

func TestHealthLifecycle(t *testing.T) {
	now := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	h := NewHealth(now)
	if !h.Eligible(now) || h.Weight(now) <= 0 || h.Weight(now) >= 0.1 {
		t.Fatalf("new endpoint weight %v", h.Weight(now))
	}
	// Probation -> healthy after enough clean traffic.
	h.Apply(Signal{OK: 25, HandshakeMsP95: 100}, now)
	if h.State != StateHealthy || h.Weight(now) < 0.5 {
		t.Fatalf("not promoted: %+v", h)
	}
	// Three failed reports in a row -> quarantined for 5 minutes.
	for i := 0; i < 3; i++ {
		h.Apply(Signal{ProxyDown: 4, LastError: "proxy_down: dial tcp socks5://u:pw@10.0.0.5:1080: refused"}, now)
	}
	if h.State != StateQuarantined || h.Eligible(now) || h.Weight(now) != 0 {
		t.Fatalf("not quarantined: %+v", h)
	}
	if strings.Contains(h.LastError, "pw") || !strings.Contains(h.LastError, "10.0.0.5:1080") {
		t.Fatalf("last error %q", h.LastError)
	}
	if got := h.QuarantinedUntil.Sub(now); got != 5*time.Minute {
		t.Fatalf("back-off %v", got)
	}
	// After the back-off it is eligible again (the re-probe), in probation weight.
	later := now.Add(6 * time.Minute)
	if !h.Eligible(later) || h.Weight(later) <= 0 {
		t.Fatal("not re-admitted after the back-off")
	}
	// The re-probe fails: back in quarantine, back-off doubled.
	h.Apply(Signal{ProxyDown: 1}, later)
	if h.State != StateQuarantined || h.QuarantinedUntil.Sub(later) != 10*time.Minute {
		t.Fatalf("re-probe failure: %+v until %v", h.State, h.QuarantinedUntil.Sub(later))
	}
	// The next re-probe works: probation.
	later2 := later.Add(11 * time.Minute)
	h.Apply(Signal{OK: 3}, later2)
	if h.State != StateProbation || h.QuarantinedUntil != nil {
		t.Fatalf("re-probe success: %+v", h)
	}
}

func TestHealthAuthQuarantinesAtOnce(t *testing.T) {
	now := time.Now()
	h := NewHealth(now)
	h.Apply(Signal{ProxyAuth: 1, LastError: "proxy_auth: 407"}, now)
	if h.State != StateQuarantined {
		t.Fatalf("state %s", h.State)
	}
}

func TestHealthTargetErrorsDoNotCount(t *testing.T) {
	now := time.Now()
	h := NewHealth(now)
	before := h.Score
	h.Apply(Signal{TargetUnreachable: 50, TargetRefused: 50}, now)
	if h.State != StateProbation || h.Score != before || h.ConsecutiveFailures != 0 {
		t.Fatalf("target errors moved the proxy: %+v", h)
	}
}

func TestHealthBackoffCapped(t *testing.T) {
	now := time.Now()
	h := NewHealth(now)
	for i := 0; i < 20; i++ {
		h.quarantine(now)
	}
	if h.QuarantinedUntil.Sub(now) != 2*time.Hour {
		t.Fatalf("back-off %v", h.QuarantinedUntil.Sub(now))
	}
}

func TestBuildJobEgress(t *testing.T) {
	now := time.Now()
	until := now.Add(time.Hour)
	p := &Pool{ID: shared.NewID(), Revision: 3, Strategy: StrategyPriority}
	healthy := Health{State: StateHealthy, Score: 0.9}
	p.Endpoints = []*Endpoint{
		{ID: shared.NewID(), Scheme: "socks5", Host: "10.0.0.5", Port: 1080, Enabled: true, Health: healthy, CredentialsEncrypted: "x"},
		{ID: shared.NewID(), Scheme: "http", Host: "10.0.0.6", Port: 3128, Enabled: false, Health: healthy},
		{ID: shared.NewID(), Scheme: "http", Host: "10.0.0.7", Port: 3128, Enabled: true, Health: Health{State: StateQuarantined, QuarantinedUntil: &until}},
		{ID: shared.NewID(), Scheme: "http", Host: "10.0.0.8", Port: 3128, Enabled: true, Health: NewHealth(now)},
	}
	eg := BuildJobEgress(p, AppliesAll, now)
	if eg.Mode != ModePool || eg.Revision != 3 || eg.Strategy != StrategyPriority || eg.AppliesTo != AppliesAll || len(eg.Endpoints) != 2 {
		t.Fatalf("%+v", eg)
	}
	if !eg.Endpoints[0].Auth || eg.Endpoints[0].Host != "10.0.0.5" || eg.Endpoints[1].Host != "10.0.0.8" || eg.Endpoints[1].Weight <= 0 {
		t.Fatalf("%+v", eg.Endpoints)
	}
	// All quarantined: an empty list, never no egress.
	p.Endpoints = p.Endpoints[2:3]
	if eg := BuildJobEgress(p, AppliesPublic, now); eg.Endpoints == nil || len(eg.Endpoints) != 0 || eg.Mode != ModePool {
		t.Fatalf("%+v", eg)
	}
}

func TestSanitizeError(t *testing.T) {
	got := SanitizeError("line1\nhttp://alice:s3cret@proxy:3128 failed\x00" + strings.Repeat("x", 300))
	if strings.Contains(got, "s3cret") || strings.Contains(got, "alice") || strings.ContainsAny(got, "\n\x00") || len([]rune(got)) > 200 {
		t.Fatalf("%q", got)
	}
}
