package httpsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
)

// setPolicyForTest installs p for one test and restores the previous policy.
func setPolicyForTest(t *testing.T, p *egressPolicy) {
	t.Helper()
	prev := policy.Load()
	policy.Store(p)
	t.Cleanup(func() { policy.Store(prev) })
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestParseConsoleCIDR(t *testing.T) {
	for raw, want := range map[string]error{
		"10.20.0.0/16":        nil,
		" 192.168.7.0/24 ":    nil,
		"10.0.0.0/8":          nil, // a whole private block: accepted, flagged wide
		"172.16.0.0/12":       nil,
		"fd12:3456:789a::/48": nil,
		"fd12:3456:789a::/64": nil,
		"fd12::/16":           ErrRangeTooWide,
		"fc00::/7":            ErrRangeTooWide,
		"172.0.0.0/8":         ErrRangeNotPrivate,
		"0.0.0.0/0":           ErrRangeNotPrivate,
		"203.0.113.0/24":      ErrRangeNotPrivate,
		"100.64.0.0/10":       ErrRangeNotPrivate,
		"127.0.0.0/8":         ErrRangeNotPrivate,
		"169.254.169.254/32":  ErrRangeNotPrivate,
		"fd00:ec2::254/128":   ErrRangeHardBlocked, // AWS metadata over IPv6
		"fd20:ce::254/128":    ErrRangeHardBlocked,
		"10.0.0.1":            ErrRangeNotCIDR,
		"":                    ErrRangeNotCIDR,
		"gitlab.example.com":  ErrRangeNotCIDR,
	} {
		_, err := ParseConsoleCIDR(raw)
		if !errors.Is(err, want) && (want != nil || err != nil) {
			t.Errorf("ParseConsoleCIDR(%q) = %v, want %v", raw, err, want)
		}
	}
	n, err := ParseConsoleCIDR("10.20.0.5/16")
	if err != nil || n.String() != "10.20.0.0/16" {
		t.Fatalf("canonical form = %v, %v", n, err)
	}
}

func TestIsWideRange(t *testing.T) {
	for s, wide := range map[string]bool{
		"10.0.0.0/8": true, "10.1.0.0/23": true, "10.1.1.0/24": false, "10.1.1.7/32": false,
		"fd12:3456:789a::/48": true, "fd12:3456:789a:1::/64": false,
	} {
		if got := IsWideRange(mustCIDR(t, s)); got != wide {
			t.Errorf("IsWideRange(%s) = %v, want %v", s, got, wide)
		}
	}
}

func TestCanonicalConsoleCIDRs_ListRules(t *testing.T) {
	var re *RangeError
	if _, err := CanonicalConsoleCIDRs([]string{"10.1.0.0/16", "10.1.0.9/16"}); !errors.As(err, &re) || !errors.Is(err, ErrRangeDuplicate) || re.Index != 1 {
		t.Fatalf("duplicate after canonical form: %v", err)
	}
	many := make([]string, MaxConsolePrivateRanges+1)
	for i := range many {
		many[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	if _, err := CanonicalConsoleCIDRs(many); !errors.Is(err, ErrTooManyRanges) {
		t.Fatalf("too many: %v", err)
	}
	if _, err := CanonicalConsoleCIDRs(many[:MaxConsolePrivateRanges]); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
}

func TestCheckRangeNote(t *testing.T) {
	for note, want := range map[string]error{
		"":                       nil,
		"GitLab":                 nil,
		"Mail relay, building 2": nil,
		strings.Repeat("a", 100): nil,
		strings.Repeat("a", 101): ErrRangeNoteTooLong,
		"two\nlines":             ErrRangeNoteNotPlain,
		"bidi \u202e override":   ErrRangeNoteNotPlain,
		"tab\there":              ErrRangeNoteNotPlain,
	} {
		if err := CheckRangeNote(note); !errors.Is(err, want) && (want != nil || err != nil) {
			t.Errorf("CheckRangeNote(%q) = %v, want %v", note, err, want)
		}
	}
}

// A refused list changes nothing; an accepted one replaces only the console
// part and keeps the server ranges.
func TestSetConsolePrivateCIDRs_ReplacesConsoleOnly(t *testing.T) {
	setPolicyForTest(t, &egressPolicy{env: []*net.IPNet{mustCIDR(t, "10.20.0.0/16")}})
	if err := SetConsolePrivateCIDRs([]string{"192.168.7.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := SetConsolePrivateCIDRs([]string{"192.168.9.0/24", "203.0.113.0/24"}); err == nil {
		t.Fatal("a public range was accepted")
	}
	if got := strings.Join(ConsolePrivateCIDRs(), ","); got != "192.168.7.0/24" {
		t.Fatalf("console = %s after a refused list", got)
	}
	if got := strings.Join(AllowedPrivateCIDRs(), ","); got != "10.20.0.0/16" {
		t.Fatalf("server ranges = %s", got)
	}
	if err := SetConsolePrivateCIDRs(nil); err != nil {
		t.Fatal(err)
	}
	if IsIPBlocked(net.ParseIP("192.168.7.9")) == false {
		t.Fatal("a cleared console range still opens its address")
	}
}

// The effective set is the union of the server and console ranges; the
// hard-blocked ranges inside an opened range stay blocked.
func TestIsIPBlocked_ServerUnionConsole(t *testing.T) {
	setPolicyForTest(t, &egressPolicy{env: []*net.IPNet{mustCIDR(t, "10.20.0.0/16")}})
	if err := SetConsolePrivateCIDRs([]string{"192.168.7.0/24", "fd00:ec2::/48"}); err != nil {
		t.Fatal(err)
	}
	for ip, blocked := range map[string]bool{
		"10.20.1.5":       false, // server
		"192.168.7.20":    false, // console
		"192.168.9.1":     true,
		"172.16.0.1":      true,
		"fd00:ec2::1":     false,
		"fd00:ec2::254":   true, // metadata over IPv6, inside the console range
		"127.0.0.1":       true,
		"169.254.169.254": true,
		"8.8.8.8":         false,
	} {
		if got := IsIPBlocked(net.ParseIP(ip)); got != blocked {
			t.Errorf("IsIPBlocked(%s) = %v, want %v", ip, got, blocked)
		}
	}
}

// The guard reads the console list while it changes (run with -race): no
// data race, and no read ever opens a range no list named or a hard-blocked
// address.
func TestConsolePrivateCIDRs_ConcurrentSwap(t *testing.T) {
	setPolicyForTest(t, &egressPolicy{})
	lists := [][]string{{"10.1.0.0/16"}, {"10.2.0.0/16"}, nil}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = IsIPBlocked(net.ParseIP("10.1.0.1"))
				if !IsIPBlocked(net.ParseIP("10.3.0.1")) {
					t.Error("a range no list names was opened")
					return
				}
				if IsIPBlocked(net.ParseIP("127.0.0.1")) == false {
					t.Error("loopback opened")
					return
				}
				_ = ConsolePrivateCIDRs()
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		if err := SetConsolePrivateCIDRs(lists[i%len(lists)]); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
}

// tableResolver answers from a fixed table and counts lookups.
type tableResolver struct {
	answers map[string][]string
	calls   int
}

func (f *tableResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.calls++
	ips, ok := f.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IPAddr, 0, len(ips))
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func TestInspectDestination_Verdicts(t *testing.T) {
	setPolicyForTest(t, &egressPolicy{env: []*net.IPNet{mustCIDR(t, "10.20.0.0/16")}})
	if err := SetConsolePrivateCIDRs([]string{"192.168.7.0/24"}); err != nil {
		t.Fatal(err)
	}
	// Every connection attempt fails the test: inspection only resolves.
	prevDialer := defaultDialer
	defaultDialer.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Error("InspectDestination dialed")
		return nil, errors.New("no dial")
	}
	t.Cleanup(func() { defaultDialer = prevDialer })

	r := &tableResolver{answers: map[string][]string{
		"gitlab.example.com": {"192.168.7.20", "10.20.3.4", "10.30.1.9", "203.0.113.5", "169.254.169.254", "fd00:ec2::254"},
	}}
	rep, err := inspectDestination(context.Background(), r, "GitLab.Example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Host != "gitlab.example.com" || len(rep.Addresses) != 6 {
		t.Fatalf("report = %+v", rep)
	}
	want := []AddressVerdict{
		{Address: "192.168.7.20", Verdict: VerdictPrivateOpen, OpenedBy: "192.168.7.0/24", Source: SourceConsole},
		{Address: "10.20.3.4", Verdict: VerdictPrivateOpen, OpenedBy: "10.20.0.0/16", Source: SourceServer},
		{Address: "10.30.1.9", Verdict: VerdictPrivateBlocked, Suggested: "10.30.1.0/24"},
		{Address: "203.0.113.5", Verdict: VerdictPublic},
		{Address: "169.254.169.254", Verdict: VerdictHardBlocked, HardBlock: HardBlockLinkLocal},
		{Address: "fd00:ec2::254", Verdict: VerdictHardBlocked, HardBlock: HardBlockMetadata},
	}
	for i, w := range want {
		if rep.Addresses[i] != w {
			t.Errorf("address %d = %+v, want %+v", i, rep.Addresses[i], w)
		}
	}

	if rep, err := inspectDestination(context.Background(), r, "localhost"); err != nil || !rep.NameBlocked {
		t.Fatalf("localhost: %+v %v", rep, err)
	}
	if _, err := inspectDestination(context.Background(), r, "missing.example.com"); !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("unresolvable: %v", err)
	}
	calls := r.calls
	for _, bad := range []string{"https://gitlab.example.com", "gitlab.example.com/path", "gitlab.example.com:443",
		"user@gitlab.example.com", "gitlab example.com", "", "-bad.example.com", strings.Repeat("a", 64) + ".example.com"} {
		if _, err := inspectDestination(context.Background(), r, bad); !errors.Is(err, ErrNotAHostName) {
			t.Errorf("%q: %v, want ErrNotAHostName", bad, err)
		}
	}
	if r.calls != calls {
		t.Fatal("a refused input was resolved")
	}
	// IP literals are judged without a lookup.
	if rep, err := inspectDestination(context.Background(), r, "[fd12:3456:789a::1]"); err != nil ||
		rep.Addresses[0].Verdict != VerdictPrivateBlocked || rep.Addresses[0].Suggested != "fd12:3456:789a::/64" {
		t.Fatalf("IPv6 literal: %+v %v", rep, err)
	}
	if r.calls != calls {
		t.Fatal("an IP literal was resolved")
	}
}

// The development switch reports every private address open, but never a
// hard-blocked one.
func TestInspectDestination_DevelopmentSwitch(t *testing.T) {
	setPolicyForTest(t, &egressPolicy{all: true})
	r := &tableResolver{answers: map[string][]string{"h.example.com": {"10.9.9.9", "127.0.0.1"}}}
	rep, err := inspectDestination(context.Background(), r, "h.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Addresses[0].AllPrivateOpen || rep.Addresses[1].Verdict != VerdictHardBlocked {
		t.Fatalf("report = %+v", rep.Addresses)
	}
}
