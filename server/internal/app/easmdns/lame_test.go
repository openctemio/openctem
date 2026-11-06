package easmdns

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/dnsprobe"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// scriptedDNS is a recursive resolver plus a set of authoritative servers,
// keyed by IP. It records which servers were asked directly.
type scriptedDNS struct {
	recursive map[string]dnsprobe.Answer      // "name TYPE"
	auth      map[string]map[string]authReply // ip -> "name TYPE" -> reply
	asked     []string
}

type authReply struct {
	ans dnsprobe.Answer
	err error
}

func key(name string, t dnsprobe.Type) string { return name + " " + t.String() }

func (s *scriptedDNS) Query(_ context.Context, name string, t dnsprobe.Type) (dnsprobe.Answer, error) {
	if a, ok := s.recursive[key(name, t)]; ok {
		return a, nil
	}
	return dnsprobe.Answer{RCode: dnsprobe.RCodeNXDomain}, nil
}

func (s *scriptedDNS) QueryServer(_ context.Context, ip, name string, t dnsprobe.Type) (dnsprobe.Answer, error) {
	// Mirror the real client's SSRF refusal.
	if p := net.ParseIP(ip); p == nil || p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() {
		return dnsprobe.Answer{}, dnsprobe.ErrServerNotAllowed
	}
	s.asked = append(s.asked, ip+" "+key(name, t))
	srv, ok := s.auth[ip]
	if !ok {
		return dnsprobe.Answer{}, dnsprobe.ErrTimeout
	}
	r, ok := srv[key(name, t)]
	if !ok {
		return dnsprobe.Answer{RCode: dnsprobe.RCodeRefused}, nil
	}
	return r.ans, r.err
}

func ns(owner string, hosts ...string) []dnsprobe.Record {
	out := make([]dnsprobe.Record, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, dnsprobe.Record{Name: owner, Type: dnsprobe.TypeNS, Value: h})
	}
	return out
}

func aRec(name, ip string) dnsprobe.Answer {
	return dnsprobe.Answer{RCode: dnsprobe.RCodeSuccess, Records: []dnsprobe.Record{{Name: name, Type: dnsprobe.TypeA, Value: ip}}}
}

// world: dev.example.com is delegated by example.com (served at 198.51.100.1)
// to two name servers at a DNS provider; the resolver answers SERVFAIL.
func world(child1, child2 map[string]authReply) *scriptedDNS {
	s := &scriptedDNS{
		recursive: map[string]dnsprobe.Answer{
			key("dev.example.com", dnsprobe.TypeA): {RCode: dnsprobe.RCodeServFail},
			key("example.com", dnsprobe.TypeNS):    {RCode: dnsprobe.RCodeSuccess, Records: ns("example.com", "ns1.example.com")},
			key("ns1.example.com", dnsprobe.TypeA): aRec("ns1.example.com", "198.51.100.1"),
			key("a.provider.net", dnsprobe.TypeA):  aRec("a.provider.net", "203.0.113.1"),
			key("b.provider.net", dnsprobe.TypeA):  aRec("b.provider.net", "203.0.113.2"),
		},
		auth: map[string]map[string]authReply{
			"198.51.100.1": {key("dev.example.com", dnsprobe.TypeNS): {ans: dnsprobe.Answer{RCode: dnsprobe.RCodeSuccess,
				Authority: ns("dev.example.com", "a.provider.net", "b.provider.net")}}},
		},
	}
	if child1 != nil {
		s.auth["203.0.113.1"] = child1
	}
	if child2 != nil {
		s.auth["203.0.113.2"] = child2
	}
	return s
}

var soaOK = map[string]authReply{key("dev.example.com", dnsprobe.TypeSOA): {ans: dnsprobe.Answer{RCode: dnsprobe.RCodeSuccess, Authoritative: true}}}

func TestCheckDangling_LameDelegation(t *testing.T) {
	ctx := context.Background()

	// Both delegated servers refuse the zone (it was deleted at the provider).
	s := world(map[string]authReply{}, nil)
	d, err := checkDangling(ctx, s, "dev.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Outcome != OutcomeDanglingNS || d.Severity != exposuredom.SeverityMedium || len(d.Lame) != 2 || !strings.Contains(d.Reason, "lame") {
		t.Fatalf("fully lame = %+v", d)
	}
	// The referral was asked of the parent without recursion; nothing was
	// sent to a public-suffix server.
	if len(s.asked) == 0 || !strings.HasPrefix(s.asked[0], "198.51.100.1 dev.example.com") {
		t.Fatalf("asked = %v", s.asked)
	}

	// One server still serves the zone: low.
	d, _ = checkDangling(ctx, world(soaOK, map[string]authReply{}), "dev.example.com")
	if d.Outcome != OutcomeDanglingNS || d.Severity != exposuredom.SeverityLow || len(d.Lame) != 1 || d.Lame[0] != "b.provider.net" {
		t.Fatalf("partly lame = %+v", d)
	}

	// Both serve it: the SERVFAIL has another cause; nothing concluded.
	d, _ = checkDangling(ctx, world(soaOK, soaOK), "dev.example.com")
	if d.Outcome != OutcomeUnknown {
		t.Fatalf("healthy delegation = %+v", d)
	}
}

// A delegated server on a private address is never queried and never called
// lame: the SSRF policy stops the packet and the check concludes nothing
// about that server.
func TestCheckDangling_LamePrivateServerNotJudged(t *testing.T) {
	s := world(map[string]authReply{}, nil)
	s.recursive[key("a.provider.net", dnsprobe.TypeA)] = aRec("a.provider.net", "10.0.0.53")
	s.recursive[key("b.provider.net", dnsprobe.TypeA)] = aRec("b.provider.net", "169.254.169.254")
	d, _ := checkDangling(context.Background(), s, "dev.example.com")
	if d.Outcome != OutcomeUnknown {
		t.Fatalf("private name servers judged: %+v", d)
	}
	for _, q := range s.asked {
		if strings.HasPrefix(q, "10.") || strings.HasPrefix(q, "169.254.") {
			t.Fatalf("a private address was queried: %v", s.asked)
		}
	}
}

// The apex of a registrable domain is not checked for lameness: that would
// mean asking TLD servers.
func TestCheckDangling_LameNeverAsksPublicSuffixServers(t *testing.T) {
	s := &scriptedDNS{recursive: map[string]dnsprobe.Answer{
		key("example.com", dnsprobe.TypeA): {RCode: dnsprobe.RCodeServFail},
		key("com", dnsprobe.TypeNS):        {RCode: dnsprobe.RCodeSuccess, Records: ns("com", "a.gtld-servers.net")},
	}}
	d, _ := checkDangling(context.Background(), s, "example.com")
	if d.Outcome != OutcomeUnknown || len(s.asked) != 0 {
		t.Fatalf("apex: %+v asked %v", d, s.asked)
	}
}

// Without an authoritative querier (a plain resolver client) a SERVFAIL stays
// unknown, as before.
func TestCheckDangling_ServFailWithoutAuthQuerier(t *testing.T) {
	q := recursiveOnly{world(nil, nil)}
	d, err := checkDangling(context.Background(), q, "dev.example.com")
	if err != nil || d.Outcome != OutcomeUnknown {
		t.Fatalf("%+v %v", d, err)
	}
}

type recursiveOnly struct{ s *scriptedDNS }

func (r recursiveOnly) Query(ctx context.Context, name string, t dnsprobe.Type) (dnsprobe.Answer, error) {
	return r.s.Query(ctx, name, t)
}

// A lame delegation becomes a dangling_ns exposure naming the lame servers.
func TestCheckDanglingTarget_LameEvent(t *testing.T) {
	svc := &Service{dns: world(map[string]authReply{}, map[string]authReply{})}
	tenant, asset := shared.NewID(), shared.NewID()
	outcome, found, clear, err := svc.checkDanglingTarget(context.Background(), tenant, Target{AssetID: asset, Name: "dev.example.com"})
	// A delegation finding clears the name's dangling_cname and any confirmed
	// subdomain_takeover (a CNAME and a delegation cannot share a name).
	if err != nil || outcome != OutcomeDanglingNS || len(found) != 1 || len(clear) != 2 {
		t.Fatalf("outcome %s found %d clear %d err %v", outcome, len(found), len(clear), err)
	}
	cname, _ := danglingEvent(tenant, Target{AssetID: asset, Name: "dev.example.com"}, exposuredom.EventTypeDanglingCNAME, Dangling{})
	takeover, _ := takeoverEvent(tenant, Target{AssetID: asset, Name: "dev.example.com"}, nil, nil)
	if !(contains(clear, cname.Fingerprint()) && contains(clear, takeover.Fingerprint())) {
		t.Fatalf("clear = %v, want the dangling_cname and takeover identities", clear)
	}
	ev := found[0]
	if ev.EventType() != exposuredom.EventTypeDanglingNS || ev.TenantID() != tenant || ev.AssetID() == nil || *ev.AssetID() != asset {
		t.Fatalf("event = %+v", ev)
	}
	if lame, _ := ev.Details()["lame_name_servers"].([]string); len(lame) != 2 {
		t.Fatalf("details = %v", ev.Details())
	}
	if !strings.Contains(ev.Description(), "do not serve the zone") {
		t.Fatalf("description = %q", ev.Description())
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
