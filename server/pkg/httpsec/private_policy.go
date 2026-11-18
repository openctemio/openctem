package httpsec

// Private network destinations: the RFC 1918 / ULA ranges the platform's
// outbound requests may reach. Two sources make one policy:
//
//   - OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS, read once at start-up ("set on the
//     server");
//   - the platform console setting, replaced at runtime by
//     SetConsolePrivateCIDRs without a restart.
//
// The guard reads one immutable snapshot (an atomic pointer) per check, and
// the dialer checks again at connect time, so a change applies to the next
// connection and a check never mixes two policies. Hard-blocked ranges
// (loopback, link-local and cloud metadata, ...) are checked first and can
// never be opened by either source. Design: docs/architecture/outbound-requests.md.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

// egressPolicy is one immutable private-egress policy. Never modify a stored
// value: build a new one and Store it.
type egressPolicy struct {
	// all opens every private range (OPENCTEM_HTTPSEC_ALLOW_PRIVATE=1,
	// development only).
	all bool
	// env are the ranges of OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS.
	env []*net.IPNet
	// console are the ranges the platform console opened.
	console []*net.IPNet
}

var policy atomic.Pointer[egressPolicy]

// currentPolicy is the policy in force (never nil).
func currentPolicy() *egressPolicy {
	if p := policy.Load(); p != nil {
		return p
	}
	return &egressPolicy{}
}

// PrivateSource says which setting opened a private range.
type PrivateSource string

// Private range sources.
const (
	// SourceServer: OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS on the server.
	SourceServer PrivateSource = "server"
	// SourceConsole: the platform console setting.
	SourceConsole PrivateSource = "console"
)

// openedRange is a range that opens an address, and where it is set.
type openedRange struct {
	net    *net.IPNet
	source PrivateSource
}

// opens returns the first range of the policy that contains ip, server
// ranges first, or nil.
func (p *egressPolicy) opens(ip net.IP) *openedRange {
	for _, n := range p.env {
		if n.Contains(ip) {
			return &openedRange{net: n, source: SourceServer}
		}
	}
	for _, n := range p.console {
		if n.Contains(ip) {
			return &openedRange{net: n, source: SourceConsole}
		}
	}
	return nil
}

func netStrings(nets []*net.IPNet) []string {
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		out = append(out, n.String())
	}
	return out
}

// Console setting bounds.
const (
	// MaxConsolePrivateRanges bounds the console list.
	MaxConsolePrivateRanges = 32
	// MinConsoleIPv6Prefix is the widest IPv6 range the console opens (one
	// site). IPv4 needs no bound of its own: a range must lie inside
	// 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16.
	MinConsoleIPv6Prefix = 48
	// WideIPv4Prefix and WideIPv6Prefix: a range wider than these is
	// accepted but the console asks the administrator to confirm it is meant.
	WideIPv4Prefix = 24
	WideIPv6Prefix = 64
	// MaxPrivateRangeNote bounds an entry's note, in characters.
	MaxPrivateRangeNote = 100
)

// Console range refusals. Every one names the offending entry.
var (
	ErrRangeNotCIDR      = errors.New("not a CIDR range")
	ErrRangeNotPrivate   = errors.New("not inside a private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)")
	ErrRangeTooWide      = fmt.Errorf("an IPv6 range must be /%d or narrower", MinConsoleIPv6Prefix)
	ErrRangeHardBlocked  = errors.New("lies inside a range that is never reachable")
	ErrRangeDuplicate    = errors.New("listed twice")
	ErrTooManyRanges     = fmt.Errorf("at most %d ranges", MaxConsolePrivateRanges)
	ErrRangeNoteTooLong  = fmt.Errorf("a note is at most %d characters", MaxPrivateRangeNote)
	ErrRangeNoteNotPlain = errors.New("a note must be plain text on one line")
)

// RangeError is a refused console range: which entry and why.
type RangeError struct {
	Index int
	Range string
	Err   error
}

func (e *RangeError) Error() string {
	return fmt.Sprintf("range %d (%q): %v", e.Index+1, e.Range, e.Err)
}

func (e *RangeError) Unwrap() error { return e.Err }

// ParseConsoleCIDR checks one console range and returns its canonical form
// (the network address with its prefix: "10.20.0.5/16" becomes
// "10.20.0.0/16"). The range must lie inside one private range, must not lie
// inside a hard-blocked range, and an IPv6 range must be /48 or narrower.
// Hard-blocked addresses inside an accepted range (the IPv6 metadata
// endpoints sit inside fc00::/7) stay blocked: the guard checks them first.
func ParseConsoleCIDR(raw string) (*net.IPNet, error) {
	raw = strings.TrimSpace(raw)
	_, n, err := net.ParseCIDR(raw)
	if err != nil || raw == "" {
		return nil, ErrRangeNotCIDR
	}
	if !insidePrivateRange(n) {
		return nil, ErrRangeNotPrivate
	}
	ones, bits := n.Mask.Size()
	if bits == 128 && ones < MinConsoleIPv6Prefix {
		return nil, ErrRangeTooWide
	}
	for _, h := range hardBlockedCIDRs {
		hOnes, hBits := h.Mask.Size()
		if hBits == bits && ones >= hOnes && h.Contains(n.IP) {
			return nil, ErrRangeHardBlocked
		}
	}
	return n, nil
}

// IsWideRange reports whether a canonical range is wider than /24 (IPv4) or
// /64 (IPv6), the point at which the console asks for a second look.
func IsWideRange(n *net.IPNet) bool {
	ones, bits := n.Mask.Size()
	if bits == 32 {
		return ones < WideIPv4Prefix
	}
	return ones < WideIPv6Prefix
}

// CheckRangeNote checks an entry's note: optional, one line of plain text.
func CheckRangeNote(note string) error {
	if len([]rune(note)) > MaxPrivateRangeNote {
		return ErrRangeNoteTooLong
	}
	for _, r := range note {
		if unicode.IsControl(r) || r == ' ' || r == ' ' || unicode.Is(unicode.Cf, r) {
			return ErrRangeNoteNotPlain
		}
	}
	return nil
}

// CanonicalConsoleCIDRs checks a whole console list: every entry valid, no
// duplicates (after canonical form), at most MaxConsolePrivateRanges. It
// returns the canonical ranges in input order.
func CanonicalConsoleCIDRs(raws []string) ([]*net.IPNet, error) {
	if len(raws) > MaxConsolePrivateRanges {
		return nil, ErrTooManyRanges
	}
	out := make([]*net.IPNet, 0, len(raws))
	seen := make(map[string]bool, len(raws))
	for i, raw := range raws {
		n, err := ParseConsoleCIDR(raw)
		if err != nil {
			return nil, &RangeError{Index: i, Range: raw, Err: err}
		}
		if seen[n.String()] {
			return nil, &RangeError{Index: i, Range: raw, Err: ErrRangeDuplicate}
		}
		seen[n.String()] = true
		out = append(out, n)
	}
	return out, nil
}

// SetConsolePrivateCIDRs replaces the console ranges of the policy. The list
// is checked first (CanonicalConsoleCIDRs); on error nothing changes. The
// server ranges and the development switch are kept.
func SetConsolePrivateCIDRs(raws []string) error {
	nets, err := CanonicalConsoleCIDRs(raws)
	if err != nil {
		return err
	}
	for {
		cur := policy.Load()
		next := &egressPolicy{console: nets}
		if cur != nil {
			next.all, next.env = cur.all, cur.env
		}
		if policy.CompareAndSwap(cur, next) {
			if cur != nil && narrows(cur.console, nets) {
				closeGuardedIdleConnections()
			}
			return nil
		}
	}
}

// ConsolePrivateCIDRs returns the console ranges in force.
func ConsolePrivateCIDRs() []string { return netStrings(currentPolicy().console) }

// Destination verdicts of InspectDestination.
const (
	// VerdictPublic: a public address, reachable.
	VerdictPublic = "allowed"
	// VerdictPrivateOpen: a private address inside an opened range.
	VerdictPrivateOpen = "allowed_private"
	// VerdictPrivateBlocked: a private address no range opens.
	VerdictPrivateBlocked = "blocked_private"
	// VerdictHardBlocked: never reachable, whatever is opened.
	VerdictHardBlocked = "hard_blocked"
)

// AddressVerdict is the guard's decision for one resolved address.
type AddressVerdict struct {
	Address string
	Verdict string
	// OpenedBy is the range that opens the address and where it is set
	// (VerdictPrivateOpen).
	OpenedBy string
	Source   PrivateSource
	// AllPrivateOpen: the development switch opens every private range.
	AllPrivateOpen bool
	// Suggested is the narrowest usual range that would open the address
	// (its /24, or /64 for IPv6) (VerdictPrivateBlocked).
	Suggested string
	// HardBlock says why the address is never reachable (VerdictHardBlocked).
	HardBlock HardBlockReason
}

// DestinationReport is what InspectDestination found for one host.
type DestinationReport struct {
	Host      string
	Addresses []AddressVerdict
	// NameBlocked: the host name itself is a blocked alias; nothing was
	// resolved.
	NameBlocked bool
}

// Destination inspection refusals.
var (
	// ErrNotAHostName: the input is not a bare host name or IP address (a
	// URL, a path, a port, credentials, spaces).
	ErrNotAHostName = errors.New("enter a host name or an IP address, without scheme, port or path")
	// ErrHostNotFound: the name has no address.
	ErrHostNotFound = errors.New("the host name does not resolve")
)

// inspectTimeout bounds the lookup of InspectDestination.
const inspectTimeout = 5 * time.Second

// InspectDestination resolves host and reports, for each address, whether
// the guard lets the platform reach it under the current policy and why. It
// only resolves: it never connects to the host.
func InspectDestination(ctx context.Context, host string) (*DestinationReport, error) {
	return inspectDestination(ctx, net.DefaultResolver, host)
}

func inspectDestination(ctx context.Context, resolver ipResolver, host string) (*DestinationReport, error) {
	host, err := checkHostName(host)
	if err != nil {
		return nil, err
	}
	rep := &DestinationReport{Host: host}
	if isDangerousHost(host) {
		rep.NameBlocked = true
		return rep, nil
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		lctx, cancel := context.WithTimeout(ctx, inspectTimeout)
		defer cancel()
		addrs, err := resolver.LookupIPAddr(lctx, host)
		if err != nil || len(addrs) == 0 {
			return nil, ErrHostNotFound
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	p := currentPolicy()
	for _, ip := range ips {
		rep.Addresses = append(rep.Addresses, verdictFor(p, ip))
	}
	return rep, nil
}

// verdictFor is isIPBlocked's decision for ip under p, with its reason.
func verdictFor(p *egressPolicy, ip net.IP) AddressVerdict {
	v := AddressVerdict{Address: ip.String()}
	if reason, hard := hardBlockReason(ip); hard {
		v.Verdict, v.HardBlock = VerdictHardBlocked, reason
		return v
	}
	if !IsPrivateIP(ip) {
		v.Verdict = VerdictPublic
		return v
	}
	if p.all {
		v.Verdict, v.AllPrivateOpen = VerdictPrivateOpen, true
		return v
	}
	if o := p.opens(ip); o != nil {
		v.Verdict, v.OpenedBy, v.Source = VerdictPrivateOpen, o.net.String(), o.source
		return v
	}
	v.Verdict, v.Suggested = VerdictPrivateBlocked, suggestedRange(ip)
	return v
}

// suggestedRange is the /24 (IPv4) or /64 (IPv6) holding ip.
func suggestedRange(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}

// checkHostName accepts a bare DNS name or an IP literal (IPv6 with or
// without brackets) and returns it trimmed, lower case, without a trailing
// dot.
func checkHostName(raw string) (string, error) {
	h := strings.TrimSpace(raw)
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.String(), nil
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" || len(h) > 253 {
		return "", ErrNotAHostName
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", ErrNotAHostName
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return "", ErrNotAHostName
			}
		}
	}
	return h, nil
}
