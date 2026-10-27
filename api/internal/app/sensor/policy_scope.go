package sensor

// The sensor-local policy prefill from the organization's scope (design:
// docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md, the local policy).
// The platform only proposes text: a person reviews it in the install
// commands, the host writes the file, and the sensor enforces it; the
// platform can never change it afterwards. A prefill therefore never
// widens anything; it replaces an empty file (which admits any target
// outside the built-in deny list) with the organization's own scope.

import (
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/openctemio/ctis/addrscope"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
)

// Where the policy prefill came from (PolicyTemplateData.Source).
const (
	PolicySourceZones = "zones"
	PolicySourceScope = "scope"
)

// MaxPolicyPrefillEntries caps each list of the prefill. The sensor accepts
// at most 4096 entries per list; a scope larger than this is cut and the
// file says how many entries were left out.
const MaxPolicyPrefillEntries = 2000

// metadataInPrivate are cloud metadata addresses inside private ranges: the
// sensor refuses them in an allow list even when private targets are on.
var metadataInPrivate = []netip.Addr{
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("fd20:ce::254"),
}

// sensorRefusesAllow reports whether the sensor would refuse to load an allow
// entry for the network starting at a: the addresses it always blocks
// (loopback, link-local, metadata, reserved), private ranges excepted. The
// sensor checks the network address of a range, so this does too.
func sensorRefusesAllow(a netip.Addr) bool {
	a = a.Unmap()
	if !addrscope.IsInternal(a) {
		return false
	}
	return !a.IsPrivate() || slices.Contains(metadataInPrivate, a)
}

// PolicyFromScope builds the policy prefill from the organization's active
// scope: CIDRs, addresses and ranges go to the allow list as networks;
// domains, host names and the hosts of URL entries as names (a wildcard
// entry "*.example.com" covers the name itself too, so both are listed).
// Active exclusions of a network or name type become the deny list. Entries
// the sensor would refuse to load (always-blocked addresses, malformed
// values) are left out and counted in Skipped. Port and protocol limits of
// an entry are not carried: the platform enforces them on every job, and the
// local policy is the network owner's coarser veto.
func PolicyFromScope(targets []*scope.Target, exclusions []*scope.Exclusion) PolicyTemplateData {
	out := PolicyTemplateData{Source: PolicySourceScope}
	for _, t := range targets {
		if t == nil || !t.IsActive() {
			continue
		}
		nets, names, ok := scopeEntry(string(t.TargetType()), t.Pattern())
		if !ok {
			if networkKind(string(t.TargetType())) {
				out.Skipped++
			}
			continue
		}
		for _, p := range nets {
			if sensorRefusesAllow(p.Addr()) {
				out.Skipped++
				continue
			}
			out.Ranges = appendUnique(out.Ranges, p.String())
			if p.Addr().IsPrivate() {
				out.AllowPrivate = true
			}
		}
		for _, n := range names {
			out.Domains = appendUnique(out.Domains, n)
		}
	}
	out.Deny = DenyFromExclusions(exclusions)
	out.Ranges, out.Truncated = capList(out.Ranges, out.Truncated)
	out.Domains, out.Truncated = capList(out.Domains, out.Truncated)
	slices.Sort(out.Ranges)
	slices.Sort(out.Domains)
	return out
}

// DenyFromExclusions turns the organization's active exclusions of a network
// or name type into the policy's deny list (never scanned, even when an
// allow entry matches). Other exclusion types (paths, finding types,
// scanners) have no place in a target list and are left out.
func DenyFromExclusions(exclusions []*scope.Exclusion) []string {
	var deny []string
	for _, e := range exclusions {
		if e == nil || !e.IsActive() {
			continue
		}
		nets, names, ok := scopeEntry(string(e.ExclusionType()), e.Pattern())
		if !ok {
			continue
		}
		for _, p := range nets {
			deny = appendUnique(deny, p.String())
		}
		for _, n := range names {
			deny = appendUnique(deny, n)
		}
	}
	deny, _ = capList(deny, 0)
	slices.Sort(deny)
	return deny
}

// networkKind reports whether entries of this type name a network location
// the policy can list (the types scopeEntry reads).
func networkKind(kind string) bool {
	switch kind {
	case "cidr", "ip_range", "ip_address", "domain", "subdomain", "email_domain", "host", "url", "api", "website":
		return true
	}
	return false
}

// scopeEntry reads one scope entry (a target or an exclusion of the same
// type names) as networks and host-name patterns in the sensor's syntax.
func scopeEntry(kind, pattern string) (nets []netip.Prefix, names []string, ok bool) {
	p := strings.ToLower(strings.TrimSpace(pattern))
	if p == "" {
		return nil, nil, false
	}
	switch kind {
	case "cidr", "ip_range", "ip_address":
		if n, ok := parseNetwork(p); ok {
			return []netip.Prefix{n}, nil, true
		}
		return nil, nil, false
	case "domain", "subdomain", "email_domain":
		return nameEntry(p)
	case "host":
		if n, ok := parseNetwork(p); ok {
			return []netip.Prefix{n}, nil, true
		}
		return nameEntry(p)
	case "url", "api", "website":
		u, err := url.Parse(p)
		if err != nil || u.Hostname() == "" {
			return nil, nil, false
		}
		h := u.Hostname()
		if a, err := netip.ParseAddr(h); err == nil {
			return []netip.Prefix{netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())}, nil, true
		}
		return nameEntry(h)
	}
	return nil, nil, false
}

// parseNetwork reads an address or a CIDR as a masked network (the sensor
// refuses a CIDR with host bits set).
func parseNetwork(s string) (netip.Prefix, bool) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-unmapShift(p.Addr())).Masked()
		return p, p.IsValid()
	}
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

// unmapShift is how many prefix bits an IPv4-mapped IPv6 prefix loses when
// it is written as IPv4.
func unmapShift(a netip.Addr) int {
	if a.Is4In6() {
		return 96
	}
	return 0
}

// nameEntry reads a host name or a "*.domain" wildcard. A wildcard is listed
// as both the name and "*.name", because the scope's wildcard covers the
// name itself and the sensor's does not.
func nameEntry(s string) (nets []netip.Prefix, names []string, ok bool) {
	wild := false
	if rest, cut := strings.CutPrefix(s, "*."); cut {
		s, wild = rest, true
	}
	s = strings.TrimSuffix(s, ".")
	if !validPolicyHostname(s) || (wild && !strings.Contains(s, ".")) {
		return nil, nil, false
	}
	if wild {
		return nil, []string{s, "*." + s}, true
	}
	return nil, []string{s}, true
}

// validPolicyHostname matches what the sensor accepts as a host name: LDH
// labels (underscores allowed), no empty label, at most 253 characters.
func validPolicyHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}

func appendUnique(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

func capList(list []string, dropped int) ([]string, int) {
	if len(list) <= MaxPolicyPrefillEntries {
		return list, dropped
	}
	return list[:MaxPolicyPrefillEntries], dropped + len(list) - MaxPolicyPrefillEntries
}
