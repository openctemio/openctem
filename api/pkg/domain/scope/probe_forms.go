package scope

// The forms a probe target is matched in, and whether it needs a scope
// entry at all (RFC-054 §4.2 step 6). The API's authority check
// (internal/app/scopeauth, internal/app/easm), its exclusion filter
// (internal/app/scope) and the job signer's ledger (internal/signer) all use
// these, so one target gets one answer on both sides of the signer socket.

import (
	"net/netip"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// AuthorityForms is the target as typed, lower-cased, and the host of a URL
// or host:port: the forms a scope entry is matched against.
func AuthorityForms(target string) []string {
	v := strings.TrimSpace(target)
	out := []string{v}
	add := func(s string) {
		s = strings.Trim(strings.TrimSpace(s), "[]")
		if s == "" {
			return
		}
		for _, have := range out {
			if have == s {
				return
			}
		}
		out = append(out, s)
	}
	add(strings.ToLower(v))
	if h := asset.HostOf(v); !strings.EqualFold(h, v) {
		add(h)
	}
	return out
}

// ExclusionForms is the value itself plus the host it names when it is a
// URL ("https://host:8443/path") or a host:port: the forms an exclusion is
// matched against. An exclusion names a host; without the host form a
// target written as a URL or with a port would slip past a domain, IP or
// CIDR exclusion of that host. More forms can only exclude more.
func ExclusionForms(value string) []string {
	v := strings.TrimSpace(value)
	forms := []string{v}
	host := asset.HostOf(v)
	if host != "" && !strings.EqualFold(host, v) {
		forms = append(forms, strings.ToLower(host))
	}
	return forms
}

// NeedsAuthority reports whether typed text names an internet host or a
// public address, network or URL: a target only a scope entry authorizes.
// Internal names and private, loopback, link-local and CGNAT addresses are
// gated by scan zones instead (RFC-054 §4.2), and text that names no host
// (a repository path, ".") needs no entry.
func NeedsAuthority(t string) bool {
	if InternalName(t) {
		return false
	}
	if probeHost(t) != "" {
		return true
	}
	h := strings.Trim(strings.TrimSpace(t), "[]")
	if _, err := netip.ParsePrefix(h); err == nil {
		return true
	}
	_, err := netip.ParseAddr(asset.HostOf(t))
	return err == nil
}

// InternalName reports whether a name is a private, loopback, link-local
// or CGNAT address or network, or an internal DNS name (localhost, .local,
// .internal, .lan).
func InternalName(name string) bool {
	if p, err := netip.ParsePrefix(strings.TrimSpace(name)); err == nil {
		return internalAddr(p.Addr())
	}
	h := asset.HostOf(name)
	if a, err := netip.ParseAddr(h); err == nil {
		return internalAddr(a)
	}
	l := strings.ToLower(strings.TrimSuffix(h, "."))
	return l == "localhost" || strings.HasSuffix(l, ".localhost") ||
		strings.HasSuffix(l, ".local") || strings.HasSuffix(l, ".internal") || strings.HasSuffix(l, ".lan")
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func internalAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || cgnat.Contains(a)
}

// probeHost is the lower-case DNS name a target names ("" for an address,
// a network or a name without a dot). asset.HostOf reads every service
// name form ("host:443:tcp", "host:443/tcp", "[v6]:443/tcp"), URLs and
// host:port, so a service follows its host.
func probeHost(s string) string {
	h := strings.ToLower(strings.TrimSpace(asset.HostOf(s)))
	h = strings.TrimSuffix(strings.TrimPrefix(h, "*."), ".")
	if h == "" || !strings.Contains(h, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return ""
	}
	return h
}
