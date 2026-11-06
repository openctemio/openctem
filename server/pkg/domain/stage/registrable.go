package stage

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// RegistryLevel reports whether the stage answers for the domain registered
// at a registry, not for each name below it: a registration lookup (RDAP)
// knows the registrable domain and has no record of a subdomain. The names
// handed to such a stage collapse to their registrable domains, each once.
func RegistryLevel(k Key) bool { return k == LookupRDAP }

// RegistrableDomain is the domain registered at the registry for a host
// name: the label before the ICANN public suffix, and the suffix
// ("www.example.co.uk" gives "example.co.uk"). A private-section suffix
// (github.io) is not a registry: the domain is the one under its ICANN
// suffix. It reports false for an address, a public suffix itself, a
// dotless name or anything that is not a plain host name.
func RegistrableDomain(name string) (string, bool) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if n == "" || !strings.Contains(n, ".") || strings.ContainsAny(n, "/:@*[] \t\\") {
		return "", false
	}
	labels := strings.Split(n, ".")
	allDigits := true
	for _, l := range labels {
		if l == "" {
			return "", false
		}
		if strings.Trim(l, "0123456789") != "" {
			allDigits = false
		}
	}
	if allDigits {
		return "", false // an IPv4 address
	}
	for i := range labels {
		cand := strings.Join(labels[i:], ".")
		if ps, icann := publicsuffix.PublicSuffix(cand); icann && ps == cand {
			if i == 0 {
				return "", false
			}
			return strings.Join(labels[i-1:], "."), true
		}
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(n)
	if err != nil {
		return "", false
	}
	return d, true
}
