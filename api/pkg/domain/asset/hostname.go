package asset

import (
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Discovered host names (docs/architecture/asset-identity-resolution.md,
// "Discovered names"): passive sources (certificate logs, search engines, web
// archives) hand back names cut out of free text and URLs. NormalizeName
// cleans what it can (percent-encoding, delimiters around the name); what
// is still not a host name afterwards is not an asset.

// maxHostnameLen is the longest DNS name in presentation form (RFC 1035).
const maxHostnameLen = 253

// maxLabelLen is the longest DNS label (RFC 1035).
const maxLabelLen = 63

// hostnameIDNA converts a name to its ASCII form for the check, with the
// lookup rules (no case or width mapping surprises; invalid input fails).
var hostnameIDNA = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(false))

// ValidHostname reports whether a normalized domain or subdomain name is a
// host name: after IDNA, at least two labels of letters, digits, "-" and
// "_", 1 to 63 characters each, none starting or ending with "-", at most
// 253 characters in all; an optional leading "*." (a wildcard) is allowed.
// It never changes the name.
func ValidHostname(name string) bool {
	name = strings.TrimPrefix(name, "*.")
	if name == "" || strings.Contains(name, "*") {
		return false
	}
	ascii, err := hostnameIDNA.ToASCII(name)
	if err != nil || ascii == "" || len(ascii) > maxHostnameLen {
		return false
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !validLabel(l) {
			return false
		}
	}
	return true
}

func validLabel(l string) bool {
	if l == "" || len(l) > maxLabelLen || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// encodedDelimiters are the percent-encodings of the URL delimiters a name
// is cut out of ("/", ":", "@", "=", "&", "?", "#", "\", quotes, space,
// ",", ";", "%"). A passive source that drops the "%" of "%2Fwww.example.com"
// leaves "2fwww.example.com".
var encodedDelimiters = []string{"2f", "3a", "40", "3d", "26", "3f", "23", "5c", "22", "27", "20", "2c", "3b", "25"}

// EncodedRemnant reports whether a normalized name starts with the remnant
// of a percent-encoded delimiter, and returns the name without it
// ("2fwww.example.com" -> "www.example.com"). It only says the name may be
// a remnant: "3ds.example.com" is a real name too. A caller drops the name
// only when the name without the remnant is also known (in the same report
// or in the inventory).
func EncodedRemnant(name string) (string, bool) {
	first, rest, ok := strings.Cut(name, ".")
	if !ok || rest == "" || len(first) <= 2 {
		return "", false
	}
	for _, d := range encodedDelimiters {
		if strings.HasPrefix(first, d) {
			stripped := name[len(d):]
			if !ValidHostname(stripped) {
				return "", false
			}
			return stripped, true
		}
	}
	return "", false
}

// IsRegistrableDomain reports whether name (a host name, any case, one
// trailing dot allowed) is a registrable domain: the public suffix plus one
// label ("example.com", "example.co.uk"). A DNS wildcard record never
// answers for the name it sits under (RFC 4592), so such a name can never
// resolve only through a wildcard of its own zone.
func IsRegistrableDomain(name string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if h == "" || strings.Contains(h, "*") {
		return false
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(h)
	return err == nil && reg == h
}
