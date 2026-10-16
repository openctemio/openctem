package jobsign

import "strings"

// NumericHost reports whether a host that did not parse as an address ends
// in a label of only decimal, octal or hex digits ("2130706433", "0x7f.1",
// "127.1", "0177.0.0.1"). No top-level domain is numeric, and resolvers and
// tools that accept the legacy inet_aton forms read such a host as an
// address (127.0.0.1 in each example). The signer and the API refuse such a
// host for a shared sensor (fail closed). host is lower case.
func NumericHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	last := host
	if i := strings.LastIndex(host, "."); i >= 0 {
		last = host[i+1:]
	}
	if last == "" {
		return false
	}
	if hex, ok := strings.CutPrefix(last, "0x"); ok {
		return strings.Trim(hex, "0123456789abcdef") == ""
	}
	return strings.Trim(last, "0123456789") == ""
}
