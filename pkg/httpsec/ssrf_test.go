package httpsec

import (
	"net"
	"strings"
	"testing"
)

// Most tests assert the production posture. TestMain pins
// allowPrivate=false so the OPENCTEM_HTTPSEC_ALLOW_PRIVATE env var
// inherited from the harness cannot drift a test result.
func TestMain(m *testing.M) {
	allowPrivate = false
	m.Run()
}

// TestValidateURL_BlockedCategories asserts the guard rejects every
// public-wrong category an attacker might point a webhook at. Each
// line is a named threat; a failure here means the SSRF door is open.
func TestValidateURL_BlockedCategories(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string // substring of the error
	}{
		{"loopback ipv4", "http://127.0.0.1/", "blocked"},
		{"loopback ipv6", "http://[::1]/", "blocked"},
		{"link-local metadata", "http://169.254.169.254/latest/meta-data/", "blocked"},
		{"metadata alias", "http://metadata.google.internal/", "blocked hostname"},
		{"localhost alias", "http://localhost:8080/", "blocked hostname"},
		{"file scheme", "file:///etc/passwd", "unsupported scheme"},
		{"gopher scheme", "gopher://evil/", "unsupported scheme"},
		{"unix scheme", "unix:///var/run/docker.sock", "unsupported scheme"},
		{"no host", "http:///just-a-path", "no host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateURL(tc.url)
			if err == nil {
				t.Fatalf("expected %q to be rejected, but got nil error", tc.url)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q missing expected substring %q", err.Error(), tc.want)
			}
		})
	}
}

// TestIsIPBlocked_Ranges asserts the CIDR table expands to the exact
// IPs we care about. If one of these starts passing, an SSRF test
// will too.
func TestIsIPBlocked_Ranges(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.255.255.255",
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.1.1",
		"169.254.169.254",
		"100.64.0.1",
		"0.0.0.1",
		"224.1.2.3",
	}
	for _, ip := range blocked {
		if !IsIPBlocked(net.ParseIP(ip)) {
			t.Fatalf("expected %s to be blocked", ip)
		}
	}

	public := []string{
		"8.8.8.8",
		"1.1.1.1",
		"140.82.114.3", // github.com
	}
	for _, ip := range public {
		if IsIPBlocked(net.ParseIP(ip)) {
			t.Fatalf("unexpectedly blocked public IP %s", ip)
		}
	}
}

// --- allowPrivate opt-in mode tests ---

// When allowPrivate=true, RFC1918 / ULA become reachable but the
// hard-blocked CIDRs (IMDS, loopback, CGNAT, multicast) stay
// blocked. This is the core promise of the env-var opt-in: an
// on-prem operator can scan 10/8 + 192.168/16 without accidentally
// opening up the cloud metadata endpoint.
func TestIsIPBlocked_AllowPrivateMode(t *testing.T) {
	prev := allowPrivate
	allowPrivate = true
	defer func() { allowPrivate = prev }()

	// RFC1918 / ULA now pass.
	rfc1918 := []string{
		"10.0.0.1",
		"10.255.255.255",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
	}
	for _, ip := range rfc1918 {
		if IsIPBlocked(net.ParseIP(ip)) {
			t.Errorf("allowPrivate=true: expected %s to be allowed", ip)
		}
	}

	// Hard-blocked still blocked — this is the whole point of the
	// split. If any of these passes, a compromised admin could
	// enable allowPrivate and exfiltrate cloud creds.
	hardBlocked := []string{
		"127.0.0.1",       // loopback
		"169.254.169.254", // AWS/GCP IMDS
		"169.254.0.1",     // any link-local
		"100.64.0.1",      // CGNAT
		"224.1.2.3",       // multicast
		"255.255.255.255", // broadcast
		"0.0.0.1",         // "this" network
	}
	for _, ip := range hardBlocked {
		if !IsIPBlocked(net.ParseIP(ip)) {
			t.Errorf("allowPrivate=true: %s MUST stay hard-blocked (IMDS/loopback/CGNAT class)", ip)
		}
	}

	// Public stays unblocked (wasn't blocked before either — sanity).
	if IsIPBlocked(net.ParseIP("8.8.8.8")) {
		t.Errorf("allowPrivate=true: public IP wrongly blocked")
	}
}

// The string-level dangerousHosts allowlist (localhost,
// metadata.google.internal, etc.) must also stay blocked in
// allowPrivate mode — these aliases resolve onto the hard-blocked
// CIDRs anyway, but ValidateURL intercepts them earlier on a name
// match, and that branch must not be loosened.
func TestValidateURL_AllowPrivate_KeepsAliasesBlocked(t *testing.T) {
	prev := allowPrivate
	allowPrivate = true
	defer func() { allowPrivate = prev }()

	cases := []string{
		"http://localhost:8080/",
		"http://metadata.google.internal/",
		"http://169.254.169.254/latest/meta-data/",
	}
	for _, u := range cases {
		if _, err := ValidateURL(u); err == nil {
			t.Errorf("allowPrivate=true: %q must still be rejected (alias or hard-blocked)", u)
		}
	}
}

// RFC1918 CIDR under the default (allowPrivate=false) posture must
// still reject so TestIsIPBlocked_Ranges above remains robust when
// the env var is unset.
func TestIsIPBlocked_DefaultMode_BlocksPrivate(t *testing.T) {
	prev := allowPrivate
	allowPrivate = false
	defer func() { allowPrivate = prev }()

	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1"} {
		if !IsIPBlocked(net.ParseIP(ip)) {
			t.Errorf("allowPrivate=false (default): %s must be blocked", ip)
		}
	}
}

// AllowPrivate() exposes the runtime toggle for startup logging.
// Trivial, but pinned so a refactor can't silently flip the return.
func TestAllowPrivate_ReturnsCurrentToggle(t *testing.T) {
	prev := allowPrivate
	defer func() { allowPrivate = prev }()

	allowPrivate = true
	if !AllowPrivate() {
		t.Error("AllowPrivate() should return true when allowPrivate is true")
	}
	allowPrivate = false
	if AllowPrivate() {
		t.Error("AllowPrivate() should return false when allowPrivate is false")
	}
}
