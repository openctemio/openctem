package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	const fpA = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	const fpB = "ffb2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	django := func(installed string) KeyInput {
		return KeyInput{Source: "sca", Ecosystem: "pypi", PackageName: "Django", InstalledVersion: installed,
			FixedVersions: []string{"5.2.8", "4.2.30"}}
	}
	cases := []struct {
		name      string
		in        KeyInput
		wantKey   string
		wantTitle string
		wantOK    bool
	}{
		{"upgrade by nearest fix", django("4.2.20"), "upgrade:pypi:django:4.2.30", "Upgrade Django to 4.2.30", true},
		{"another installed version, same fix", django("4.2.25"), "upgrade:pypi:django:4.2.30", "Upgrade Django to 4.2.30", true},
		{"other release line", django("5.2.1"), "upgrade:pypi:django:5.2.8", "Upgrade Django to 5.2.8", true},
		{"package without a fix and generic text", KeyInput{Source: "sca", Ecosystem: "npm", PackageName: "lodash",
			InstalledVersion: "4.17.20", SolutionText: "Upgrade to the latest version"}, "", "", false},
		{"secret keyed by fingerprint", KeyInput{Source: "secret", SecretFingerprint: fpA, SecretType: "aws_access_key",
			SolutionText: "Rotate the secret"}, "rotate:secret:" + fpA, "Rotate the leaked aws_access_key secret a1b2c3d4", true},
		{"secret without fingerprint never grouped by text", KeyInput{Source: "secret",
			SolutionText: "Rotate the credential issued on 2024-01-01 and purge history"}, "", "", false},
		{"secret type with non-hex fingerprint", KeyInput{FindingType: "secret", SecretFingerprint: "not-hex"}, "", "", false},
		{"pentest never grouped", KeyInput{Source: "pentest", SolutionText: "Upgrade OpenSSL to 3.0.7 on every host"}, "", "", false},
		{"generic solution text", KeyInput{Source: "dast", SolutionText: "Apply the vendor patch."}, "", "", false},
		{"short solution text", KeyInput{Source: "dast", SolutionText: "Patch 1"}, "", "", false},
		{"text without a version or id", KeyInput{Source: "dast", SolutionText: "Configure the web server to send security headers"}, "", "", false},
		{"specific solution text", KeyInput{Source: "va", SolutionText: "  Upgrade OpenSSL to 3.0.7  "},
			"sol:va:" + sha256Hex("upgrade openssl to 3.0.7"), "Upgrade OpenSSL to 3.0.7", true},
		{"empty", KeyInput{}, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, title, ok := DeriveKey(tc.in)
			if ok != tc.wantOK || key != tc.wantKey || (tc.wantTitle != "" && title != tc.wantTitle) {
				t.Fatalf("DeriveKey = (%q, %q, %v), want (%q, %q, %v)", key, title, ok, tc.wantKey, tc.wantTitle, tc.wantOK)
			}
		})
	}
	// Two different secrets never share a key.
	a, _, _ := DeriveKey(KeyInput{Source: "secret", SecretFingerprint: fpA})
	b, _, _ := DeriveKey(KeyInput{Source: "secret", SecretFingerprint: fpB})
	if a == b {
		t.Fatalf("two secrets share key %q", a)
	}
	// The same text from two sources forms two groups.
	x, _, _ := DeriveKey(KeyInput{Source: "va", SolutionText: "Upgrade OpenSSL to 3.0.7"})
	y, _, _ := DeriveKey(KeyInput{Source: "container", SolutionText: "Upgrade OpenSSL to 3.0.7"})
	if x == y {
		t.Fatalf("sources share key %q", x)
	}
	// No title is a raw id.
	_, title, _ := DeriveKey(django("4.2.20"))
	if strings.Count(title, "-") >= 4 {
		t.Fatalf("title looks like an id: %q", title)
	}
}

func TestKeyKind(t *testing.T) {
	for in, want := range map[string]string{"upgrade:pypi:django:4.2.30": "upgrade", "sol:va:abc": "sol", "rotate:secret:ab": "rotate", "x": "x"} {
		if got := KeyKind(in); got != want {
			t.Errorf("KeyKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestDeriveKey_NoSlash(t *testing.T) {
	for _, in := range []KeyInput{
		{Source: "sca", Ecosystem: "npm", PackageName: "@scope/pkg", InstalledVersion: "1.0.0", FixedVersions: []string{"1.0.1"}},
		{Source: "sca", Ecosystem: "go", PackageName: "github.com/acme/lib", InstalledVersion: "1.2.0", FixedVersions: []string{"1.2.3"}},
	} {
		key, title, ok := DeriveKey(in)
		if !ok || strings.Contains(key, "/") {
			t.Fatalf("key %q (ok %v) must exist and hold no slash", key, ok)
		}
		if !strings.Contains(title, in.PackageName) {
			t.Fatalf("title %q must name %q", title, in.PackageName)
		}
	}
}
