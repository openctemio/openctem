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

// Boilerplate advice never forms a group: findings of different
// vulnerabilities that a scanner gave the same generic text stay apart.
func TestDeriveKey_BoilerplateNeverGroups(t *testing.T) {
	for _, text := range []string{
		"Apply the suggested fix code.",
		"Follow the remediation steps on each finding.",
		"Upgrade to the latest version.",
		"Apply the suggested fix code.\nSee https://example.com/docs/v2/1234 for details.",
		"Review the code. Validate all input. Use parameterized queries.",
	} {
		for _, src := range []string{"sast", "dast", "va", "manual"} {
			if key, _, ok := DeriveKey(KeyInput{Source: src, RuleID: "r1", SolutionText: text}); ok {
				t.Errorf("source %s text %q formed key %q", src, text, key)
			}
		}
	}
}

func TestDeriveKey_SpecificSentencesOnly(t *testing.T) {
	a, ta, okA := DeriveKey(KeyInput{Source: "va", SolutionText: "Upgrade Jenkins to 2.442 or later."})
	b, _, okB := DeriveKey(KeyInput{Source: "va", SolutionText: "Upgrade Jenkins to 2.442 or later.\nRestart the service afterwards."})
	if !okA || !okB || a != b {
		t.Fatalf("boilerplate around one specific fix must not split the group: %q vs %q", a, b)
	}
	if ta != "Upgrade Jenkins to 2.442 or later." {
		t.Fatalf("title = %q", ta)
	}
	// The title is the specific sentence, not the boilerplate before it.
	_, tt, ok := DeriveKey(KeyInput{Source: "va", SolutionText: "Apply the vendor patch. Install MS17-010 on every host."})
	if !ok || tt != "Install MS17-010 on every host." {
		t.Fatalf("title = %q ok=%v", tt, ok)
	}
	// Advisory ids count as specific.
	for _, s := range []string{"Apply the MS17-010 security update.", "Install KB5034441 from the catalog", "Apply RHSA-2024:1234 errata now"} {
		if _, _, ok := DeriveKey(KeyInput{Source: "va", SolutionText: s}); !ok {
			t.Errorf("%q should be specific", s)
		}
	}
	// A bare number is not a version.
	if _, _, ok := DeriveKey(KeyInput{Source: "va", SolutionText: "Close port 8080 on the firewall"}); ok {
		t.Error("a port number is not a fix identity")
	}
}

func TestDeriveKey_RuleScopedForCode(t *testing.T) {
	text := "Use bcrypt 4.0.1 or later for password hashing"
	a, _, okA := DeriveKey(KeyInput{Source: "sast", RuleID: "go.weak-hash", SolutionText: text})
	b, _, okB := DeriveKey(KeyInput{Source: "sast", RuleID: "go.missing-user", SolutionText: text})
	if !okA || !okB || a == b {
		t.Fatalf("two code rules must not share a fix: %q %q", a, b)
	}
	if _, _, ok := DeriveKey(KeyInput{Source: "sast", SolutionText: text}); ok {
		t.Fatal("a code finding without a rule id gets no solution key")
	}
	// Host findings group across rules (one patch, many plugins).
	x, _, _ := DeriveKey(KeyInput{Source: "va", RuleID: "p1", SolutionText: "Upgrade OpenSSL to 3.0.7"})
	y, _, _ := DeriveKey(KeyInput{Source: "va", RuleID: "p2", SolutionText: "Upgrade OpenSSL to 3.0.7"})
	if x != y {
		t.Fatal("host findings with the same specific fix group across plugins")
	}
}
