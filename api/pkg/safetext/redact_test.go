package safetext

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// genPEMKey returns a freshly generated RSA private key in PEM form, so the
// tests use a real key shape without a committed key.
func genPEMKey(t testing.TB) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // test-only key shape
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

// assertNoKeyLine fails when any base64 body line of the PEM key appears in out.
func assertNoKeyLine(t testing.TB, key, out string) {
	t.Helper()
	for _, line := range strings.Split(key, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		if strings.Contains(out, line) {
			t.Fatalf("a private key line survived redaction: %q\nout:\n%s", line, out)
		}
	}
	if strings.Contains(out, "PRIVATE KEY-----") {
		t.Fatalf("a private key header or footer survived:\n%s", out)
	}
}

func TestRedactSecrets_PEMBlockRemovedWhole(t *testing.T) {
	key := genPEMKey(t)
	out := RedactSecrets("config file:\n" + key + "\nend of file")
	assertNoKeyLine(t, key, out)
	if !strings.Contains(out, "config file:") || !strings.Contains(out, "end of file") {
		t.Fatalf("surrounding text lost: %q", out)
	}
}

func TestRedactSecrets_TruncatedPEMBody(t *testing.T) {
	key := genPEMKey(t)
	lines := strings.Split(strings.TrimSpace(key), "\n")
	truncated := strings.Join(lines[:len(lines)/2], "\n") // no footer
	assertNoKeyLine(t, truncated, RedactSecrets("leaked: "+truncated))
}

func TestRedactSecrets_ECAndPKCS8Keys(t *testing.T) {
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	assertNoKeyLine(t, key, RedactSecrets(key))
}

func TestRedactSecrets_Shapes(t *testing.T) {
	cases := []struct{ in, secret, keep string }{
		{"key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE", "here"},
		{"temp key ASIAIOSFODNN7EXAMPLE here", "ASIAIOSFODNN7EXAMPLE", "here"},
		{"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36P here", "SflKxwRJSMeKKF2QT4fwpMeJf36P", "here"},
		{"gh ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 x", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "x"},
		{"pat github_pat_11ABCDEFG0123456789_abcdefghijklmnop x", "github_pat_11ABCDEFG0123456789_abcdefghijklmnop", "x"},
		{"slack xoxb-1234567890-abcdefghijkl x", "xoxb-1234567890-abcdefghijkl", "x"},
		{"google AIzaSyA1234567890abcdefghijklmnopqrstuv x", "AIzaSyA1234567890abcdefghijklmnopqrstuv", "x"},
		{"Authorization: Bearer abcdef0123456789abcdef x", "abcdef0123456789abcdef", "x"},
		{"password: hunter2supersecret", "hunter2supersecret", "password: [REDACTED]"},
		{"api_key=abcdef1234567890xyz", "abcdef1234567890xyz", "api_key=[REDACTED]"},
		{`db.password = "hunter2supersecret"`, "hunter2supersecret", "password"},
	}
	for _, c := range cases {
		got := RedactSecrets(c.in)
		if strings.Contains(got, c.secret) {
			t.Errorf("RedactSecrets(%q) kept the secret: %q", c.in, got)
		}
		if !strings.Contains(got, c.keep) {
			t.Errorf("RedactSecrets(%q) = %q, want %q kept", c.in, got, c.keep)
		}
	}
}

func TestRedactSecrets_BenignTextUntouched(t *testing.T) {
	for _, in := range []string{"", "This is a SQL injection in the login form.", "Upgrade django to 4.2.30 and redeploy."} {
		if got := RedactSecrets(in); got != in {
			t.Errorf("RedactSecrets(%q) = %q", in, got)
		}
	}
}
