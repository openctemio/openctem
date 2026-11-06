package ticketing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// TestBuildIssueBody_PrivateKeyBodyNeverLeaks puts a real-shaped PEM private
// key in a finding description and in the operator brief: no line of the key
// (header, base64 body, footer) may reach the GitHub issue body.
func TestBuildIssueBody_PrivateKeyBodyNeverLeaks(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // test-only key shape
	if err != nil {
		t.Fatal(err)
	}
	key := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))

	f := newTestFinding(t, vulnerability.FindingSourceSAST)
	f.SetDescription("Hard-coded key in deploy/key.pem:\n" + key)
	f.SetRemediation(&vulnerability.FindingRemediation{SuccessCriteria: "rotate this key:\n" + key})
	body := buildIssueBody(f)

	for _, line := range strings.Split(key, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(body, line) {
			t.Fatalf("private key line leaked into the issue body: %q", line)
		}
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Fatalf("expected a redaction marker:\n%s", body)
	}
}
