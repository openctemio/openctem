package jira

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// TestTicketDescription_PrivateKeyBodyNeverLeaks: the same check as the
// GitHub issue body, on the Jira description (finding text and brief).
func TestTicketDescription_PrivateKeyBodyNeverLeaks(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // test-only key shape
	if err != nil {
		t.Fatal(err)
	}
	key := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh, "key in repo")
	if err != nil {
		t.Fatal(err)
	}
	f.SetDescription("Hard-coded key:\n" + key)
	f.SetRemediation(&vulnerability.FindingRemediation{SuccessCriteria: "rotate [~admin] key " + key + " see [x|https://evil.test]"})
	desc := ticketDescription(f)
	for _, line := range strings.Split(key, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(desc, line) {
			t.Fatalf("private key line leaked into the Jira description: %q", line)
		}
	}
	// The brief is wiki-encoded: it sits in a {noformat} block, URLs defanged.
	if strings.Contains(desc, "https://evil.test") {
		t.Fatalf("brief link not defanged:\n%s", desc)
	}
	if strings.Count(desc, "{noformat}") < 4 {
		t.Fatalf("brief not placed in a noformat block:\n%s", desc)
	}
}
