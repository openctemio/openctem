package ticketing

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A stored GitHub credential that does not decrypt under the configured key
// (a key mismatch, or a legacy plaintext row) is never sent to GitHub as is
// (RFC-049 F-8): the integration is skipped.
func TestGitHubTicket_UndecryptableCredentialIsNotUsed(t *testing.T) {
	cipher, err := crypto.NewCipherFromKey("ab00112233445566778899aabbccddeeff00112233445566778899aabbccddee", "hex")
	if err != nil {
		t.Fatal(err)
	}
	tenantID := shared.NewID()
	finding := newTestFinding(t, vulnerability.FindingSourceSAST)
	intg := connectedGitHubIntegration(t, tenantID) // plaintext value, not ciphertext
	ic := &fakeIssueCreator{}
	var usedToken string
	s := NewGitHubTicketService(&fakeFindingRepo{finding: finding},
		&fakeIntegrationRepo{list: []*integration.Integration{intg}}, cipher, logger.NewNop())
	s.clientFactory = func(token, _ string) (issueCreator, error) { usedToken = token; return ic, nil }

	_, err = s.CreateTicketFromFinding(context.Background(), GitHubTicketInput{
		TenantID: tenantID.String(), FindingID: finding.ID().String(), Owner: "octo", Repo: "repo",
	})
	if !errors.Is(err, ErrNoGitHubIntegration) {
		t.Fatalf("err = %v, want ErrNoGitHubIntegration", err)
	}
	if usedToken != "" || ic.calls != 0 {
		t.Fatalf("undecryptable credential used: token=%q calls=%d", usedToken, ic.calls)
	}
}
