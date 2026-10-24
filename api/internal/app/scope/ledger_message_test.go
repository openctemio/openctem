package scope

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// The divergence warning says what the signer does with such jobs: in audit
// mode they are still signed (nothing refused yet), in enforce mode refused.
func TestDivergedLedgerMessage_ByMode(t *testing.T) {
	audit := divergedLedgerMessage(jobsign.LedgerAudit)
	if !strings.Contains(audit, "signed and logged") || strings.Contains(audit, "are refused until") {
		t.Fatalf("audit wording: %q", audit)
	}
	if enforce := divergedLedgerMessage(jobsign.LedgerEnforce); !strings.Contains(enforce, "refused until it is approved again") {
		t.Fatalf("enforce wording: %q", enforce)
	}
}
