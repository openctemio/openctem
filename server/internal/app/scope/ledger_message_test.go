package scope

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/jobsign"
)

// The divergence warning says what the signer does with such jobs: in audit
// mode they are still signed (nothing refused yet), in enforce mode refused.
func TestDivergedLedgerMessage_ByMode(t *testing.T) {
	audit := divergedLedgerMessage(jobsign.LedgerAudit)
	if !strings.Contains(audit, "signed and logged") || strings.Contains(audit, "for it are refused") {
		t.Fatalf("audit wording: %q", audit)
	}
	if enforce := divergedLedgerMessage(jobsign.LedgerEnforce); !strings.Contains(enforce, "jobs for it are refused") ||
		strings.Contains(enforce, "signed and logged") {
		t.Fatalf("enforce wording: %q", enforce)
	}
}

// The API cannot tell scope in effect before the ledger existed (an
// upgraded installation whose bootstrap was not run) from scope written past
// the hook, so the warning names both ways out in every mode: the bootstrap,
// whose import needs -replace because the ledger already holds this
// organization (only such organizations are synced), and taking an entry out
// of effect and approving it again (saving it unchanged sends nothing).
func TestDivergedLedgerMessage_NamesBothRemedies(t *testing.T) {
	for _, mode := range []string{jobsign.LedgerAudit, jobsign.LedgerEnforce} {
		msg := divergedLedgerMessage(mode)
		for _, want := range []string{"ledger bootstrap", "-replace", "taken out of effect and approved again"} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s wording lacks %q: %q", mode, want, msg)
			}
		}
		if strings.Contains(msg, " · ") {
			t.Errorf("%s wording uses a middot separator: %q", mode, msg)
		}
	}
}
