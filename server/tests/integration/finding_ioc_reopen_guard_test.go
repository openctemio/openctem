package integration

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The IOC reopen re-checks the status in its UPDATE: a resolved finding
// reopens (with its timeline entry); one someone changed since it was read is
// not overwritten; another tenant cannot reopen it. A review flag must pair
// a finding with its own tenant.
func TestIOCReopen_GuardedAndTenantPaired(t *testing.T) {
	f := newReviewFixture(t)
	ctx := context.Background()
	repo := postgres.NewFindingRepository(f.pdb)
	moveCtx := vulnerability.WithStatusTransition(ctx, vulnerability.StatusTransition{Source: "ioc_correlator", Reason: "ioc_match"})

	resolved := f.finding(t, f.tenant, f.asset, "ioc-resolved", "resolved")
	if moved, err := repo.ReopenResolved(moveCtx, f.other, resolved); err != nil || moved {
		t.Errorf("another tenant reopened it: moved=%v err=%v", moved, err)
	}
	if moved, err := repo.ReopenResolved(moveCtx, f.tenant, resolved); err != nil || !moved {
		t.Fatalf("resolved finding: moved=%v err=%v", moved, err)
	}
	var entries int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2 AND source = 'ioc_correlator'`,
		f.tenant.String(), resolved.String()).Scan(&entries); err != nil {
		t.Fatal(err)
	}
	if entries != 1 {
		t.Errorf("timeline entries = %d, want 1", entries)
	}

	// Changed since it was read (a person accepted the risk): left alone.
	changed := f.finding(t, f.tenant, f.asset, "ioc-changed", "accepted")
	if moved, err := repo.ReopenResolved(moveCtx, f.tenant, changed); err != nil || moved {
		t.Errorf("a finding no longer resolved was reopened: moved=%v err=%v", moved, err)
	}
	if st, _, _ := f.state(t, changed); st != "accepted" {
		t.Errorf("status = %s, want accepted", st)
	}

	// A flag pairing the finding with another tenant is refused.
	if _, err := f.db.Exec(`INSERT INTO finding_decision_reviews (tenant_id, finding_id, decision_status, reason)
		VALUES ($1, $2, 'accepted', 'ioc_match')`, f.other.String(), changed.String()); err == nil {
		t.Error("a review flag paired a finding with another tenant")
	}
}
