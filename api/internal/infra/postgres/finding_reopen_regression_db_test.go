package postgres

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// RFC-039 §6.5: a scan that re-detects a finding a person resolved reopens it,
// and the reopen clears resolved_by / resolution / the closure on the row.
// Before this change the regression's activity said only
// {"reason":"finding_detected_again"}: who had fixed it, and how, was gone. A
// scan re-detecting a validated_fixed finding left it validated_fixed.
func TestAutoReopenBatch_RegressionKeepsPreviousResolverInActivity(t *testing.T) {
	db := openReopenDB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	resolver := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'resolver')`,
		resolver.String(), resolver.String()+"@reopen.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, resolver.String())
	})

	humanID, humanFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "resolved", "patched in release 4.2")
	if _, err := db.ExecContext(ctx, `UPDATE findings SET resolved_by = $2, closure_reason = 'fixed', verification = 'security_review' WHERE id = $1`,
		humanID.String(), resolver.String()); err != nil {
		t.Fatal(err)
	}
	downgradedID, downgradedFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "validated_fixed", "")

	// The reopen writes its own timeline entry in the same transaction, with
	// the scan from the context's evidence.
	scanCtx := vulnerability.WithTransitionEvidence(ctx, map[string]any{"scanner": "nuclei", "scan_id": "report-9"})
	reopened, err := repo.AutoReopenByFingerprintsBatch(scanCtx, tenantID, []string{humanFP, downgradedFP})
	if err != nil {
		t.Fatalf("AutoReopenByFingerprintsBatch: %v", err)
	}
	if got := statusOf(ctx, t, db, humanID); got != "confirmed" {
		t.Errorf("human-resolved finding status = %s, want confirmed", got)
	}
	if got := statusOf(ctx, t, db, downgradedID); got != "confirmed" {
		t.Errorf("validated_fixed finding a scan saw again: status = %s, want confirmed", got)
	}

	rf, ok := reopened[humanFP]
	if !ok {
		t.Fatalf("human-resolved finding not returned as reopened: %+v", reopened)
	}
	if rf.PreviousResolvedBy == nil || *rf.PreviousResolvedBy != resolver ||
		rf.PreviousResolution != "patched in release 4.2" || rf.PreviousClosureReason != "fixed" || rf.PreviousVerification != "security_review" ||
		string(rf.PreviousStatus) != "resolved" || rf.PreviousResolvedAt == nil {
		t.Errorf("reopen lost what it cleared: %+v", rf)
	}

	var raw []byte
	if err := db.QueryRowContext(ctx,
		`SELECT changes FROM finding_activities WHERE finding_id = $1 AND activity_type = 'auto_reopened'`,
		humanID.String()).Scan(&raw); err != nil {
		t.Fatalf("read activity: %v", err)
	}
	var changes map[string]any
	if err := json.Unmarshal(raw, &changes); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"reason": "regression_detected_again", "previous_resolved_by": resolver.String(),
		"previous_resolution": "patched in release 4.2", "previous_closure_reason": "fixed",
		"previous_verification": "security_review",
		"scanner":               "nuclei", "scan_id": "report-9",
	} {
		if changes[k] != want {
			t.Errorf("activity changes[%q] = %v, want %q", k, changes[k], want)
		}
	}
}
