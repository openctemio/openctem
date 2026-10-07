package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
)

// research/62 SG-9: a run that failed at queue time (no tool, incompatible
// targets, a stage that cannot be chained) fails the same way on a retry, so
// it is never offered for one.
func TestListPendingRetries_QueueTimeFailuresArePermanent_DB(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)

	for _, code := range []string{
		scanrun.FailureNoMatchingTool, scanrun.FailureIncompatibleTargets, scanrun.FailureStageNotChainable,
		scanrun.FailureCapabilityAmbiguous, scanrun.FailureNoSensorForTool, scanrun.FailurePolicyRefused,
	} {
		run := seedFinishedRun(ctx, t, db, tenantID, seedRetryScan(ctx, t, db, tenantID, 5), "failed", 0, "failed", code)
		if listedRuns(ctx, t, repo)[run] {
			t.Errorf("a run failed with %s was offered for retry", code)
		}
	}
	lost := seedFinishedRun(ctx, t, db, tenantID, seedRetryScan(ctx, t, db, tenantID, 5), "failed", 0, "failed", scanrun.FailureLeaseLost)
	if !listedRuns(ctx, t, repo)[lost] {
		t.Error("a transient failure (lease lost) must stay retryable")
	}
}

// A command whose lease was lost goes back to pending with its timestamps
// cleared but its dispatch attempts counted. Such a run was claimed: it must
// not be aborted as "no sensor ever took it" (NO_SENSOR, never retried).
func TestAbortUnclaimedRuns_LostLeaseIsNotUnclaimed_DB(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	scanID := seedRetryScan(ctx, t, db, tenantID, 0)

	requeued := seedActiveRun(ctx, t, db, tenantID, scanID, "manual", 2*time.Hour)
	seedRunCommand(ctx, t, db, tenantID, requeued, "pending", false, 1)

	if _, err := repo.AbortUnclaimedRuns(ctx, 4*time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	if s, _ := runStatus(ctx, t, db, requeued); s != "running" {
		t.Fatalf("a run whose command was claimed then requeued: status=%s, want running", s)
	}
}
