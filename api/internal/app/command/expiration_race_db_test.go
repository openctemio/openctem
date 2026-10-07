package command

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The expiration checker reads expired rows (FindExpired) and later writes each
// one back. Between the read and the write a sensor can pick the command up or
// finish it, and with two API replicas both checkers read the same rows. The
// write was an unconditional full-row Update of the stale snapshot, so it:
//   - flipped a command the sensor had just started (or completed) back to
//     'expired', erasing its started_at/result, and
//   - failed the owning workflow step although the sensor was running it, and
//     failed it once per replica.
//
// These tests take the snapshot the checker would have read, change the row the
// way a sensor or the other replica would, then let the checker act on the
// snapshot.

func seedExpiredScanRunCommand(ctx context.Context, t *testing.T, db *postgres.DB, repo *postgres.CommandRepository, tenantID shared.ID, runID, stepKey string) *commanddom.Command {
	t.Helper()
	svc := NewService(repo, logger.NewNop())
	created, err := svc.Create(ctx, CreateInput{
		TenantID: tenantID.String(),
		Type:     string(commanddom.CommandTypeScan),
		Payload:  scanRunPayload(t, runID, stepKey),
	})
	if err != nil {
		t.Fatalf("create command: %v", err)
	}
	shiftSeconds := int64((commanddom.DefaultCommandTTL + time.Hour).Seconds())
	if _, err := db.ExecContext(ctx,
		`UPDATE commands SET expires_at = expires_at - ($2 || ' seconds')::INTERVAL WHERE id = $1`,
		created.ID.String(), shiftSeconds); err != nil {
		t.Fatalf("shift expiry: %v", err)
	}
	// The snapshot the checker works from.
	expired, err := repo.FindExpired(ctx)
	if err != nil {
		t.Fatalf("find expired: %v", err)
	}
	for _, c := range expired {
		if c.ID == created.ID {
			return c
		}
	}
	t.Fatalf("seeded command %s not returned by FindExpired", created.ID)
	return nil
}

func newCheckerWithFailer(repo *postgres.CommandRepository) (*ExpirationChecker, *stubStepFailer) {
	failer := &stubStepFailer{}
	checker := NewExpirationChecker(repo, nil, ExpirationCheckerConfig{}, logger.NewNop())
	checker.scanRunService = failer
	return checker, failer
}

func stepFailuresFor(f *stubStepFailer, runID string) int {
	n := 0
	for _, c := range f.calls {
		if c.runID == runID {
			n++
		}
	}
	return n
}

func TestExpirationChecker_DoesNotOverwriteACommandPickedUpMeanwhile(t *testing.T) {
	ctx := context.Background()
	db := openCommandDB(t)
	repo := postgres.NewCommandRepository(db)
	tenantID := seedExpiryTenant(ctx, t, db)

	for _, tc := range []struct {
		name, setSQL, wantStatus string
	}{
		{"started by a sensor", `UPDATE commands SET status='running', started_at=now() WHERE id=$1`, "running"},
		{"completed by a sensor", `UPDATE commands SET status='completed', started_at=now(), completed_at=now() WHERE id=$1`, "completed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runID := shared.NewID().String()
			snapshot := seedExpiredScanRunCommand(ctx, t, db, repo, tenantID, runID, "race-step")

			if _, err := db.ExecContext(ctx, tc.setSQL, snapshot.ID.String()); err != nil {
				t.Fatalf("simulate sensor: %v", err)
			}

			checker, failer := newCheckerWithFailer(repo)
			checker.handleExpiredCommand(ctx, snapshot, expiryReasonCommand)

			var status string
			var startedAt *time.Time
			if err := db.QueryRowContext(ctx, `SELECT status, started_at FROM commands WHERE id=$1`,
				snapshot.ID.String()).Scan(&status, &startedAt); err != nil {
				t.Fatalf("read back: %v", err)
			}
			if status != tc.wantStatus || startedAt == nil {
				t.Fatalf("status=%q started_at=%v after expiry of a stale snapshot, want %q with started_at kept",
					status, startedAt, tc.wantStatus)
			}
			if n := stepFailuresFor(failer, runID); n != 0 {
				t.Fatalf("pipeline step failed %d times although the sensor had the command", n)
			}
		})
	}
}

func TestExpirationChecker_TwoReplicasFailTheStepOnce(t *testing.T) {
	ctx := context.Background()
	db := openCommandDB(t)
	repo := postgres.NewCommandRepository(db)
	tenantID := seedExpiryTenant(ctx, t, db)

	runID := shared.NewID().String()
	snapshot := seedExpiredScanRunCommand(ctx, t, db, repo, tenantID, runID, "race-step")
	// The second replica read the same row before either wrote.
	snapshot2 := *snapshot

	checker, failer := newCheckerWithFailer(repo)
	checker.handleExpiredCommand(ctx, snapshot, expiryReasonCommand)
	checker.handleExpiredCommand(ctx, &snapshot2, expiryReasonCommand)

	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM commands WHERE id=$1`, snapshot.ID.String()).Scan(&status); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if status != string(commanddom.CommandStatusExpired) {
		t.Fatalf("status = %q, want expired", status)
	}
	if n := stepFailuresFor(failer, runID); n != 1 {
		t.Fatalf("pipeline step failed %d times for one expired command, want 1", n)
	}
}
