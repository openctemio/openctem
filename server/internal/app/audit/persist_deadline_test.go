package audit_test

import (
	"context"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// ctxCheckingRepo records whether Create ran on a live context, the way the
// Postgres repository fails with "context deadline exceeded" on a dead one.
type ctxCheckingRepo struct {
	auditdom.Repository
	stored  int
	ctxErr  error
	hasDead bool
}

func (r *ctxCheckingRepo) Create(ctx context.Context, _ *auditdom.AuditLog) error {
	if err := ctx.Err(); err != nil {
		r.ctxErr = err
		return err
	}
	_, r.hasDead = ctx.Deadline()
	r.stored++
	return nil
}

// The database chains the row itself, so the service appends nothing.
func (r *ctxCheckingRepo) ChainsInDatabase() bool { return true }

// The change an audit event records has already happened when LogEvent runs.
// A request whose deadline passed in between (a slow channel test answered
// 504 after the integration was stored) used to lose the audit row with
// "failed to persist audit log: context deadline exceeded".
func TestLogEvent_PersistsAfterTheRequestDeadline(t *testing.T) {
	repo := &ctxCheckingRepo{}
	svc := auditapp.NewAuditService(repo, logger.NewNop())

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	ev := auditapp.NewSuccessEvent(auditdom.ActionScopeTargetCreated, auditdom.ResourceTypeScopeTarget, "t-1")
	if err := svc.LogEvent(ctx, auditapp.AuditContext{TenantID: "01a21c21-5096-79db-a340-635ed08cdb20"}, ev); err != nil {
		t.Fatalf("LogEvent after the request deadline: %v (repo saw %v)", err, repo.ctxErr)
	}
	if repo.stored != 1 {
		t.Fatalf("stored %d audit rows, want 1", repo.stored)
	}
	if !repo.hasDead {
		t.Fatal("the audit write has no deadline of its own; a stuck database would hold the caller")
	}
}

// A cancelled request (the client went away after the write) is recorded too.
func TestLogEvent_PersistsAfterTheRequestIsCancelled(t *testing.T) {
	repo := &ctxCheckingRepo{}
	svc := auditapp.NewAuditService(repo, logger.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ev := auditapp.NewSuccessEvent(auditdom.ActionScopeTargetCreated, auditdom.ResourceTypeScopeTarget, "t-2")
	if err := svc.LogEvent(ctx, auditapp.AuditContext{}, ev); err != nil || repo.stored != 1 {
		t.Fatalf("LogEvent after cancel: err %v stored %d, want nil and 1", err, repo.stored)
	}
}
