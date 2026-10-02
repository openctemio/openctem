package jobs

import (
	"context"
	"log/slog"
	"testing"

	"github.com/hibiken/asynq"

	"github.com/openctemio/api/pkg/domain/shared"
)

func TestGitHubSyncHandler_CallsSyncer(t *testing.T) {
	// stubSyncer (jira_sync_tasks_test.go) satisfies GitHubStatusSyncer too —
	// both interfaces share the SyncFindingStatus signature.
	syncer := &stubSyncer{}
	h := NewGitHubSyncTaskHandler(syncer, slog.Default())

	tid, fid := shared.NewID(), shared.NewID()
	task, err := NewGitHubSyncFindingStatusTask(GitHubSyncFindingStatusPayload{
		TenantID:  tid.String(),
		FindingID: fid.String(),
	})
	if err != nil {
		t.Fatalf("NewGitHubSyncFindingStatusTask: %v", err)
	}

	if err := h.HandleSyncFindingStatus(context.Background(), task); err != nil {
		t.Fatalf("HandleSyncFindingStatus: %v", err)
	}
	if syncer.calls != 1 || syncer.tenantID != tid || syncer.finding != fid {
		t.Fatalf("syncer not invoked with the right IDs: calls=%d", syncer.calls)
	}
}

func TestGitHubSyncHandler_BadPayloadDoesNotCallSyncer(t *testing.T) {
	syncer := &stubSyncer{}
	h := NewGitHubSyncTaskHandler(syncer, slog.Default())

	bad := asynq.NewTask(TypeGitHubSyncFindingStatus, []byte("not-json"))
	if err := h.HandleSyncFindingStatus(context.Background(), bad); err == nil {
		t.Fatal("expected an error on unparseable payload")
	}
	if syncer.calls != 0 {
		t.Fatalf("syncer must not be called on bad payload; calls=%d", syncer.calls)
	}
}

func TestGitHubSyncHandler_InvalidIDsSkipRetry(t *testing.T) {
	syncer := &stubSyncer{}
	h := NewGitHubSyncTaskHandler(syncer, slog.Default())

	task, err := NewGitHubSyncFindingStatusTask(GitHubSyncFindingStatusPayload{
		TenantID:  "not-a-uuid",
		FindingID: shared.NewID().String(),
	})
	if err != nil {
		t.Fatalf("NewGitHubSyncFindingStatusTask: %v", err)
	}
	if err := h.HandleSyncFindingStatus(context.Background(), task); err == nil {
		t.Fatal("expected an error on invalid tenant_id")
	}
	if syncer.calls != 0 {
		t.Fatalf("syncer must not be called on invalid ids; calls=%d", syncer.calls)
	}
}
