package jobs

import (
	"context"
	"log/slog"
	"testing"

	"github.com/hibiken/asynq"

	"github.com/openctemio/api/pkg/domain/shared"
)

type stubSyncer struct {
	calls    int
	tenantID shared.ID
	finding  shared.ID
	err      error
}

func (s *stubSyncer) SyncFindingStatus(_ context.Context, tenantID, findingID shared.ID) error {
	s.calls++
	s.tenantID, s.finding = tenantID, findingID
	return s.err
}

func TestJiraSyncHandler_CallsSyncer(t *testing.T) {
	syncer := &stubSyncer{}
	h := NewJiraSyncTaskHandler(syncer, slog.Default())

	tid, fid := shared.NewID(), shared.NewID()
	task, err := NewJiraSyncFindingStatusTask(JiraSyncFindingStatusPayload{
		TenantID:  tid.String(),
		FindingID: fid.String(),
	})
	if err != nil {
		t.Fatalf("NewJiraSyncFindingStatusTask: %v", err)
	}

	if err := h.HandleSyncFindingStatus(context.Background(), task); err != nil {
		t.Fatalf("HandleSyncFindingStatus: %v", err)
	}
	if syncer.calls != 1 || syncer.tenantID != tid || syncer.finding != fid {
		t.Fatalf("syncer not invoked with the right IDs: calls=%d", syncer.calls)
	}
}

func TestJiraSyncHandler_BadPayloadDoesNotCallSyncer(t *testing.T) {
	syncer := &stubSyncer{}
	h := NewJiraSyncTaskHandler(syncer, slog.Default())

	// asynq.NewTask with garbage payload (not valid JSON for the payload struct).
	bad := asynq.NewTask(TypeJiraSyncFindingStatus, []byte("not-json"))
	if err := h.HandleSyncFindingStatus(context.Background(), bad); err == nil {
		t.Fatal("expected an error on unparseable payload")
	}
	if syncer.calls != 0 {
		t.Fatalf("syncer must not be called on bad payload; calls=%d", syncer.calls)
	}
}
