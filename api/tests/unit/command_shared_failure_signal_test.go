package unit

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type recordingSharedFailures struct{ by map[shared.ID]int }

func (r *recordingSharedFailures) ObserveSharedFailure(_ context.Context, tenantID shared.ID) {
	r.by[tenantID]++
}

// A failed shared (platform) job counts for its organization's anomaly
// signal; an organization sensor's failed job does not.
func TestCommandFail_SharedJobFailureSignal(t *testing.T) {
	for _, platform := range []bool{true, false} {
		repo := newCmdMockRepo()
		svc := newCmdTestService(repo)
		obs := &recordingSharedFailures{by: map[shared.ID]int{}}
		svc.SetSharedFailureObserver(obs)
		tenantID := newCmdTestTenantID()
		sensorID := shared.NewID()
		cmd, err := svc.Create(context.Background(), command.CreateInput{
			TenantID: tenantID, SensorID: sensorID.String(), Type: "scan", Priority: "normal",
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		repo.commands[cmd.ID.String()].IsPlatformJob = platform
		if _, err := svc.Fail(context.Background(), command.FailInput{
			TenantID: tenantID, SensorID: sensorID.String(), CommandID: cmd.ID.String(), ErrorMessage: "connection refused",
		}); err != nil {
			t.Fatalf("fail: %v", err)
		}
		tid, _ := shared.IDFromString(tenantID)
		want := 0
		if platform {
			want = 1
		}
		if obs.by[tid] != want {
			t.Fatalf("platform=%v: failures counted = %d, want %d", platform, obs.by[tid], want)
		}
	}
}
