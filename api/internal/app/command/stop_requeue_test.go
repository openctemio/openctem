package command

import (
	"context"
	"encoding/json"
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// stopRepo holds one running command; requeue says whether it was
// stop-requested.
type stopRepo struct {
	commanddom.Repository
	cmd     *commanddom.Command
	requeue bool
	failed  bool
}

func (r *stopRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*commanddom.Command, error) {
	if r.cmd.TenantID != tenantID || r.cmd.ID != id {
		return nil, shared.ErrNotFound
	}
	c := *r.cmd
	return &c, nil
}

func (r *stopRepo) RequeueStopped(context.Context, *commanddom.Command, commanddom.Fence, string) (bool, error) {
	return r.requeue, nil
}

func (r *stopRepo) FencedUpdate(_ context.Context, cmd *commanddom.Command, _ commanddom.Fence) (bool, error) {
	r.failed = cmd.Status == commanddom.CommandStatusFailed
	return true, nil
}

// A task the platform asked to stop as stalled that its sensor reports
// failed (nothing finished) is re-queued, not failed, so the step is not
// failed for a stall; any other failure fails as before.
func TestFail_StopRequestedIsRequeued(t *testing.T) {
	for _, stopRequested := range []bool{true, false} {
		cmd, sensor := runningStopScan(t)
		repo := &stopRepo{cmd: cmd, requeue: stopRequested}
		svc := NewService(repo, logger.NewNop())
		out, err := svc.Fail(context.Background(), FailInput{TenantID: cmd.TenantID.String(), SensorID: sensor.String(),
			CommandID: cmd.ID.String(), ErrorMessage: "scan failed: context canceled"})
		if err != nil {
			t.Fatal(err)
		}
		if stopRequested && (out.Status != commanddom.CommandStatusPending || repo.failed) {
			t.Fatalf("stop-requested: status %s failed %v", out.Status, repo.failed)
		}
		if !stopRequested && (out.Status != commanddom.CommandStatusFailed || !repo.failed) {
			t.Fatalf("not stop-requested: status %s failed %v", out.Status, repo.failed)
		}
	}
}

func runningStopScan(t *testing.T) (*commanddom.Command, shared.ID) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"scanner": "httpx", "targets": []string{"https://a.example"}})
	cmd, err := commanddom.NewCommand(shared.NewID(), commanddom.CommandTypeScan, commanddom.CommandPriorityNormal, payload)
	if err != nil {
		t.Fatal(err)
	}
	sensor := shared.NewID()
	cmd.SetSensorID(sensor)
	cmd.Start()
	return cmd, sensor
}
