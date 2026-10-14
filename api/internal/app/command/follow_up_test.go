package command

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/openctemio/ctis/outcome"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// followUpRepo holds one running command and records how it was saved.
type followUpRepo struct {
	commanddom.Repository
	cmd      *commanddom.Command
	fenced   int
	followUp *commanddom.Command
}

func (r *followUpRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*commanddom.Command, error) {
	if r.cmd.TenantID != tenantID || r.cmd.ID != id {
		return nil, shared.ErrNotFound
	}
	c := *r.cmd
	return &c, nil
}

func (r *followUpRepo) FencedUpdate(context.Context, *commanddom.Command, commanddom.Fence) (bool, error) {
	r.fenced++
	return true, nil
}

func (r *followUpRepo) CompleteWithFollowUp(_ context.Context, _ *commanddom.Command, _ commanddom.Fence, fu *commanddom.Command) (bool, error) {
	r.followUp = fu
	return true, nil
}

func runningScan(t *testing.T, targets []string) (*commanddom.Command, shared.ID) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"scanner": "httpx", "targets": targets})
	cmd, err := commanddom.NewCommand(shared.NewID(), commanddom.CommandTypeScan, commanddom.CommandPriorityNormal, payload)
	if err != nil {
		t.Fatal(err)
	}
	sensor := shared.NewID()
	cmd.SetSensorID(sensor)
	cmd.Start()
	return cmd, sensor
}

// A completion that leaves targets unfinished queues a follow-up with only
// those targets; one that settles every target (or comes from a sensor
// without outcomes) is saved as before.
func TestComplete_FollowUpOnlyForUnfinished(t *testing.T) {
	targets := []string{"https://a.example", "https://b.example", "https://c.example"}
	cases := []struct {
		name   string
		result any
		want   []string
	}{
		{"partial", map[string]any{"target_outcomes": []outcome.Target{
			{Target: targets[0], State: outcome.Done},
			{Target: targets[1], State: outcome.Failed, Class: outcome.Unreachable},
			{Target: "https://other.example", State: outcome.Unfinished},
		}}, targets[2:]},
		{"all settled", map[string]any{"target_outcomes": []outcome.Target{
			{Target: targets[0], State: outcome.Done},
			{Target: targets[1], State: outcome.Done},
			{Target: targets[2], State: outcome.Skipped, Class: outcome.Refused},
		}}, nil},
		{"older sensor", map[string]any{"findings_count": 2}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd, sensor := runningScan(t, targets)
			repo := &followUpRepo{cmd: cmd}
			svc := NewService(repo, logger.NewNop())
			res, _ := json.Marshal(c.result)
			if _, err := svc.Complete(context.Background(), CompleteInput{
				TenantID: cmd.TenantID.String(), SensorID: sensor.String(), CommandID: cmd.ID.String(), Result: res,
			}); err != nil {
				t.Fatal(err)
			}
			if c.want == nil {
				if repo.followUp != nil || repo.fenced != 1 {
					t.Fatalf("follow-up %+v, fenced saves %d", repo.followUp, repo.fenced)
				}
				return
			}
			if repo.followUp == nil || !slices.Equal(commanddom.PayloadTargets(repo.followUp.Payload), c.want) ||
				repo.followUp.TenantID != cmd.TenantID {
				t.Fatalf("follow-up %+v", repo.followUp)
			}
		})
	}
}
