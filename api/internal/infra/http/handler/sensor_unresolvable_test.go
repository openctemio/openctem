package handler

import (
	"encoding/json"
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const legacyAllUnresolvable = `invalid scan target: 3 of 3 targets refused: "a.example.com": cannot resolve scan target host "a.example.com" (refusing to scan an unverifiable target): lookup a.example.com: no such host; "b.example.com": cannot resolve scan target host "b.example.com" (refusing to scan an unverifiable target): lookup b.example.com: no such host; and 1 more`

func runningCommandOf(t *testing.T, sensor shared.ID) *commanddom.Command {
	t.Helper()
	cmd, err := commanddom.NewCommand(shared.NewID(), commanddom.CommandTypeScan, commanddom.CommandPriorityNormal, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	cmd.SensorID = &sensor
	cmd.Status = commanddom.CommandStatusRunning
	return cmd
}

// A legacy sensor reports a task whose every target does not resolve as a
// failure; the platform completes it with per-target skips instead.
func TestUnresolvableResultFor(t *testing.T) {
	sensor := shared.NewID()
	cmd := runningCommandOf(t, sensor)

	res, ok := unresolvableResultFor(cmd, sensor.String(), legacyAllUnresolvable)
	if !ok {
		t.Fatal("an all-unresolvable failure of a running command must complete with skips")
	}
	var got struct {
		Metadata struct {
			Refused []struct{ Target, Reason string } `json:"refused_targets"`
			Total   int                               `json:"refused_targets_total"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(res, &got); err != nil {
		t.Fatal(err)
	}
	if got.Metadata.Total != 3 || len(got.Metadata.Refused) != 2 || got.Metadata.Refused[0].Reason != "unresolvable" {
		t.Fatalf("result = %s", res)
	}

	// A retried report of the converted failure compares equal.
	cmd.Status = commanddom.CommandStatusCompleted
	cmd.Result = res
	if again, ok := unresolvableResultFor(cmd, sensor.String(), legacyAllUnresolvable); !ok || string(again) != string(res) {
		t.Fatalf("replay: ok=%v", ok)
	}

	for name, tc := range map[string]struct {
		mutate func(*commanddom.Command)
		sensor string
		msg    string
	}{
		"another sensor": {func(c *commanddom.Command) { c.Status = commanddom.CommandStatusRunning }, shared.NewID().String(), legacyAllUnresolvable},
		"not started":    {func(c *commanddom.Command) { c.Status = commanddom.CommandStatusAcknowledged }, sensor.String(), legacyAllUnresolvable},
		"completed by the sensor": {func(c *commanddom.Command) {
			c.Status = commanddom.CommandStatusCompleted
			c.Result = json.RawMessage(`{"findings_count":1}`)
		}, sensor.String(), legacyAllUnresolvable},
		"a denied target is a refusal": {func(c *commanddom.Command) { c.Status = commanddom.CommandStatusRunning }, sensor.String(), `invalid scan target: 2 of 2 targets refused: "a.example.com": cannot resolve scan target host "a.example.com" (x); "10.0.0.1": scan target IP 10.0.0.1 is in a blocked range`},
		"another failure":              {func(c *commanddom.Command) { c.Status = commanddom.CommandStatusRunning }, sensor.String(), "scanner not found: nuclei"},
	} {
		c := runningCommandOf(t, sensor)
		tc.mutate(c)
		if _, ok := unresolvableResultFor(c, tc.sensor, tc.msg); ok {
			t.Errorf("%s: converted", name)
		}
	}
}
