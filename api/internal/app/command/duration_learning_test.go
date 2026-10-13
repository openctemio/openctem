package command

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/toolbudget"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordedSample struct {
	tenant shared.ID
	tool   string
	sample time.Duration
}

type fakeDurations struct{ got []recordedSample }

func (f *fakeDurations) ObservePerTarget(_ context.Context, tenantID shared.ID, tool string, sample, _, _ time.Duration) error {
	f.got = append(f.got, recordedSample{tenantID, tool, sample})
	return nil
}
func (f *fakeDurations) ToolStats(context.Context, shared.ID, string) (toolbudget.Stats, bool, error) {
	return toolbudget.Stats{}, false, nil
}

// A completed scan command is one per-target sample of its tool in its
// tenant; other commands, and ones that never started, teach nothing.
func TestLearnDuration(t *testing.T) {
	f := &fakeDurations{}
	s := &Service{durations: f, logger: logger.NewNop()}
	tenant := shared.NewID()
	mk := func(typ commanddom.CommandType, payload map[string]any, started bool) *commanddom.Command {
		raw, _ := json.Marshal(payload)
		c, err := commanddom.NewCommand(tenant, typ, commanddom.CommandPriorityNormal, raw)
		if err != nil {
			t.Fatal(err)
		}
		if started {
			at := time.Now().Add(-100 * time.Second)
			c.StartedAt = &at
		}
		c.Complete(nil)
		return c
	}
	targets := make([]string, 50)
	for i := range targets {
		targets[i] = "h"
	}
	s.learnDuration(context.Background(), mk(commanddom.CommandTypeScan, map[string]any{"scanner": "dnsx", "targets": targets}, true))
	s.learnDuration(context.Background(), mk(commanddom.CommandTypeScan, map[string]any{"scanner": "nuclei", "target": "a"}, false))
	s.learnDuration(context.Background(), mk(commanddom.CommandTypeHealthCheck, map[string]any{"scanner": "nuclei", "target": "a"}, true))
	if len(f.got) != 1 {
		t.Fatalf("samples = %+v", f.got)
	}
	// 100 s over 50 targets, 50 at a time: 100 s per target, clamped to
	// dnsx's 30 s ceiling.
	if g := f.got[0]; g.tenant != tenant || g.tool != "dnsx" || g.sample != 30*time.Second {
		t.Fatalf("sample = %+v", g)
	}
}
