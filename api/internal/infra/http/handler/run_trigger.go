package handler

import (
	"context"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RunTrigger is who or what started a run, in one shape for every kind of
// run (research/62 P0-3): a person, a schedule, an automation, an API call,
// a webhook or the platform itself.
type RunTrigger struct {
	// Type: user, schedule, automation, api, webhook, asset_discovery,
	// system.
	Type string `json:"type"`
	// ID: the user, the automation or the scan (schedule) behind it.
	ID string `json:"id,omitempty"`
	// RunID: the automation run that started it.
	RunID string `json:"run_id,omitempty"`
	// NodeKey: the automation step that started it.
	NodeKey string `json:"node_key,omitempty"`
	// Label: the user's display name, when known.
	Label string `json:"label,omitempty"`
}

// Run trigger types (RunTrigger.Type).
const (
	runTriggerUser       = "user"
	runTriggerAutomation = "automation"
	runTriggerSchedule   = "schedule"
)

// automationTriggerPrefix is how an automation step names itself in a run's
// triggered_by ("workflow:<automation id>").
const automationTriggerPrefix = "workflow:"

// runTrigger derives the trigger of run from what the run stored: the
// automation cause in its context (an automation-started scan), its
// triggered_by and its trigger_type.
func runTrigger(run *scanrun.Run) RunTrigger {
	if cause, ok := run.Context["automation_cause"].(map[string]any); ok {
		t := RunTrigger{Type: runTriggerAutomation}
		t.ID, _ = cause["workflow_id"].(string)
		t.RunID, _ = cause["run_id"].(string)
		t.NodeKey, _ = cause["node_key"].(string)
		if t.ID != "" {
			return t
		}
	}
	if id, ok := strings.CutPrefix(run.TriggeredBy, automationTriggerPrefix); ok {
		return RunTrigger{Type: runTriggerAutomation, ID: id}
	}
	switch tt := string(run.TriggerType); tt {
	case "schedule":
		t := RunTrigger{Type: runTriggerSchedule}
		if run.ScanID != nil {
			t.ID = run.ScanID.String()
		}
		return t
	case "manual", "api", "":
		if _, err := shared.IDFromString(run.TriggeredBy); err == nil {
			return RunTrigger{Type: runTriggerUser, ID: run.TriggeredBy}
		}
		if tt == "" || tt == "manual" {
			return RunTrigger{Type: "system"}
		}
		return RunTrigger{Type: tt}
	case "on_asset_discovery":
		return RunTrigger{Type: "asset_discovery"}
	default:
		return RunTrigger{Type: tt}
	}
}

// runTriggerNames batch-loads the display names of the users who started
// runs, keyed by user id: one query for a page of runs. TriggeredBy is free
// text (a user id for a person, otherwise "system", "workflow:<id>", a
// webhook name...), so only values that parse as an id are looked up.
func runTriggerNames(ctx context.Context, users user.Repository, log *logger.Logger, runs ...*scanrun.Run) map[string]string {
	if users == nil || len(runs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(runs))
	ids := make([]shared.ID, 0, len(runs))
	for _, run := range runs {
		if run == nil || run.TriggeredBy == "" {
			continue
		}
		if _, ok := seen[run.TriggeredBy]; ok {
			continue
		}
		seen[run.TriggeredBy] = struct{}{}
		if id, err := shared.IDFromString(run.TriggeredBy); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	found, err := users.GetByIDs(ctx, ids)
	if err != nil {
		log.Warn("failed to batch-resolve run trigger names", "error", err)
		return nil
	}
	names := make(map[string]string, len(found))
	for _, u := range found {
		if u == nil {
			continue
		}
		name := u.Name()
		if name == "" {
			name = u.Email()
		}
		names[u.ID().String()] = name
	}
	return names
}

// withRunTriggerLabel sets the trigger's user label and the older
// triggered_by_name from names. Pure.
func withRunTriggerLabel(resp *RunResponse, names map[string]string) *RunResponse {
	if resp == nil {
		return nil
	}
	resp.TriggeredByName = names[resp.TriggeredBy]
	if resp.Trigger != nil && resp.Trigger.Type == runTriggerUser {
		resp.Trigger.Label = names[resp.Trigger.ID]
	}
	return resp
}
