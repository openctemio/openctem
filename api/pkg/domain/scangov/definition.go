package scangov

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
)

// Definition is what an approval covers: the fields of a scan that decide
// what runs, how hard, against what, when and where. Runs of an approved
// definition need no further approval; a change to any field needs a new
// one. Name, description, retries and timeouts are not part of it.
type Definition struct {
	// Targets: direct targets and selectors (wildcard domains, CIDRs),
	// sorted. A selector is approved as written: each run resolves it
	// again within its pattern.
	Targets       []string       `json:"targets"`
	AssetGroupIDs []string       `json:"asset_group_ids"`
	TargetOptions map[string]any `json:"target_options,omitempty"`
	// What runs.
	ScanType      string         `json:"scan_type"`
	ScannerName   string         `json:"scanner_name,omitempty"`
	ScannerConfig map[string]any `json:"scanner_config,omitempty"`
	WorkflowID    string         `json:"workflow_id,omitempty"`
	// WorkflowSteps: tool or capability of each workflow step, sorted (a
	// workflow edit that changes the tools changes the definition).
	WorkflowSteps []string `json:"workflow_steps,omitempty"`
	ProfileID     string   `json:"profile_id,omitempty"`
	Intensity     string   `json:"intensity"`
	// When.
	ScheduleType     string `json:"schedule_type"`
	ScheduleCron     string `json:"schedule_cron,omitempty"`
	ScheduleRRule    string `json:"schedule_rrule,omitempty"`
	ScheduleDay      *int   `json:"schedule_day,omitempty"`
	ScheduleTime     string `json:"schedule_time,omitempty"`
	ScheduleTimezone string `json:"schedule_timezone,omitempty"`
	ScheduleRunAt    string `json:"schedule_run_at,omitempty"`
	// Where.
	SensorPreference  string   `json:"sensor_preference,omitempty"`
	RunOnTenantRunner bool     `json:"run_on_tenant_runner,omitempty"`
	ScanZoneID        string   `json:"scan_zone_id,omitempty"`
	Tags              []string `json:"tags,omitempty"`
}

// Canonical sorts the list fields so equal definitions encode equally.
func (d Definition) Canonical() Definition {
	sortClean := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, v := range in {
			if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
		slices.Sort(out)
		return out
	}
	d.Targets = sortClean(d.Targets)
	d.AssetGroupIDs = sortClean(d.AssetGroupIDs)
	d.WorkflowSteps = sortClean(d.WorkflowSteps)
	d.Tags = sortClean(d.Tags)
	return d
}

// Digest is the SHA-256 of the canonical definition ("sha256:<hex>").
// encoding/json sorts map keys, so nested configuration encodes stably.
func (d Definition) Digest() string {
	raw, _ := json.Marshal(d.Canonical())
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Change is one field that differs between two definitions.
type Change struct {
	Field  string `json:"field"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

// Diff lists the fields of after that differ from before, in field order
// (the JSON names). The approvers see it on a re-approval.
func Diff(before, after Definition) []Change {
	b, a := before.Canonical(), after.Canonical()
	bv, av := reflect.ValueOf(b), reflect.ValueOf(a)
	t := bv.Type()
	var out []Change
	for i := range t.NumField() {
		name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		x, y := bv.Field(i).Interface(), av.Field(i).Interface()
		if !equalJSON(x, y) {
			out = append(out, Change{Field: name, Before: x, After: y})
		}
	}
	return out
}

// equalJSON compares two values by their JSON encoding (nil and empty
// collections are the same).
func equalJSON(x, y any) bool {
	xr, _ := json.Marshal(x)
	yr, _ := json.Marshal(y)
	norm := func(r []byte) string {
		switch s := string(r); s {
		case "null", "[]", "{}", `""`, "false", "0":
			return ""
		default:
			return s
		}
	}
	return norm(xr) == norm(yr)
}

// AssetFacts are what the inventory says about a scan's target assets.
type AssetFacts struct {
	// Expanded: assets reached through asset groups and wildcard selectors
	// (not the direct targets themselves).
	Expanded       int
	Tags           []string
	MaxCriticality string
	CrownJewel     bool
}
