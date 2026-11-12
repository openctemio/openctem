package handler

// The per-zone breakdown of a workflow run split over several scan zones
// (docs/architecture/scan-zones.md, "Workflow runs over several zones").

import (
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
)

// RunZoneSplitResponse describes a split run. On the parent: Groups, one per
// zone group (zone_name empty for the targets outside every zone). On a
// zone run: its parent, zone and position.
type RunZoneSplitResponse struct {
	ParentRunID string                 `json:"parent_run_id,omitempty"`
	ZoneID      string                 `json:"zone_id,omitempty"`
	ZoneName    string                 `json:"zone_name,omitempty"`
	Part        int                    `json:"part,omitempty"`
	Parts       int                    `json:"parts,omitempty"`
	Groups      []RunZoneGroupResponse `json:"groups,omitempty"`
}

// RunZoneGroupResponse is one zone group of a split run.
type RunZoneGroupResponse struct {
	ZoneID   string `json:"zone_id,omitempty"`
	ZoneName string `json:"zone_name,omitempty"`
	Targets  int    `json:"targets"`
	// Status is started (RunID set) or refused (Reason says why).
	Status string `json:"status" enums:"started,refused"`
	Reason string `json:"reason,omitempty"`
	RunID  string `json:"run_id,omitempty"`
	// RunStatus is the zone run's status (run detail only).
	RunStatus     string `json:"run_status,omitempty"`
	TotalFindings int    `json:"total_findings,omitempty"`
}

// toRunZoneSplit reads the run context's zone_split value (nil when the run
// is not part of a split).
func toRunZoneSplit(ctx map[string]any) *RunZoneSplitResponse {
	raw, ok := ctx[scanrundom.RunContextKeyZoneSplit].(map[string]any)
	if !ok {
		return nil
	}
	str := func(m map[string]any, k string) string { v, _ := m[k].(string); return v }
	num := func(m map[string]any, k string) int {
		switch v := m[k].(type) {
		case float64:
			return int(v)
		case int:
			return v
		}
		return 0
	}
	out := &RunZoneSplitResponse{
		ParentRunID: str(raw, "parent_run_id"), ZoneID: str(raw, "zone_id"), ZoneName: str(raw, "zone_name"),
		Part: num(raw, "part"), Parts: num(raw, "parts"),
	}
	var groups []any
	switch g := raw["groups"].(type) {
	case []any:
		groups = g
	case []map[string]any:
		for _, m := range g {
			groups = append(groups, m)
		}
	}
	for _, g := range groups {
		m, ok := g.(map[string]any)
		if !ok {
			continue
		}
		out.Groups = append(out.Groups, RunZoneGroupResponse{
			ZoneID: str(m, "zone_id"), ZoneName: str(m, "zone_name"), Targets: num(m, "target_count"),
			Status: str(m, "status"), Reason: str(m, "reason"), RunID: str(m, "run_id"),
		})
	}
	return out
}

// withZoneRunStatuses fills each group's zone run status and findings.
func withZoneRunStatuses(split *RunZoneSplitResponse, children []*scanrundom.Run) {
	if split == nil {
		return
	}
	byID := make(map[string]*scanrundom.Run, len(children))
	for _, c := range children {
		byID[c.ID.String()] = c
	}
	for i := range split.Groups {
		if c, ok := byID[split.Groups[i].RunID]; ok {
			split.Groups[i].RunStatus = string(c.Status)
			split.Groups[i].TotalFindings = c.TotalFindings
		}
	}
}
