package handler

import (
	"context"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// FindingLocationResponse is one service a version-match finding is
// observed on (docs/architecture/vulnerability-matching.md, "Locations").
type FindingLocationResponse struct {
	AssetID   string `json:"asset_id"`
	AssetName string `json:"asset_name"`
	// Label names the service by scheme (or transport) and port: "https:443".
	Label string `json:"label"`
	Port  int    `json:"port,omitempty"`
	// State is affected, fixed or not_affected.
	State       string    `json:"state" enums:"affected,fixed,not_affected"`
	StateReason string    `json:"state_reason,omitempty"`
	StateAt     time.Time `json:"state_at"`
	Version     string    `json:"version,omitempty"`
	// Evidence is what the version was read from (a banner, a header);
	// untrusted plain text.
	Evidence  string    `json:"evidence,omitempty"`
	FirstSeen time.Time `json:"first_seen_at"`
	LastSeen  time.Time `json:"last_seen_at"`
}

// enrichFindingWithLocations adds the locations the caller may see to a
// finding detail. f is already authorized by GetFindingWithScope; the
// service drops every location on an asset outside the caller's data scope.
// A read error only leaves them out.
func (h *VulnerabilityHandler) enrichFindingWithLocations(ctx context.Context, f *vulnerability.Finding, userID string, isAdmin bool, resp *FindingResponse) {
	locs, err := h.service.GetFindingLocations(ctx, f, userID, isAdmin)
	if err != nil {
		h.logger.Debug("failed to fetch finding locations", "finding_id", f.ID().String(), "error", err)
		return
	}
	resp.Locations = toFindingLocations(locs)
}

func toFindingLocations(locs []softwarematch.Location) []FindingLocationResponse {
	if len(locs) == 0 {
		return nil
	}
	out := make([]FindingLocationResponse, 0, len(locs))
	for _, l := range locs {
		out = append(out, FindingLocationResponse{
			AssetID: l.AssetID.String(), AssetName: l.AssetName,
			Label: softwarematch.LocationLabel(l.AssetName, l.Port, l.Transport), Port: l.Port,
			State: string(l.State), StateReason: l.StateReason, StateAt: l.StateAt, Version: l.Version,
			Evidence: l.Evidence, FirstSeen: l.FirstSeen, LastSeen: l.LastSeen,
		})
	}
	return out
}
