package scanrun

import "github.com/openctemio/openctem/api/pkg/domain/shared"

// RunContextKeyScanZoneID is the run-context key carrying the scan zone a
// workflow run was routed to (RFC-023). Every step command of such a run is
// stamped with the zone, so only sensors assigned to it can claim the step.
const RunContextKeyScanZoneID = "scan_zone_id"

// ScanZoneFromContext returns the zone a run was routed to, or nil.
func ScanZoneFromContext(runContext map[string]any) *shared.ID {
	raw, ok := runContext[RunContextKeyScanZoneID].(string)
	if !ok || raw == "" {
		return nil
	}
	id, err := shared.IDFromString(raw)
	if err != nil {
		return nil
	}
	return &id
}
