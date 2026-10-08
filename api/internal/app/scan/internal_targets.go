package scan

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// dropInternalOutsideZones applies the private-range policy of scan create
// again when a run is triggered: an internal address (private, loopback,
// link-local, unspecified, carrier-grade NAT; a literal address, a range, a
// URL or a host:port with one) is dispatched only when it is a private
// address inside one of the tenant's scan zones. A tenant with zones gets
// that from zone routing (planZoneDispatch refuses uncovered targets); for a
// tenant without zones every such target is left out of the run here, and
// counted.
//
// Scan create already refuses such targets, but a run is built later and from
// more than the saved direct targets: asset-group members were never
// validated, and a zone that admitted a private target may have been deleted
// or shrunk since. ResolveDispatchTargets (the gate of every other dispatch
// path) applies the same rule through the target validator.
//
// Hostnames are not resolved here, as on create: they are routed by the zone
// router and the sensor's local policy.
func (s *Service) dropInternalOutsideZones(ctx context.Context, tenantID shared.ID, r *resolvedTargets) error {
	var internal []string
	for _, t := range r.Targets {
		if pt := scanzone.ParseTarget(t); pt.IsAddr && isInternalAddr(pt.Prefix.Addr()) {
			internal = append(internal, t)
		}
	}
	if len(internal) == 0 {
		return nil
	}
	zones, err := s.loadZones(ctx, tenantID)
	if err != nil {
		return err
	}
	if len(zones) > 0 {
		// Zone routing (planZoneDispatch) refuses every target no zone
		// covers, with a reason per target.
		return nil
	}
	refused := make(map[string]bool, len(internal))
	for _, t := range internal {
		refused[t] = true
	}
	kept := r.Targets[:0]
	for _, t := range r.Targets {
		if refused[t] {
			delete(r.TargetTypes, t)
			continue
		}
		kept = append(kept, t)
	}
	r.Targets = kept
	r.InternalOutsideZones = len(refused)
	r.Warnings = append(r.Warnings, fmt.Sprintf(
		"%d internal address target(s) were skipped: internal addresses are scanned only inside a scan zone of this organization", len(refused)))
	s.logger.Warn("SECURITY: internal targets outside every scan zone left out of a run",
		"tenant_id", tenantID.String(), "count", len(refused))
	return nil
}
