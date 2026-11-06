package scan

// Instance scan zones at the scan trigger (docs/rfcs/RFC-100-shared-sensors.md
// §6.1). A single scan's internal targets may go to shared sensors only
// when one instance scan zone assigned to the organization contains them
// all (addresses and ranges; never names) and the instance lets shared
// sensors scan internal zones. The job is then stamped with the zone; its
// id and ranges reach the sensor only inside the signed job statement.
//
// Workflow steps keep the public-only rule for shared sensors: a step's
// internal targets stay on the organization's own sensors.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/instancezone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// InstanceZones looks up the instance scan zone for an organization's
// internal targets (*instancezone.Service).
type InstanceZones interface {
	ZoneFor(ctx context.Context, tenantID shared.ID, internalTargets []string) (*instancezone.Zone, error)
}

// SetInstanceZones wires the lookup. Without it, internal targets never go
// to shared sensors.
func (s *Service) SetInstanceZones(z InstanceZones) { s.instanceZones = z }

// internalTargets returns the targets that are internal addresses, ranges
// or names.
func internalTargets(targets []string) []string {
	var out []string
	for _, t := range targets {
		if isInternalTarget(t) {
			out = append(out, t)
		}
	}
	return out
}

// instanceZoneFor returns the instance scan zone that contains every
// internal target of targets for the organization, or nil (no internal
// target, no lookup wired, or no single assigned zone contains them).
func (s *Service) instanceZoneFor(ctx context.Context, tenantID shared.ID, targets []string) (*instancezone.Zone, error) {
	internal := internalTargets(targets)
	if len(internal) == 0 || s.instanceZones == nil {
		return nil, nil
	}
	return s.instanceZones.ZoneFor(ctx, tenantID, internal)
}

// stampInstanceZone stamps a shared job whose targets include internal
// ones with their instance scan zone. A shared job with internal targets
// and no zone is refused: it would never be signed.
func (s *Service) stampInstanceZone(ctx context.Context, cmd *command.Command, targets []string) error {
	if !cmd.IsPlatformJob || len(internalTargets(targets)) == 0 {
		return nil
	}
	zone, err := s.instanceZoneFor(ctx, cmd.TenantID, targets)
	if err != nil {
		return err
	}
	if zone == nil {
		return shared.NewDomainError(codePlatformRefused,
			"shared platform sensors scan internal targets only inside an instance scan zone assigned to your organization; scan them on your own sensors",
			shared.ErrValidation)
	}
	cmd.SetInstanceScanZone(zone.ID)
	return nil
}

// zoneRefusal is nil when the internal targets of targets lie in an
// instance scan zone assigned to the organization, else the refusal.
func (s *Service) zoneRefusal(ctx context.Context, tenantID shared.ID, targets []string) (error, error) {
	zone, err := s.instanceZoneFor(ctx, tenantID, targets)
	if err != nil {
		return nil, fmt.Errorf("instance scan zone lookup: %w", err)
	}
	if zone == nil {
		return shared.NewDomainError(codePlatformRefused,
			"shared platform sensors never scan asset groups or internal targets outside an instance scan zone assigned to your organization; scan them on your own sensors, or scan only public targets",
			shared.ErrValidation), nil
	}
	return nil, nil
}
