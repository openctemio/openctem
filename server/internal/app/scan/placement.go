package scan

// Where a job runs decides whether ownership confirmation applies
// (docs/architecture/scan-targets.md, "Where ownership confirmation
// applies"). On the hosted service (MANAGED_SERVICE) a job on platform
// sensors may reach only assets whose ownership the tenant confirmed (or a
// scope entry covers) and keeps wildcard-only names passive. A job on the
// tenant's own sensors, and any job on a self-hosted install, is judged by
// the tenant's scope entries alone. A rejection, a scope exclusion, the
// deny list and the guardrails apply on every placement.
//
// The decision is per job, made where the job is checked: the trigger
// predicts the routing it will decide (placementFor), a workflow hop reads
// the run's recorded routing, and the claim-time re-check knows the sensor.
// The ownership gate reads the placement from the context
// (attribution.WithPlacement); a check that does not know it is judged as a
// platform job on the hosted service (fail closed).

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// confirmationScoped is implemented by the ownership gate
// (*easm.ActiveGate): whether confirmation can apply on this deployment.
type confirmationScoped interface {
	OwnershipConfirmationManaged() bool
}

// confirmationManaged reports whether ownership confirmation can apply at
// all (MANAGED_SERVICE). A gate that does not say counts as managed.
func (s *Service) confirmationManaged() bool {
	if c, ok := s.attributionGate.(confirmationScoped); ok {
		return c.OwnershipConfirmationManaged()
	}
	return true
}

// placementFor predicts where jobs of a scan with these settings run: the
// tenant's own sensors, or platform sensors. It mirrors the routing the
// trigger decides (shouldUsePlatformSensor): an asset group or an explicit
// tenant preference never goes to shared sensors; an explicit platform
// preference always does; in auto mode a job goes to shared sensors only
// when the tenant may use them and no tenant sensor of the tool is
// available (a busy fleet makes the job wait, it does not move). tools are
// the tools the job runs (empty for a workflow whose steps are not known:
// any step may go to shared sensors). A failed lookup keeps the job on
// tenant sensors, as the trigger does; the claim-time re-check judges the
// sensor that really takes the job.
func (s *Service) placementFor(ctx context.Context, tenantID shared.ID, pref scan.SensorPreference, tenantOnly, assetGroup bool, tools ...string) attribution.Placement {
	if !s.confirmationManaged() {
		return attribution.PlacementTenant
	}
	switch {
	case tenantOnly || assetGroup || pref == scan.SensorPreferenceTenant:
		return attribution.PlacementTenant
	case pref == scan.SensorPreferencePlatform:
		return attribution.PlacementPlatform
	case s.sensorSelector == nil || !s.mayUseShared(ctx, tenantID):
		return attribution.PlacementTenant
	}
	if len(tools) == 0 {
		return attribution.PlacementPlatform
	}
	for _, tool := range tools {
		res, err := s.sensorSelector.SelectSensor(ctx, SelectSensorRequest{
			TenantID: tenantID, Capabilities: []string{tool}, Tool: tool,
			Mode: SelectTenantFirst, AllowQueue: true,
		})
		if err != nil {
			continue
		}
		if (res.Sensor != nil && !res.IsPlatform) || res.TenantBusy {
			continue
		}
		return attribution.PlacementPlatform
	}
	return attribution.PlacementTenant
}

// scanPlacement is placementFor for a saved scan; tools override the
// scanner (a workflow's step tools).
func (s *Service) scanPlacement(ctx context.Context, sc *scan.Scan, tools ...string) attribution.Placement {
	if len(tools) == 0 && sc.ScannerName != "" {
		tools = []string{sc.ScannerName}
	}
	return s.placementFor(ctx, sc.TenantID, sc.SensorPreference, sc.RunOnTenantRunner, sc.HasAssetGroup(), tools...)
}

// withScanPlacement adds the scan's predicted placement to ctx unless a
// caller already decided it.
func (s *Service) withScanPlacement(ctx context.Context, sc *scan.Scan, tools ...string) context.Context {
	if attribution.PlacementOf(ctx) != attribution.PlacementUnknown {
		return ctx
	}
	return attribution.WithPlacement(ctx, s.scanPlacement(ctx, sc, tools...))
}

// workflowTools lists the tools a workflow's steps pin; nil when any step
// leaves its tool to the platform (then any step may go to shared sensors).
func workflowTools(steps []*scanworkflow.Step) []string {
	tools := make([]string, 0, len(steps))
	for _, st := range steps {
		if st.Tool == "" {
			return nil
		}
		tools = append(tools, st.Tool)
	}
	return tools
}

// scannerTools is the tools list of a single scanner ("" is a workflow:
// none known).
func scannerTools(scanner string) []string {
	if scanner == "" {
		return nil
	}
	return []string{scanner}
}
