package scan

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// Scan-zone routing preview and zone picker support. Design:
// docs/rfcs/RFC-023-scan-zones-and-scanners.md §7; architecture:
// docs/architecture/scan-zones.md.

const (
	// maxPreviewTargets bounds the per-target detail of a preview response.
	maxPreviewTargets = 500
	// maxPreviewDirectTargets mirrors the direct-target limit of scan creation.
	maxPreviewDirectTargets = 1000

	// Per-target routing outcomes of a preview.
	PreviewStatusZone      = "zone"      // routed into a zone
	PreviewStatusUnzoned   = "unzoned"   // public, no zone: dispatched as before zones
	PreviewStatusUncovered = "uncovered" // not scanned; Reason says why

	errCodeInvalidTarget = "INVALID_TARGET"

	// previewScanName names the unsaved scan in trigger messages; previewError
	// rewrites it to "this scan".
	previewScanName = "preview"
)

// ErrSelectedZoneNotFound is returned when a scan names a zone that is not one
// of the tenant's zones.
var ErrSelectedZoneNotFound = shared.NewDomainError("SCAN_ZONE_NOT_FOUND",
	"scan zone not found; pick one of the tenant's scan zones, or Automatic routing", shared.ErrValidation)

// resolveSelectedZone validates the zone picker value of a scan: "" means
// Automatic (nil). Any other value must be one of the tenant's zones.
func (s *Service) resolveSelectedZone(ctx context.Context, tenantID shared.ID, raw string) (*shared.ID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	id, err := shared.IDFromString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid scan_zone_id", shared.ErrValidation)
	}
	zones, err := s.loadZones(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, z := range zones {
		if z.ID == id {
			return &id, nil
		}
	}
	return nil, ErrSelectedZoneNotFound
}

// ZoneRoutingPreviewInput is what a scan would be created with.
type ZoneRoutingPreviewInput struct {
	TenantID      string
	Targets       []string
	AssetGroupIDs []string
	ScanType      string // single (default) or workflow
	ScannerName   string
	TargetsPerJob int
	ScanZoneID    string // "" = Automatic
}

// PreviewTarget is where one target would go.
type PreviewTarget struct {
	Target    string   `json:"target"`
	Status    string   `json:"status"` // zone | unzoned | uncovered
	ZoneID    string   `json:"zone_id,omitempty"`
	ZoneName  string   `json:"zone_name,omitempty"`
	SensorID  string   `json:"sensor_id,omitempty"` // the sensor its job would be pinned to
	Reason    string   `json:"reason,omitempty"`
	Addresses []string `json:"addresses,omitempty"` // what a hostname resolved to
}

// PreviewZone is the work one zone would receive.
type PreviewZone struct {
	ZoneID     string   `json:"zone_id"`
	ZoneName   string   `json:"zone_name"`
	Targets    int      `json:"targets"`
	Jobs       int      `json:"jobs"`
	QueuedJobs int      `json:"queued_jobs"` // jobs with no online sensor yet: they wait in the zone
	SensorIDs  []string `json:"sensor_ids"`
}

// PreviewError is the error a trigger with these settings would fail with.
type PreviewError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ZoneRoutingPreview is what a trigger would do with a scan's targets, computed
// by the same code as the trigger, without creating anything.
type ZoneRoutingPreview struct {
	ZonesEnabled     bool            `json:"zones_enabled"`
	Routed           bool            `json:"routed"`
	NotRoutedReason  string          `json:"not_routed_reason,omitempty"`
	ResolvedTargets  int             `json:"resolved_targets"`
	ExcludedTargets  int             `json:"excluded_targets"`
	Excluded         []string        `json:"excluded"`
	Targets          []PreviewTarget `json:"targets"`
	Zones            []PreviewZone   `json:"zones"`
	UnzonedTargets   int             `json:"unzoned_targets"`
	UncoveredTargets int             `json:"uncovered_targets"`
	Jobs             int             `json:"jobs"`
	TargetsPerJob    int             `json:"targets_per_job"`
	SelectedZoneID   string          `json:"selected_zone_id,omitempty"`
	Warnings         []string        `json:"warnings"`
	Error            *PreviewError   `json:"error,omitempty"`
}

// PreviewZoneRouting shows, for a scan about to be created, which targets go
// to which zone and sensor, which scope excludes, and which are not scanned
// and why. Read-only: it creates no scan, run or command. Hostnames are
// resolved as at trigger time, so the answer can change with DNS.
//
// Request errors (unknown zone or asset group) are returned as errors; what a
// trigger would refuse is reported in the preview's Error.
func (s *Service) PreviewZoneRouting(ctx context.Context, in ZoneRoutingPreviewInput) (*ZoneRoutingPreview, error) {
	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	if len(in.Targets) > maxPreviewDirectTargets {
		return nil, fmt.Errorf("%w: at most %d targets", shared.ErrValidation, maxPreviewDirectTargets)
	}
	scanType := scan.ScanType(in.ScanType)
	if in.ScanType == "" {
		scanType = scan.ScanTypeSingle
	}
	if scanType != scan.ScanTypeSingle && scanType != scan.ScanTypeWorkflow {
		return nil, fmt.Errorf("%w: invalid scan_type", shared.ErrValidation)
	}

	zones, err := s.loadZones(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	sc := &scan.Scan{
		TenantID:      tenantID,
		Name:          previewScanName,
		ScanType:      scanType,
		ScannerName:   in.ScannerName,
		TargetsPerJob: in.TargetsPerJob,
	}
	if strings.TrimSpace(in.ScanZoneID) != "" {
		zid, err := shared.IDFromString(strings.TrimSpace(in.ScanZoneID))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid scan_zone_id", shared.ErrValidation)
		}
		sc.ScanZoneID = &zid
		if _, err := selectedZone(sc, zones); err != nil {
			return nil, scanzone.ErrZoneNotFound
		}
	}
	for _, raw := range in.AssetGroupIDs {
		id, err := s.validateScanAssetGroup(ctx, tenantID, in.TenantID, raw)
		if err != nil {
			return nil, err
		}
		sc.AssetGroupIDs = append(sc.AssetGroupIDs, id)
	}

	out := &ZoneRoutingPreview{
		ZonesEnabled: len(zones) > 0,
		Excluded:     []string{},
		Targets:      []PreviewTarget{},
		Zones:        []PreviewZone{},
		Warnings:     []string{},
	}
	if sc.ScanZoneID != nil {
		out.SelectedZoneID = sc.ScanZoneID.String()
	}

	// Direct targets go through the same validation as scan creation; what
	// creation would refuse is shown as not scanned, with the reason.
	accepted, rejected, err := s.previewValidateTargets(ctx, in.TenantID, in.Targets)
	if err != nil {
		return nil, err
	}
	sc.Targets = accepted

	resolved, err := s.resolveScanTargets(ctx, sc)
	if err != nil {
		return nil, err
	}
	out.ResolvedTargets = len(resolved.Targets)
	out.ExcludedTargets = resolved.Excluded
	out.Excluded = append(out.Excluded, resolved.ExcludedNames[:min(len(resolved.ExcludedNames), maxListedUncovered)]...)
	out.Warnings = append(out.Warnings, resolved.Warnings...)
	if len(rejected) > 0 {
		out.Error = &PreviewError{Code: errCodeInvalidTarget, Message: fmt.Sprintf(
			"invalid target %q: %s; the scan cannot be created with it", rejected[0].Target, rejected[0].Reason)}
	}
	if err := recordResolvedTargets(sc, resolved, map[string]any{}); err != nil && out.Error == nil {
		out.Error = previewError(err)
	}

	var plan *zonePlan
	switch {
	case len(zones) == 0:
		out.NotRoutedReason = "the tenant has no scan zones: targets are dispatched to any tenant sensor"
	case scanType == scan.ScanTypeSingle && !s.toolReachesNetwork(ctx, sc.ScannerName):
		out.NotRoutedReason = fmt.Sprintf("scanner %q does not scan network targets, so scan zones do not apply", sc.ScannerName)
	default:
		out.Routed = true
		plan, err = s.previewPlan(ctx, sc, zones, resolved.Targets, out)
		if err != nil {
			return nil, err
		}
	}

	out.Targets = previewTargets(resolved.Targets, plan, rejected)
	sortByInputOrder(out.Targets, in.Targets)
	out.UncoveredTargets = len(rejected)
	if plan == nil {
		out.UnzonedTargets = len(resolved.Targets)
		if len(resolved.Targets) > 0 {
			out.Jobs = 1
		}
		return out, nil
	}
	out.UnzonedTargets = len(plan.Routing.Unzoned)
	out.UncoveredTargets += len(plan.Uncovered)
	out.Jobs = len(plan.Batches)
	out.Warnings = append(out.Warnings, plan.Warnings...)
	out.Zones = previewZones(plan, sc.ScanType == scan.ScanTypeWorkflow)
	return out, nil
}

// previewPlan runs the trigger's planning for the scan type. A planning
// refusal (split workflow, too many jobs, no coverage) is reported in
// out.Error; the routing is still returned so the per-target view stays.
func (s *Service) previewPlan(ctx context.Context, sc *scan.Scan, zones []*scanzone.Zone, targets []string, out *ZoneRoutingPreview) (*zonePlan, error) {
	routing, err := s.routeForScan(ctx, sc, zones, targets)
	if err != nil {
		return nil, err
	}
	var plan *zonePlan
	if sc.ScanType == scan.ScanTypeWorkflow {
		plan, _, err = planWorkflowZone(sc, routing)
	} else {
		out.TargetsPerJob = zoneBatchSize(sc)
		plan, err = s.planZoneBatches(ctx, sc, routing)
	}
	if err != nil {
		var de *shared.DomainError
		if !errors.As(err, &de) {
			return nil, err // a lookup failure, not a refusal
		}
		if out.Error == nil {
			out.Error = previewError(err)
		}
		return &zonePlan{Uncovered: routing.Uncovered, Routing: routing, Warnings: uncoveredWarnings(routing.Uncovered)}, nil
	}
	if len(targets) > 0 {
		if err := recordZonePlan(sc, plan, map[string]any{}); err != nil && out.Error == nil {
			out.Error = previewError(err)
		}
	}
	return plan, nil
}

type rejectedTarget struct {
	Target string
	Reason string
}

// previewValidateTargets applies scan creation's target validation, including
// the admission of private targets a zone covers.
func (s *Service) previewValidateTargets(ctx context.Context, tenantID string, targets []string) ([]string, []rejectedTarget, error) {
	return s.validateTargetsEach(ctx, tenantID, targets, maxPreviewDirectTargets)
}

// validateTargetsEach is scan creation's target validation, target by target:
// it returns the accepted targets (private ones only when a scan zone covers
// them) and the rejected ones with the reason, instead of failing on the
// first rejection.
func (s *Service) validateTargetsEach(ctx context.Context, tenantID string, targets []string, maxTargets int) ([]string, []rejectedTarget, error) {
	if len(targets) == 0 {
		return nil, nil, nil
	}
	v := validator.NewTargetValidator(
		validator.WithAllowInternalIPs(false),
		validator.WithAllowLocalhost(false),
		validator.WithMaxTargets(maxTargets),
	)
	result := v.ValidateTargets(targets)
	var admitted []string
	if result.HasErrors && len(result.BlockedIPs) > 0 {
		var err error
		if admitted, err = s.admitZonedPrivateTargets(ctx, tenantID, result); err != nil {
			return nil, nil, err
		}
	}
	rejected := make([]rejectedTarget, 0, len(result.Invalid))
	for _, inv := range result.Invalid {
		rejected = append(rejected, rejectedTarget{Target: inv.Original, Reason: inv.Error})
	}
	return append(result.GetValidTargetStrings(), admitted...), rejected, nil
}

func previewError(err error) *PreviewError {
	var de *shared.DomainError
	if !errors.As(err, &de) {
		return &PreviewError{Code: "INVALID", Message: err.Error()}
	}
	quoted := fmt.Sprintf("%q", previewScanName)
	msg := strings.NewReplacer(
		"Workflow scan "+quoted, "This workflow scan",
		"Scan "+quoted, "This scan",
		"scan "+quoted, "this scan",
	).Replace(de.Message)
	return &PreviewError{Code: de.Code, Message: msg}
}

// sortByInputOrder puts the per-target rows in the order the targets were
// given; asset-group members (not in the input) follow, in routing order.
func sortByInputOrder(rows []PreviewTarget, input []string) {
	pos := make(map[string]int, len(input))
	for i, t := range input {
		k := strings.ToLower(strings.TrimSpace(t))
		if _, seen := pos[k]; !seen {
			pos[k] = i
		}
	}
	rank := func(t string) int {
		if i, ok := pos[strings.ToLower(strings.TrimSpace(t))]; ok {
			return i
		}
		return len(input)
	}
	slices.SortStableFunc(rows, func(a, b PreviewTarget) int { return rank(a.Target) - rank(b.Target) })
}

// previewTargets lists each target's outcome: routed targets in order, then
// the ones scan creation would refuse.
func previewTargets(targets []string, plan *zonePlan, rejected []rejectedTarget) []PreviewTarget {
	out := make([]PreviewTarget, 0, min(len(targets)+len(rejected), maxPreviewTargets))
	add := func(t PreviewTarget) {
		if len(out) < maxPreviewTargets {
			out = append(out, t)
		}
	}
	if plan == nil {
		for _, t := range targets {
			add(PreviewTarget{Target: t, Status: PreviewStatusUnzoned})
		}
	} else {
		sensorOf := map[string]string{}
		for _, b := range plan.Batches {
			if b.SensorID == nil {
				continue
			}
			for _, t := range b.Targets {
				sensorOf[t] = b.SensorID.String()
			}
		}
		// Uncovered after routing (zone without sensors) overrides the zone.
		uncovered := map[string]string{}
		for _, u := range plan.Uncovered {
			uncovered[u.Target] = u.Reason
		}
		for _, rt := range plan.Routing.Routes {
			pt := PreviewTarget{Target: rt.Target}
			for _, a := range rt.Addrs {
				pt.Addresses = append(pt.Addresses, a.String())
			}
			switch {
			case uncovered[rt.Target] != "":
				pt.Status, pt.Reason = PreviewStatusUncovered, uncovered[rt.Target]
				if rt.Zone != nil {
					pt.ZoneID, pt.ZoneName = rt.Zone.ID.String(), rt.Zone.Name
				}
			case rt.Zone != nil:
				pt.Status, pt.ZoneID, pt.ZoneName = PreviewStatusZone, rt.Zone.ID.String(), rt.Zone.Name
				pt.SensorID = sensorOf[rt.Target]
			case rt.Unzoned:
				pt.Status = PreviewStatusUnzoned
			default:
				pt.Status, pt.Reason = PreviewStatusUncovered, rt.Reason
			}
			add(pt)
		}
	}
	for _, r := range rejected {
		add(PreviewTarget{Target: r.Target, Status: PreviewStatusUncovered, Reason: "not accepted by scan creation: " + r.Reason})
	}
	return out
}

// previewZones summarizes the jobs per zone. Workflow steps are never pinned
// at trigger time (the zone's sensors claim them), so they are not "queued".
func previewZones(plan *zonePlan, workflow bool) []PreviewZone {
	out := []PreviewZone{}
	idx := map[string]int{}
	for _, b := range plan.Batches {
		if b.Zone == nil {
			continue
		}
		id := b.Zone.ID.String()
		i, ok := idx[id]
		if !ok {
			i = len(out)
			idx[id] = i
			out = append(out, PreviewZone{ZoneID: id, ZoneName: b.Zone.Name, SensorIDs: []string{}})
		}
		z := &out[i]
		z.Targets += len(b.Targets)
		z.Jobs++
		switch {
		case b.SensorID != nil:
			z.SensorIDs = appendUnique(z.SensorIDs, b.SensorID.String())
		case !workflow:
			z.QueuedJobs++
		}
	}
	return out
}
