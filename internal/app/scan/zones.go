package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/scanzone"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/validator"
)

// Scan-zone routing at trigger time (RFC-023 D4-D6, Phase 1). Design:
// docs/rfcs/RFC-023-scan-zones-and-scanners.md; architecture:
// docs/architecture/scan-zones.md.

// ZoneDirectory is what trigger-time routing needs from the zone store.
// Implemented by postgres.ScanZoneRepository.
type ZoneDirectory interface {
	List(ctx context.Context, tenantID shared.ID) ([]*scanzone.Zone, error)
	RoutableSensors(ctx context.Context, tenantID shared.ID, zoneIDs []shared.ID, tool string) (map[shared.ID][]scanzone.SensorCandidate, error)
}

// WithScanZones enables zone routing. resolver resolves hostname targets
// (nil: hostnames in a zoned tenant are reported as unresolved).
func WithScanZones(dir ZoneDirectory, resolver scanzone.Resolver) ServiceOption {
	return func(s *Service) {
		s.zones = dir
		s.zoneResolver = resolver
	}
}

const (
	// maxZoneJobsPerRun bounds how many commands one zoned run may create.
	maxZoneJobsPerRun = 1000
	// maxListedUncovered bounds the per-target detail kept in the run context.
	maxListedUncovered = 100

	runContextKeyZoneRouting = "zone_routing"
	runContextKeyUncovered   = "uncovered_targets"
)

// zoneBatch is one command of a zoned run.
type zoneBatch struct {
	Zone     *scanzone.Zone // nil: unzoned public targets, dispatched as before zones
	Targets  []string
	SensorID *shared.ID // pinned sensor; nil = the zone's pool (or any tenant sensor when unzoned)
}

// zonePlan is how a run's targets are split over zones and sensors.
type zonePlan struct {
	Batches   []zoneBatch
	Uncovered []scanzone.Uncovered
	Warnings  []string
	Summary   map[string]any
}

// zoneRouted reports the zone routing for this run's tenant: the zones, or
// nil when the tenant has none (pre-zone behavior) or routing is not wired.
// A failed lookup stops the dispatch: without the zones nothing can tell a
// private target that must stay in its zone from one that may go anywhere.
func (s *Service) loadZones(ctx context.Context, tenantID shared.ID) ([]*scanzone.Zone, error) {
	if s.zones == nil {
		return nil, nil
	}
	zones, err := s.zones.List(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("scan zone lookup failed, scan not dispatched: %w", err)
	}
	return zones, nil
}

// toolReachesNetwork reports whether a scanner scans network targets, and so
// is subject to zone routing (RFC-023 D20). A tool whose supported targets
// are only files, repositories or containers (SAST, SCA, secrets, IaC) runs
// where the code is and is not routed. An unknown tool is routed (fail
// closed).
func (s *Service) toolReachesNetwork(ctx context.Context, name string) bool {
	if s.toolRepo == nil || name == "" {
		return true
	}
	t, err := s.toolRepo.GetByName(ctx, name)
	if err != nil || t == nil || len(t.SupportedTargets) == 0 {
		return true
	}
	for _, st := range t.SupportedTargets {
		switch strings.ToLower(st) {
		case "file", "repository", "container":
		default:
			return true
		}
	}
	return false
}

// planZoneDispatch routes targets to zones, batches them, and picks the least
// busy healthy sensor of each zone for each batch.
func (s *Service) planZoneDispatch(ctx context.Context, sc *scan.Scan, zones []*scanzone.Zone, targets []string) (*zonePlan, error) {
	routing := scanzone.NewRouter(zones, s.zoneResolver).Plan(ctx, targets)
	plan := &zonePlan{Uncovered: routing.Uncovered}

	batchSize := sc.TargetsPerJob
	if batchSize < 1 || !scannerAcceptsTargetList(sc.ScannerName) {
		batchSize = 1 // a scanner that reads one target gets one target per job
	}

	sensors, err := s.zones.RoutableSensors(ctx, sc.TenantID, routing.ZoneOrder, sc.ScannerName)
	if err != nil {
		return nil, fmt.Errorf("scan zone sensor lookup failed, scan not dispatched: %w", err)
	}

	zoneSummaries := make([]map[string]any, 0, len(routing.ZoneOrder))
	for _, zid := range routing.ZoneOrder {
		z := routing.Zones[zid]
		zoneTargets := routing.ByZone[zid]
		if len(z.SensorIDs) == 0 {
			for _, t := range zoneTargets {
				plan.Uncovered = append(plan.Uncovered, scanzone.Uncovered{
					Target: t,
					Reason: fmt.Sprintf("scan zone %q has no sensors assigned", z.Name),
				})
			}
			continue
		}
		cands := sensors[zid]
		load := make([]int, len(cands))
		for i, c := range cands {
			load[i] = c.ActiveCommands
		}
		var pinned []string
		queued := 0
		for _, chunk := range chunkTargets(zoneTargets, batchSize) {
			b := zoneBatch{Zone: z, Targets: chunk}
			if len(cands) > 0 {
				i := leastLoaded(load)
				load[i]++
				id := cands[i].ID
				b.SensorID = &id
				pinned = appendUnique(pinned, id.String())
			} else {
				queued++
			}
			plan.Batches = append(plan.Batches, b)
		}
		if queued > 0 {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf(
				"scan zone %q: no assigned sensor with %q is online; %d job(s) wait in the zone until one is",
				z.Name, sc.ScannerName, queued))
		}
		zoneSummaries = append(zoneSummaries, map[string]any{
			"zone_id":     z.ID.String(),
			"zone_name":   z.Name,
			"targets":     len(zoneTargets),
			"jobs":        len(chunkTargets(zoneTargets, batchSize)),
			"sensor_ids":  pinned,
			"queued_jobs": queued,
		})
	}
	for _, chunk := range chunkTargets(routing.Unzoned, batchSize) {
		plan.Batches = append(plan.Batches, zoneBatch{Targets: chunk})
	}
	if len(plan.Batches) > maxZoneJobsPerRun {
		return nil, shared.NewDomainError("TOO_MANY_JOBS", fmt.Sprintf(
			"scan %q would create %d jobs, more than the %d allowed per run; raise targets_per_job or split the scan",
			sc.Name, len(plan.Batches), maxZoneJobsPerRun), shared.ErrValidation)
	}

	for i, u := range plan.Uncovered {
		if i == maxListedUncovered {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("... and %d more target(s) not scanned", len(plan.Uncovered)-i))
			break
		}
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("%s not scanned: %s", u.Target, u.Reason))
	}
	plan.Summary = map[string]any{
		"zones":             zoneSummaries,
		"unzoned_targets":   len(routing.Unzoned),
		"uncovered_targets": len(plan.Uncovered),
		"jobs":              len(plan.Batches),
		"targets_per_job":   batchSize,
	}
	return plan, nil
}

// recordZonePlan writes the routing outcome into the run context: warnings
// for every target that is not scanned (never silently dropped, RFC-023 D5),
// the per-zone summary, and the uncovered targets with their reasons.
func recordZonePlan(sc *scan.Scan, plan *zonePlan, runContext map[string]any) error {
	var warnings []string
	if prev, ok := runContext["dispatch_warnings"].([]string); ok {
		for _, w := range prev {
			// One job per target in a zoned run: the single-target caveat no
			// longer applies.
			if !strings.HasPrefix(w, singleTargetWarningPrefix) {
				warnings = append(warnings, w)
			}
		}
	}
	warnings = append(warnings, plan.Warnings...)
	if len(warnings) > 0 {
		runContext["dispatch_warnings"] = warnings
	} else {
		delete(runContext, "dispatch_warnings")
	}
	runContext[runContextKeyZoneRouting] = plan.Summary
	if len(plan.Uncovered) > 0 {
		n := min(len(plan.Uncovered), maxListedUncovered)
		runContext[runContextKeyUncovered] = plan.Uncovered[:n]
	}
	if len(plan.Batches) == 0 {
		return shared.NewDomainError("NO_ZONE_COVERAGE", fmt.Sprintf(
			"No target of scan %q can be scanned: %d target(s) are outside every scan zone or in a zone without sensors. See the run warnings, or add the ranges to a zone.",
			sc.Name, len(plan.Uncovered)), shared.ErrValidation)
	}
	return nil
}

// createZoneCommands creates one command per batch of a zoned single-scanner
// run. Zone batches are stamped with their zone and pinned to the chosen
// sensor; they are never platform jobs (RFC-023 D14). Unzoned public batches
// follow the pre-zone platform/tenant rules.
func (s *Service) createZoneCommands(ctx context.Context, sc *scan.Scan, run *pipeline.Run, stepRun *pipeline.StepRun, plan *zonePlan) error {
	templates := s.customTemplatesForScan(ctx, sc)
	batchContext := batchRunContext(run.Context)

	created := make([]*command.Command, 0, len(plan.Batches))
	for _, b := range plan.Batches {
		cfg := batchScannerConfig(sc.ScannerConfig, b.Targets)
		payloadMap := s.scannerPayload(sc, run, stepRun, cfg, batchContext, b.Targets, templates)
		payload, err := json.Marshal(payloadMap)
		if err != nil {
			s.cancelCreated(ctx, created)
			return err
		}
		cmd, err := command.NewCommand(sc.TenantID, command.CommandTypeScan, command.CommandPriorityNormal, payload)
		if err != nil {
			s.cancelCreated(ctx, created)
			return err
		}
		if stepRun != nil {
			cmd.SetStepRunID(stepRun.ID) // the step finishes with its last batch
		}
		if b.Zone != nil {
			cmd.SetScanZone(b.Zone.ID)
			if b.SensorID != nil {
				cmd.SetSensorID(*b.SensorID)
			}
		} else {
			usePlatform, err := s.shouldUsePlatformSensor(ctx, sc, b.Targets)
			if err != nil {
				s.logger.Warn("failed to determine sensor selection, falling back to tenant only",
					"error", err, "scan_id", sc.ID.String())
				usePlatform = false
			}
			if usePlatform {
				cmd.SetPlatformJob(s.calculateInitialPriority(cmd.Priority))
			}
		}
		if err := s.commandRepo.Create(ctx, cmd); err != nil {
			s.cancelCreated(ctx, created)
			return err
		}
		created = append(created, cmd)
	}

	if stepRun != nil && len(created) > 0 {
		stepRun.CommandID = &created[0].ID
		stepRun.Queue()
		if err := s.stepRunRepo.Update(ctx, stepRun); err != nil {
			s.logger.Warn("failed to link step run to command",
				"run_id", run.ID.String(), "command_id", created[0].ID.String(), "error", err)
		}
	}
	return nil
}

// cancelCreated cancels the batches already created when a later one fails,
// so a run that reports failure does not leave half of its jobs running.
func (s *Service) cancelCreated(ctx context.Context, cmds []*command.Command) {
	for _, c := range cmds {
		c.Cancel()
		if err := s.commandRepo.Update(ctx, c); err != nil {
			s.logger.Warn("failed to cancel batch command", "command_id", c.ID.String(), "error", err)
		}
	}
}

// batchScannerConfig returns the scanner config for one batch: any target
// list carried in the config (quick scans store it there) is replaced by the
// batch, so a sensor never receives another zone's targets.
func batchScannerConfig(cfg map[string]any, targets []string) map[string]any {
	if cfg == nil {
		return nil
	}
	out := maps.Clone(cfg)
	if _, ok := out["targets"]; ok {
		out["targets"] = targets
	}
	if _, ok := out["target"]; ok {
		out["target"] = targets[0]
	}
	return out
}

// batchRunContext is the run context sent with each batch: without the
// run-wide target list and routing report, which name other zones' targets.
func batchRunContext(runContext map[string]any) map[string]any {
	out := maps.Clone(runContext)
	for _, k := range []string{"targets", "scanner_config", "dispatch_warnings", runContextKeyZoneRouting, runContextKeyUncovered} {
		delete(out, k)
	}
	return out
}

func chunkTargets(targets []string, size int) [][]string {
	if size < 1 {
		size = 1
	}
	var out [][]string
	for i := 0; i < len(targets); i += size {
		end := min(i+size, len(targets))
		out = append(out, targets[i:end])
	}
	return out
}

func leastLoaded(load []int) int {
	best := 0
	for i := 1; i < len(load); i++ {
		if load[i] < load[best] {
			best = i
		}
	}
	return best
}

func appendUnique(xs []string, x string) []string {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	return append(xs, x)
}

// routeWorkflowTargets applies zones to a workflow run. A workflow runs as one
// pipeline, so all of its routed targets must fall in one zone (or all be
// unzoned public targets); the run is stamped with that zone and every step
// command stays inside it.
func (s *Service) routeWorkflowTargets(ctx context.Context, sc *scan.Scan, zones []*scanzone.Zone, targets []string, runContext map[string]any) ([]string, error) {
	routing := scanzone.NewRouter(zones, s.zoneResolver).Plan(ctx, targets)
	plan := &zonePlan{Uncovered: routing.Uncovered}
	var kept []string
	switch {
	case len(routing.ZoneOrder) > 1 || (len(routing.ZoneOrder) == 1 && len(routing.Unzoned) > 0):
		names := make([]string, 0, len(routing.ZoneOrder))
		for _, id := range routing.ZoneOrder {
			names = append(names, routing.Zones[id].Name)
		}
		if len(routing.Unzoned) > 0 {
			names = append(names, "(no zone)")
		}
		return nil, shared.NewDomainError("ZONE_SPLIT_REQUIRED", fmt.Sprintf(
			"Workflow scan %q has targets in several scan zones (%s); a workflow runs in one zone, so split it into one scan per zone.",
			sc.Name, strings.Join(names, ", ")), shared.ErrValidation)
	case len(routing.ZoneOrder) == 1:
		z := routing.Zones[routing.ZoneOrder[0]]
		kept = routing.ByZone[z.ID]
		if len(z.SensorIDs) == 0 {
			for _, t := range kept {
				plan.Uncovered = append(plan.Uncovered, scanzone.Uncovered{Target: t, Reason: fmt.Sprintf("scan zone %q has no sensors assigned", z.Name)})
			}
			kept = nil
		} else {
			runContext[pipeline.RunContextKeyScanZoneID] = z.ID.String()
			plan.Batches = []zoneBatch{{Zone: z, Targets: kept}}
		}
	default:
		kept = routing.Unzoned
		if len(kept) > 0 {
			plan.Batches = []zoneBatch{{Targets: kept}}
		}
	}
	for i, u := range plan.Uncovered {
		if i == maxListedUncovered {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("... and %d more target(s) not scanned", len(plan.Uncovered)-i))
			break
		}
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("%s not scanned: %s", u.Target, u.Reason))
	}
	plan.Summary = map[string]any{
		"unzoned_targets":   len(routing.Unzoned),
		"uncovered_targets": len(plan.Uncovered),
	}
	if zid, ok := runContext[pipeline.RunContextKeyScanZoneID].(string); ok {
		plan.Summary["zone_id"] = zid
	}
	if err := recordZonePlan(sc, plan, runContext); err != nil {
		return nil, err
	}
	return kept, nil
}

// admitZonedPrivateTargets moves the private targets a scan zone of the
// tenant covers from result.Invalid to the returned list (RFC-023 D6). Every
// other rejection stays: loopback, link-local, the deny list, private space
// no zone covers, and anything invalid for another reason. Without zones it
// admits nothing.
func (s *Service) admitZonedPrivateTargets(ctx context.Context, tenantIDStr string, result *validator.TargetValidationResult) ([]string, error) {
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, nil //nolint:nilerr // no tenant, no zones: the strict result stands
	}
	zones, err := s.loadZones(ctx, tenantID)
	if err != nil || len(zones) == 0 {
		return nil, err
	}
	lenient := validator.NewTargetValidator(
		validator.WithAllowInternalIPs(true),
		validator.WithAllowLocalhost(false),
	)
	router := scanzone.NewRouter(zones, nil)

	var admitted []string
	remaining := result.Invalid[:0]
	for _, v := range result.Invalid {
		if isInternalIPRejection(v.Error) && lenient.ValidateSingleTarget(v.Original).IsValid {
			pt := scanzone.ParseTarget(v.Original)
			if pt.IsAddr {
				if rt := router.Route(ctx, v.Original); rt.Zone != nil && scanzone.IsPrivate(pt.Prefix.Addr()) {
					admitted = append(admitted, v.Original)
					continue
				}
			}
		}
		if pt := scanzone.ParseTarget(v.Original); isInternalIPRejection(v.Error) && pt.IsAddr &&
			scanzone.IsPrivate(pt.Prefix.Addr()) && !scanzone.IsDenied(pt.Prefix.Addr()) {
			v.Error = "private address outside every scan zone; add it to a zone's ranges to scan it (internal IP addresses are not allowed otherwise)"
		}
		remaining = append(remaining, v)
	}
	result.Invalid = remaining
	result.HasErrors = len(remaining) > 0
	result.BlockedIPs = result.BlockedIPs[:0]
	for _, v := range remaining {
		if isInternalIPRejection(v.Error) || strings.Contains(v.Error, "localhost") {
			result.BlockedIPs = append(result.BlockedIPs, v.Original)
		}
	}
	return admitted, nil
}

func isInternalIPRejection(msg string) bool {
	return strings.Contains(msg, "internal IP")
}
