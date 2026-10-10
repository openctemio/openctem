package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/validator"
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
	// runContextKeyPerTarget records an unzoned run fanned out one command
	// per target (perTargetPlan).
	runContextKeyPerTarget = "per_target_dispatch"
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
	Routing   *scanzone.Plan // where each target went
	// PolicyRefused explains, per zone, the targets no zone sensor's local
	// policy accepts (research/25 §3.6); they are in Uncovered too.
	PolicyRefused []string
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
func (s *Service) toolReachesNetwork(ctx context.Context, tenantID shared.ID, name string) bool {
	if s.toolRepo == nil || name == "" {
		return true
	}
	t, err := s.toolRepo.GetByName(ctx, tenantID, name)
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

// selectedZone returns the zone a scan is pinned to (the zone picker), or nil
// for Automatic routing. A scan pinned to a zone that no longer exists fails
// closed: it is never quietly routed automatically instead.
func selectedZone(sc *scan.Scan, zones []*scanzone.Zone) (*scanzone.Zone, error) {
	if sc.ScanZoneID == nil || sc.ScanZoneID.IsZero() {
		return nil, nil
	}
	for _, z := range zones {
		if z.ID == *sc.ScanZoneID {
			return z, nil
		}
	}
	return nil, shared.NewDomainError("SCAN_ZONE_NOT_FOUND", fmt.Sprintf(
		"Scan %q is pinned to a scan zone that no longer exists; pick another zone or Automatic routing.",
		sc.Name), shared.ErrValidation)
}

// routeForScan routes a scan's targets: to the narrowest zone (Automatic), or
// only into the scan's selected zone, whose ranges are always enforced.
func (s *Service) routeForScan(ctx context.Context, sc *scan.Scan, zones []*scanzone.Zone, targets []string) (*scanzone.Plan, error) {
	sel, err := selectedZone(sc, zones)
	if err != nil {
		return nil, err
	}
	if sel != nil {
		return scanzone.NewRouter([]*scanzone.Zone{sel}, s.zoneResolver).Plan(ctx, targets).RestrictTo(sel), nil
	}
	return scanzone.NewRouter(zones, s.zoneResolver).Plan(ctx, targets), nil
}

// planZoneDispatch routes targets to zones, batches them, and picks the least
// busy healthy sensor of each zone for each batch.
func (s *Service) planZoneDispatch(ctx context.Context, sc *scan.Scan, zones []*scanzone.Zone, targets []string) (*zonePlan, error) {
	routing, err := s.routeForScan(ctx, sc, zones, targets)
	if err != nil {
		return nil, err
	}
	return s.planZoneBatches(ctx, sc, routing)
}

// planZoneBatches batches a routing plan and pins each batch to the least busy
// healthy sensor of its zone. It reads sensor load and writes nothing.
func (s *Service) planZoneBatches(ctx context.Context, sc *scan.Scan, routing *scanzone.Plan) (*zonePlan, error) {
	plan := &zonePlan{Uncovered: slices.Clone(routing.Uncovered), Routing: routing}

	batchSize := zoneBatchSize(sc)

	sensors, err := s.zones.RoutableSensors(ctx, sc.TenantID, routing.ZoneOrder, sc.ScannerName)
	if err != nil {
		return nil, fmt.Errorf("scan zone sensor lookup failed, scan not dispatched: %w", err)
	}
	opts, err := s.dispatchOptions(ctx, sc.TenantID)
	if err != nil {
		return nil, err
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
		reports := make([]*sensor.LocalPolicyReport, len(cands))
		for i, c := range cands {
			load[i] = c.ActiveCommands
			reports[i] = c.LocalPolicy
		}
		var pinned []string
		queued, jobs := 0, 0
		for _, chunk := range chunkTargets(zoneTargets, batchSize) {
			b := zoneBatch{Zone: z, Targets: chunk}
			if len(cands) > 0 {
				// Only a sensor whose reported local policy accepts the
				// batch is a candidate (sensor.Accepts).
				v := judge(reports, scanJob(sc, chunk), opts)
				if len(v.accepted) == 0 {
					reason := v.reason(fmt.Sprintf("scan zone %q", z.Name))
					plan.PolicyRefused = appendUnique(plan.PolicyRefused, reason)
					for _, t := range chunk {
						plan.Uncovered = append(plan.Uncovered, scanzone.Uncovered{Target: t, Reason: reason})
					}
					continue
				}
				i := leastLoadedOf(load, v.accepted)
				load[i]++
				id := cands[i].ID
				b.SensorID = &id
				pinned = appendUnique(pinned, id.String())
			} else {
				queued++
			}
			jobs++
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
			"jobs":        jobs,
			"sensor_ids":  pinned,
			"queued_jobs": queued,
		})
	}
	for _, chunk := range chunkTargets(routing.Unzoned, batchSize) {
		plan.Batches = append(plan.Batches, zoneBatch{Targets: chunk})
	}
	if len(plan.Batches) > maxZoneJobsPerRun {
		return nil, tooManyJobsError(sc, len(plan.Batches))
	}

	plan.Warnings = append(plan.Warnings, uncoveredWarnings(plan.Uncovered)...)
	plan.Summary = map[string]any{
		"zones":             zoneSummaries,
		"unzoned_targets":   len(routing.Unzoned),
		"uncovered_targets": len(plan.Uncovered),
		"jobs":              len(plan.Batches),
		"targets_per_job":   batchSize,
	}
	if sc.ScanZoneID != nil {
		plan.Summary["selected_zone_id"] = sc.ScanZoneID.String()
	}
	return plan, nil
}

// tooManyJobsError refuses a run that would create more than
// maxZoneJobsPerRun commands. A scanner that reads one target per job cannot
// be batched, so the advice differs.
func tooManyJobsError(sc *scan.Scan, jobs int) error {
	advice := "raise targets_per_job or split the scan"
	if !scannerAcceptsTargetList(sc.ScannerName) {
		advice = fmt.Sprintf("%q scans one target per job; split the scan into runs of at most %d targets", sc.ScannerName, maxZoneJobsPerRun)
	}
	return shared.NewDomainError("TOO_MANY_JOBS", fmt.Sprintf(
		"scan %q would create %d jobs, more than the %d allowed per run; %s",
		sc.Name, jobs, maxZoneJobsPerRun, advice), shared.ErrValidation)
}

// perTargetPlan is the dispatch plan of an unzoned run of a scanner that
// reads one target per job (trivy, semgrep, betterleaks, ...): one unzoned
// batch per target, created like zone batches (createZoneCommands) so the
// step completes with the last one (checkStepBatches). nil when the run is a
// single command: one target, or a scanner that reads the whole list.
//
// Before this, such a run sent every target in one command and the sensor
// scanned only the first (RFC-030 B4).
func perTargetPlan(sc *scan.Scan, targets []string) (*zonePlan, error) {
	if len(targets) < 2 || scannerAcceptsTargetList(sc.ScannerName) {
		return nil, nil
	}
	if len(targets) > maxZoneJobsPerRun {
		return nil, tooManyJobsError(sc, len(targets))
	}
	plan := &zonePlan{Batches: make([]zoneBatch, 0, len(targets))}
	for _, chunk := range chunkTargets(targets, 1) {
		plan.Batches = append(plan.Batches, zoneBatch{Targets: chunk})
	}
	return plan, nil
}

// recordPerTargetPlan writes a per-target fan-out into the run context.
func recordPerTargetPlan(plan *zonePlan, runContext map[string]any) {
	runContext[runContextKeyPerTarget] = map[string]any{
		"jobs":            len(plan.Batches),
		"targets_per_job": 1,
	}
}

// zoneBatchSize is how many targets go in one command of a zoned run.
func zoneBatchSize(sc *scan.Scan) int {
	if sc.TargetsPerJob < 1 || !scannerAcceptsTargetList(sc.ScannerName) {
		return 1 // a scanner that reads one target gets one target per job
	}
	return sc.TargetsPerJob
}

// uncoveredWarnings lists every target that is not scanned, with its reason
// (bounded; the rest are counted).
func uncoveredWarnings(uncovered []scanzone.Uncovered) []string {
	out := make([]string, 0, min(len(uncovered), maxListedUncovered+1))
	for i, u := range uncovered {
		if i == maxListedUncovered {
			out = append(out, fmt.Sprintf("... and %d more target(s) not scanned", len(uncovered)-i))
			break
		}
		out = append(out, fmt.Sprintf("%s not scanned: %s", u.Target, u.Reason))
	}
	return out
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
	if len(plan.Batches) == 0 && len(plan.PolicyRefused) > 0 {
		return policyRefusedError(sc, plan.PolicyRefused)
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
func (s *Service) createZoneCommands(ctx context.Context, sc *scan.Scan, run *scanrun.Run, stepRun *scanrun.StepRun, plan *zonePlan, usePlatform bool) error {
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
		cmd.DispatchGate = scanDispatchGate(sc, run)
		if b.Zone != nil {
			cmd.SetScanZone(b.Zone.ID)
			if b.SensorID != nil {
				cmd.SetSensorID(*b.SensorID)
			}
		} else {
			// Unzoned batches follow the routing decided before the run
			// was created (decideSensorRouting); nothing is re-decided here.
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

// leastLoadedOf returns the index, among idx, of the least loaded sensor.
func leastLoadedOf(load []int, idx []int) int {
	best := idx[0]
	for _, i := range idx[1:] {
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
// scan workflow, so all of its routed targets must fall in one zone (or all be
// unzoned public targets); the run is stamped with that zone and every step
// command stays inside it.
func (s *Service) routeWorkflowTargets(ctx context.Context, sc *scan.Scan, zones []*scanzone.Zone, targets []string, runContext map[string]any) ([]string, error) {
	routing, err := s.routeForScan(ctx, sc, zones, targets)
	if err != nil {
		return nil, err
	}
	plan, kept, err := planWorkflowZone(sc, routing)
	if err != nil {
		return nil, err
	}
	if zid, ok := plan.Summary["zone_id"].(string); ok {
		runContext[scanrun.RunContextKeyScanZoneID] = zid
	}
	if err := recordZonePlan(sc, plan, runContext); err != nil {
		return nil, err
	}
	return kept, nil
}

// planWorkflowZone decides the one zone of a workflow run from its routing.
// It returns ZONE_SPLIT_REQUIRED when the targets span zones.
func planWorkflowZone(sc *scan.Scan, routing *scanzone.Plan) (*zonePlan, []string, error) {
	plan := &zonePlan{Uncovered: slices.Clone(routing.Uncovered), Routing: routing}
	var kept []string
	var zoneID string
	switch {
	case len(routing.ZoneOrder) > 1 || (len(routing.ZoneOrder) == 1 && len(routing.Unzoned) > 0):
		names := make([]string, 0, len(routing.ZoneOrder)+1)
		for _, id := range routing.ZoneOrder {
			names = append(names, routing.Zones[id].Name)
		}
		if len(routing.Unzoned) > 0 {
			names = append(names, "(no zone)")
		}
		return nil, nil, shared.NewDomainError("ZONE_SPLIT_REQUIRED", fmt.Sprintf(
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
			zoneID = z.ID.String()
			plan.Batches = []zoneBatch{{Zone: z, Targets: kept}}
		}
	default:
		kept = routing.Unzoned
		if len(kept) > 0 {
			plan.Batches = []zoneBatch{{Targets: kept}}
		}
	}
	plan.Warnings = uncoveredWarnings(plan.Uncovered)
	plan.Summary = map[string]any{
		"unzoned_targets":   len(routing.Unzoned),
		"uncovered_targets": len(plan.Uncovered),
	}
	if zoneID != "" {
		plan.Summary["zone_id"] = zoneID
	}
	if sc.ScanZoneID != nil {
		plan.Summary["selected_zone_id"] = sc.ScanZoneID.String()
	}
	return plan, kept, nil
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
