package scan

// Continuous coverage runs (docs/rfcs/RFC-093-asset-coverage.md): the
// coverage planner starts one capability on a batch of due assets. Like an
// enrichment run, one target that may not be scanned never refuses the
// batch: it is reported with the gate's code and the rest runs. The run acts
// with the coverage policy's system authority (scope entries only, no member's act scope), at the
// capability's tier; an intrusive capability is never started this way.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// CoverageTag marks continuous coverage scans.
const CoverageTag = "auto-coverage"

// maxCoverageTargets caps one coverage run.
const maxCoverageTargets = 500

// defaultCoverageChunk is the targets per command when the stage names no
// chunk size.
const defaultCoverageChunk = 25

// CoverageScanName is the scan that carries one capability's coverage runs
// for a tenant: one per capability, reused by every batch.
func CoverageScanName(capability string) string { return "Continuous coverage: " + capability }

// CoverageInput is one batch of one capability.
type CoverageInput struct {
	TenantID   shared.ID
	Capability string
	Targets    []string
}

// CoverageResult is what was started. RunID is nil when nothing was left.
type CoverageResult struct {
	RunID *shared.ID
	Tool  string
	Kept  []string
	// Refused are the targets the gate refused, with its code.
	Refused []RefusedTarget
	// Deferred are targets left for a later batch (neither run nor
	// refused): a passive batch runs its public names and its routed
	// names in separate runs.
	Deferred []string
}

// ErrCoverageBusy: the capability's previous coverage run is still active;
// the batch waits for the next pass.
var ErrCoverageBusy = errors.New("coverage run of this capability still active")

// StartCoverage starts one capability on the targets, as the system.
func (s *Service) StartCoverage(ctx context.Context, in CoverageInput) (*CoverageResult, error) {
	if in.TenantID.IsZero() || len(in.Targets) == 0 {
		return nil, fmt.Errorf("%w: tenant and targets are required", shared.ErrValidation)
	}
	if len(in.Targets) > maxCoverageTargets {
		return nil, fmt.Errorf("%w: at most %d targets per coverage run", shared.ErrValidation, maxCoverageTargets)
	}
	st, ok := stage.Lookup(stage.Key(in.Capability))
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a stage", shared.ErrValidation, in.Capability)
	}
	if st.Tier >= stage.TierIntrusive {
		return nil, fmt.Errorf("%w: intrusive capabilities are never started by coverage", shared.ErrValidation)
	}
	tool := st.DefaultTool()
	if tool == "" {
		return nil, fmt.Errorf("%w: %s has no tool", shared.ErrValidation, in.Capability)
	}
	tier, intensity, passive := scopedom.TierActive, scan.IntensityActive, st.Tier == stage.TierPassive
	if passive {
		tier, intensity = scopedom.TierPassive, scan.IntensityPassive
	}
	targets, deferred, skipZones, err := s.coverageZoneGroup(ctx, in.TenantID, in.Targets, passive)
	if err != nil {
		return nil, err
	}
	if skipZones {
		// Only this function's own trigger below reads the marker.
		ctx = withoutZoneRouting(ctx)
	}
	gated, err := s.ResolveDispatchTargets(ctx, DispatchTargetsInput{
		TenantID: in.TenantID,
		Targets:  targets,
		// The policy's explicit system authority: scope entries and the
		// tier, never a member's act scope (and never "no actor").
		SystemPolicy: string(scan.ManagedByCoverage),
		// Coverage scans route automatically.
		Placement:   s.placementFor(ctx, in.TenantID, scan.SensorPreferenceAuto, false, false, tool),
		PassiveOnly: passive,
		Tier:        &tier,
		// Zone routing here: a target no zone can place is refused on its
		// own (zone_none, zone_no_sensor), so the rest of the batch runs.
		// A passive batch of public names skips it (coverageZoneGroup).
		SkipZoneRouting: skipZones,
		MaxTargets:      maxCoverageTargets,
		Path:            "auto_coverage",
		// What runs decides whether a name with no DNS answer may go
		// (a lookup-only capability such as resolve.dns runs on it).
		Tool:       tool,
		Capability: in.Capability,
	})
	if err != nil {
		return nil, fmt.Errorf("coverage targets not checked, nothing dispatched: %w", err)
	}
	res := &CoverageResult{Tool: tool, Refused: gated.Refused, Deferred: deferred}
	allowed := make(map[string]bool, len(gated.Allowed))
	for _, t := range gated.Allowed {
		allowed[strings.ToLower(t)] = true
	}
	for _, t := range gated.Excluded {
		res.Refused = append(res.Refused, RefusedTarget{Target: t, Code: "excluded", Reason: "excluded"})
	}
	for _, t := range targets {
		if allowed[strings.ToLower(strings.TrimSpace(t))] {
			res.Kept = append(res.Kept, strings.TrimSpace(t))
		}
	}
	if len(res.Kept) == 0 {
		return res, nil
	}

	sc, err := s.coverageScan(ctx, in.TenantID, in.Capability)
	if err != nil {
		return nil, err
	}
	sc.SetTargets(res.Kept)
	// One command per chunk of the stage's size (list tools are efficient
	// with lists), not one per target.
	perJob := coverageChunk(st, tool)
	if err := sc.SetSingleScanner(tool, map[string]any{"targets": res.Kept}, perJob); err != nil {
		return nil, fmt.Errorf("failed to set scanner: %w", err)
	}
	if err := s.applyIntensity(ctx, sc, string(intensity)); err != nil {
		return nil, err
	}
	if err := s.scanRepo.Update(ctx, sc); err != nil {
		return nil, fmt.Errorf("failed to update coverage scan: %w", err)
	}
	run, err := s.TriggerScan(ctx, TriggerScanExecInput{
		TenantID:      in.TenantID.String(),
		ScanID:        sc.ID.String(),
		SkipIfRunning: true,
		// A refusal pauses the capability (the planner maps it to a
		// readiness reason); it never becomes a blocked run per batch.
		NoBlockedRun: true,
		// The run is the coverage policy's: no person is behind it.
		TriggerType: scanworkflow.TriggerTypeSystem,
		TriggeredBy: PolicyTriggerPrefix + string(scan.ManagedByCoverage),
		Context:     map[string]any{"trigger": "auto_coverage", "capability": in.Capability, "target_count": len(res.Kept)},
	})
	if err != nil {
		if errors.Is(err, ErrScanRunInProgress) {
			return nil, ErrCoverageBusy
		}
		return nil, fmt.Errorf("failed to trigger coverage: %w", err)
	}
	res.RunID = &run.ID
	return res, nil
}

// coverageScan returns the tenant's coverage scan of a capability, creating
// it on first use. The scan is found by its managed key, never by name: a
// person's scan that carries the coverage scan's name is left alone and the
// managed scan is created under a different name. It is ad hoc (hidden from
// the configurations list).
func (s *Service) coverageScan(ctx context.Context, tenantID shared.ID, capability string) (*scan.Scan, error) {
	sc, err := s.scanRepo.GetManaged(ctx, tenantID, scan.ManagedByCoverage, capability)
	if err == nil {
		return sc, nil
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("load coverage scan: %w", err)
	}
	base := CoverageScanName(capability)
	var createErr error
	for _, name := range []string{base, base + " (platform)", ""} {
		if name == "" {
			name = fmt.Sprintf("%s (%s)", base, shared.NewID().String()[:8])
		}
		sc, err = scan.NewScan(tenantID, name, shared.ID{}, scan.ScanTypeSingle)
		if err != nil {
			return nil, fmt.Errorf("failed to create scan: %w", err)
		}
		sc.AdHoc = true
		sc.ManagedBy, sc.ManagedKey = scan.ManagedByCoverage, capability
		sc.Description = "Continuous coverage of every asset that needs " + capability
		sc.SetTags([]string{CoverageTag})
		if err := sc.SetSingleScanner(stageTool(capability), map[string]any{}, 1); err != nil {
			return nil, fmt.Errorf("failed to set scanner: %w", err)
		}
		if createErr = s.scanRepo.Create(ctx, sc); createErr == nil {
			s.logAudit(ctx, AuditContext{TenantID: tenantID.String()},
				NewSuccessEvent(audit.ActionScanConfigManagedCreated, audit.ResourceTypeScanConfig, sc.ID.String()).
					WithResourceName(sc.Name).
					WithMetadata("managed_by", string(scan.ManagedByCoverage)).
					WithMetadata("managed_key", capability))
			return sc, nil
		}
		if !errors.Is(createErr, shared.ErrAlreadyExists) {
			break
		}
		// Another replica created it first, or the name is taken: look again.
		if got, gerr := s.scanRepo.GetManaged(ctx, tenantID, scan.ManagedByCoverage, capability); gerr == nil {
			return got, nil
		}
	}
	return nil, fmt.Errorf("failed to create coverage scan: %w", createErr)
}

// coverageChunk is how many targets one task of a coverage run of the stage
// carries with tool.
func coverageChunk(st stage.Stage, tool string) int {
	if n := st.ChunkSizeFor(tool); n > 0 {
		return n
	}
	return defaultCoverageChunk
}

// CoverageChunkSize is how many targets one task of a coverage run of the
// capability carries (its default tool's chunk size): the size of a batch
// that fills one task. 0 for a capability that is not a stage.
func CoverageChunkSize(capability string) int {
	st, ok := stage.Lookup(stage.Key(capability))
	if !ok {
		return 0
	}
	return coverageChunk(st, st.DefaultTool())
}

func stageTool(capability string) string {
	st, _ := stage.Lookup(stage.Key(capability))
	return st.DefaultTool()
}

// zoneRoutingKey marks a context whose coverage trigger skips zone routing.
// It is unexported: only StartCoverage sets it, for a passive batch of
// public names, and no request can.
type zoneRoutingKey struct{}

func withoutZoneRouting(ctx context.Context) context.Context {
	return context.WithValue(ctx, zoneRoutingKey{}, true)
}

func zoneRoutingSkipped(ctx context.Context) bool {
	v, _ := ctx.Value(zoneRoutingKey{}).(bool)
	return v
}

// coverageZoneGroup picks the targets of one coverage run. A passive
// capability (a DNS resolution, a registration or network owner lookup,
// subdomain discovery from passive sources) sends no traffic to the target,
// so a public name needs no zone: routing it would refuse exactly the names
// that stopped resolving, whose DNS re-check is the point. A name is public
// when it is registrable under an ICANN public suffix and none of the
// addresses it resolves to from the platform is private or denied; an
// internal name keeps zone routing (its resolver is inside the zone), and
// so does every address. Without zones, or for an active capability,
// nothing changes. One run is either public names (zone routing skipped)
// or routed targets: the group of the batch's first (oldest) target runs
// now, the other is deferred to a later batch.
func (s *Service) coverageZoneGroup(ctx context.Context, tenantID shared.ID, targets []string, passive bool) (run, deferred []string, skipZones bool, err error) {
	if !passive {
		return targets, nil, false, nil
	}
	zones, err := s.loadZones(ctx, tenantID)
	if err != nil {
		return nil, nil, false, err
	}
	if len(zones) == 0 {
		return targets, nil, false, nil
	}
	plan := scanzone.NewRouter(zones, s.zoneResolver).Plan(ctx, targets)
	public := make([]bool, len(targets))
	for i, rt := range plan.Routes {
		public[i] = publicName(rt)
	}
	first := len(targets) > 0 && public[0]
	for i, t := range targets {
		if public[i] == first {
			run = append(run, t)
		} else {
			deferred = append(deferred, t)
		}
	}
	return run, deferred, first, nil
}

// specialUseSuffixes are the names reserved for local, private or
// documentation use (RFC 6761, RFC 6762, RFC 8375, RFC 7686, RFC 6303 and
// the private-use "internal"): never public, whatever the public suffix
// list says. Such a name keeps zone routing.
var specialUseSuffixes = []string{
	"home.arpa", "in-addr.arpa", "ip6.arpa", "local", "localhost", "internal",
	"test", "invalid", "onion", "example",
}

// specialUseName reports whether host is, or is under, a special-use name.
func specialUseName(host string) bool {
	for _, s := range specialUseSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// publicName reports whether a routed target is a public name: a hostname
// registrable under an ICANN public suffix whose platform resolution, if
// any, has no private or denied address.
func publicName(rt scanzone.Route) bool {
	pt := scanzone.ParseTarget(rt.Target)
	if pt.IsAddr || pt.Host == "" || strings.HasPrefix(pt.Host, "*") {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(pt.Host, "."))
	if specialUseName(host) {
		return false
	}
	if _, icann := publicsuffix.PublicSuffix(host); !icann {
		return false
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(host); err != nil {
		return false
	}
	for _, a := range rt.Addrs {
		if scanzone.IsPrivate(a) || scanzone.IsDenied(a) {
			return false
		}
	}
	return !rt.OutsideZones
}
