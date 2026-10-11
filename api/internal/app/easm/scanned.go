package easm

// Attribution of what a sensor report wrote (RFC-036 §6.4; owner decision O8
// as narrowed by research/22 E7):
//
//   - a target the tenant typed gets tenant_scanned evidence (strong); an
//     automatic record is re-evaluated unless it is needs_review or
//     rejected, so a scan cannot launder a name past the review queue;
//   - a name the scan found while scanning something else gets
//     tenant_scan_discovered evidence (medium, never confirms on its own).
//     A new internet-facing name gets a needs_review record, or a confirmed
//     one when it is at or under a verified domain;
//   - an unsolicited report records nothing but a candidate record for a new
//     internet-facing asset;
//   - an existing asset without a record keeps having none (the active-scan
//     gate decides by scope target and seed), and a person's decision is
//     never touched.
//
// Which assets qualify is decided by ingest; this side records. Every write
// is tenant-scoped in the store: an asset id of another tenant writes nothing.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScanEvidenceStore is the storage the stamper needs.
type ScanEvidenceStore interface {
	// UpsertEvidenceBulk records one evidence row per asset (same rule,
	// technique, source, weight and datum) in one statement.
	UpsertEvidenceBulk(ctx context.Context, tenantID shared.ID, assetIDs []string, ev attribution.Evidence) error
	FiredRules(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string][]attribution.Rule, error)
	Records(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.Record, error)
	SaveAutomatic(ctx context.Context, tenantID shared.ID, assetID string, d attribution.Decision) error
	// ScanRunOf returns the scan run and scan of a step run in the
	// tenant ("" when unknown).
	ScanRunOf(ctx context.Context, tenantID, stepRunID shared.ID) (runID, scanID string, err error)
}

// VerifiedRoots lists the tenant's verified domains (*postgres.EASMSeedRepository).
type VerifiedRoots interface {
	VerifiedDomainNames(ctx context.Context, tenantID shared.ID) ([]string, error)
}

// ProgramAssigner keeps the tenant's program group assignments current
// (*postgres.BountyProgramRepository, RFC-065 §7).
type ProgramAssigner interface {
	AssignTenantPrograms(ctx context.Context, tenantID shared.ID) (int64, error)
}

// ScanStamper implements ingest.ScanAttributionStamper.
type ScanStamper struct {
	store ScanEvidenceStore
	roots VerifiedRoots
	join  *ScopeJoin
	// programs assigns new assets a program covers to its group, so the
	// program's researchers see what their scan found.
	programs ProgramAssigner
}

// SetProgramAssigner wires the program data scope.
func (s *ScanStamper) SetProgramAssigner(p ProgramAssigner) { s.programs = p }

// assignPrograms is best effort: the periodic pass repeats it.
func (s *ScanStamper) assignPrograms(ctx context.Context, tenantID shared.ID) {
	if s.programs != nil {
		_, _ = s.programs.AssignTenantPrograms(ctx, tenantID)
	}
}

// SetScopeJoin confirms the new names a scan found under a permanent scope
// target or seed of the tenant (RFC-054 §4.3). Nil: they go to review.
func (s *ScanStamper) SetScopeJoin(j *ScopeJoin) { s.join = j }

var _ ingest.ScanAttributionStamper = (*ScanStamper)(nil)

// NewScanStamper creates the stamper. roots may be nil: then no discovered
// name is confirmed through a verified domain (all go to review).
func NewScanStamper(store ScanEvidenceStore, roots VerifiedRoots) *ScanStamper {
	return &ScanStamper{store: store, roots: roots}
}

// TechniqueSensorScan is the technique of a tenant-scan sighting whose tool
// is unknown.
const TechniqueSensorScan = "sensor_scan"

// PlatformSensorSource is the evidence source of every sighting by a shared
// platform sensor: one source for all of them, so no tenant learns a
// platform sensor id.
const PlatformSensorSource = "sensor:platform"

// TechniqueVerifiedDomain is the technique of the verified-root evidence a
// scan-discovered name gets when it sits under a verified domain.
const TechniqueVerifiedDomain = "verified_domain"

// StampScanned records evidence and attribution for the assets a sensor
// report wrote.
func (s *ScanStamper) StampScanned(ctx context.Context, tenantID shared.ID, assets []ingest.ScannedAsset, prov ingest.ScanProvenance) error {
	if len(assets) == 0 || prov.SensorID.IsZero() {
		return nil
	}
	if prov.Unsolicited {
		return s.holdUnsolicited(ctx, tenantID, assets)
	}
	defer s.assignPrograms(ctx, tenantID)
	observed, err := s.observed(ctx, tenantID, prov)
	if err != nil {
		return err
	}
	technique := TechniqueSensorScan
	if prov.Tool != "" {
		technique = truncate(prov.Tool, 100)
	}
	// One row per (asset, rule, sensor): a re-scan refreshes the datum and
	// last_observed_at instead of piling up rows. Platform sensors share one
	// source: the tenant sees "the platform scanned", never which sensor.
	source := "sensor:" + prov.SensorID.String()
	if prov.Platform {
		source = PlatformSensorSource
	}

	all := make([]string, 0, len(assets))
	var typed, found []string
	byID := make(map[string]ingest.ScannedAsset, len(assets))
	for _, a := range assets {
		id := a.ID.String()
		byID[id] = a
		all = append(all, id)
		if a.Typed {
			typed = append(typed, id)
		} else {
			found = append(found, id)
		}
	}
	if err := s.evidence(ctx, tenantID, typed, attribution.RuleTenantScanned, technique, source, observed); err != nil {
		return err
	}
	if err := s.evidence(ctx, tenantID, found, attribution.RuleScanDiscovered, technique, source, observed); err != nil {
		return err
	}

	records, err := s.store.Records(ctx, tenantID, all)
	if err != nil {
		return err
	}
	// New internet-facing names the scan found get a record; one under a
	// verified domain gets the verified-root evidence first.
	var fresh []string
	for _, id := range found {
		a := byID[id]
		if _, has := records[id]; !has && a.Created && heldForReviewOnCreate(a.Type.Type, a.Type.SubType) {
			fresh = append(fresh, id)
		}
	}
	if err := s.verifiedEvidence(ctx, tenantID, fresh, byID); err != nil {
		return err
	}
	if err := s.scopeJoinEvidence(ctx, tenantID, fresh, byID); err != nil {
		return err
	}

	evaluate := toEvaluate(all, records, byID, fresh)
	if len(evaluate) == 0 {
		return nil
	}
	fired, err := s.store.FiredRules(ctx, tenantID, evaluate)
	if err != nil {
		return err
	}
	for _, id := range evaluate {
		dec, err := attribution.Evaluate(fired[id])
		if err != nil {
			return err
		}
		var current *attribution.Record
		if rec, has := records[id]; has {
			current = &rec
		}
		if err := s.store.SaveAutomatic(ctx, tenantID, id, attribution.Merge(current, dec)); err != nil {
			return err
		}
	}
	return nil
}

// toEvaluate picks the assets whose automatic record is (re)computed.
func toEvaluate(all []string, records map[string]attribution.Record, byID map[string]ingest.ScannedAsset, fresh []string) []string {
	out := make([]string, 0, len(all))
	for _, id := range all {
		rec, has := records[id]
		switch {
		case has && rec.HumanDecided:
			continue // a person decided; automation never overrides it
		case byID[id].Typed && has && (rec.State == attribution.StateNeedsReview || rec.State == attribution.StateRejected):
			continue // a scan of it does not take it past review (E7)
		case !has && !slices.Contains(fresh, id):
			continue // no record: the active-scan gate decides by scope and seed
		}
		out = append(out, id)
	}
	return out
}

// holdUnsolicited gives a new internet-facing asset from an unsolicited
// report a candidate record: hidden from the inventory and never probed
// until a person decides.
func (s *ScanStamper) holdUnsolicited(ctx context.Context, tenantID shared.ID, assets []ingest.ScannedAsset) error {
	var ids []string
	for _, a := range assets {
		if a.Created && heldForReviewOnCreate(a.Type.Type, a.Type.SubType) {
			ids = append(ids, a.ID.String())
		}
	}
	if len(ids) == 0 {
		return nil
	}
	records, err := s.store.Records(ctx, tenantID, ids)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, has := records[id]; has {
			continue
		}
		if err := s.store.SaveAutomatic(ctx, tenantID, id, attribution.Decision{State: attribution.StateCandidate}); err != nil {
			return err
		}
	}
	return nil
}

func (s *ScanStamper) observed(ctx context.Context, tenantID shared.ID, prov ingest.ScanProvenance) (map[string]any, error) {
	observed := map[string]any{
		"sensor_id":   prov.SensorID.String(),
		"observed_at": prov.ObservedAt.UTC().Format(time.RFC3339),
	}
	if prov.Platform {
		delete(observed, "sensor_id")
		observed["platform"] = true
	}
	if prov.CommandID != nil {
		observed["command_id"] = prov.CommandID.String()
	}
	if prov.Tool != "" {
		observed["tool"] = truncate(prov.Tool, 100)
	}
	if prov.ReportID != "" {
		observed["report_id"] = truncate(prov.ReportID, 200)
	}
	if prov.StepRunID != nil {
		observed["scan_run_step_id"] = prov.StepRunID.String()
		runID, scanID, err := s.store.ScanRunOf(ctx, tenantID, *prov.StepRunID)
		if err != nil {
			return nil, fmt.Errorf("resolve scan run: %w", err)
		}
		if runID != "" {
			observed["scan_run_id"] = runID
		}
		if scanID != "" {
			observed["scan_id"] = scanID
		}
	}
	return observed, nil
}

func (s *ScanStamper) evidence(ctx context.Context, tenantID shared.ID, ids []string, rule attribution.Rule, technique, source string, observed map[string]any) error {
	if len(ids) == 0 {
		return nil
	}
	w, _, err := attribution.Weight(rule)
	if err != nil {
		return err
	}
	return s.store.UpsertEvidenceBulk(ctx, tenantID, ids, attribution.Evidence{
		Rule: rule, Technique: technique, Source: source, Weight: w, Observed: observed,
	})
}

// verifiedEvidence records fqdn_under_verified_root on the fresh names at or
// under one of the tenant's verified domains (one row per root).
func (s *ScanStamper) verifiedEvidence(ctx context.Context, tenantID shared.ID, fresh []string, byID map[string]ingest.ScannedAsset) error {
	if len(fresh) == 0 || s.roots == nil {
		return nil
	}
	roots, err := s.roots.VerifiedDomainNames(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("list verified domains: %w", err)
	}
	byRoot := map[string][]string{}
	for _, id := range fresh {
		host := hostOf(byID[id].Name)
		if host == "" {
			continue
		}
		for _, r := range roots {
			r = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r), "."))
			if r != "" && (host == r || strings.HasSuffix(host, "."+r)) {
				byRoot[r] = append(byRoot[r], id)
				break
			}
		}
	}
	w, _, err := attribution.Weight(attribution.RuleVerifiedRoot)
	if err != nil {
		return err
	}
	for root, ids := range byRoot {
		if err := s.store.UpsertEvidenceBulk(ctx, tenantID, ids, attribution.Evidence{
			Rule: attribution.RuleVerifiedRoot, Technique: TechniqueVerifiedDomain, Source: "verified_domain:" + root,
			Weight: w, Observed: map[string]any{"root": root},
		}); err != nil {
			return err
		}
	}
	return nil
}

// scopeJoinEvidence records matches_scope_target on the fresh names a
// permanent scope target or seed covers. A failed lookup records nothing
// (the names go to review) and is logged by the caller's error path only
// when the store itself fails.
func (s *ScanStamper) scopeJoinEvidence(ctx context.Context, tenantID shared.ID, fresh []string, byID map[string]ingest.ScannedAsset) error {
	if len(fresh) == 0 || s.join == nil {
		return nil
	}
	items := make([]JoinItem, 0, len(fresh))
	for _, id := range fresh {
		a := byID[id]
		items = append(items, JoinItem{ID: id, Name: a.Name, Type: a.Type.Type, SubType: a.Type.SubType})
	}
	ev, err := s.join.Evidence(ctx, tenantID, items)
	if err != nil {
		s.join.log.Warn("scan attribution: scope join failed; names go to review", "error", err)
		return nil
	}
	for _, e := range ev {
		if err := s.store.UpsertEvidenceBulk(ctx, tenantID, []string{e.AssetID}, e); err != nil {
			return err
		}
	}
	return nil
}

// hostOf is the lower-case host an asset name names ("" for none).
func hostOf(name string) string { return asset.HostOf(name) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
