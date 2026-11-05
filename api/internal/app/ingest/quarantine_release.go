package ingest

// Automatic release of out-of-contract holds.
//
// A report bound to a command that carries asset types its tool's signed
// descriptor does not declare is held (output_binding.go). The usual cause is
// a descriptor that lags the importer: the sensor's next release declares the
// type. Ingest never silently drops, and the tenant should not have to
// approve, one by one, what the tool's own current contract now allows. So
// when the sensor's CURRENT, verified descriptor declares what a held item
// carries, the platform re-checks the item against that descriptor and the
// platform catalog, exactly as a fresh report would be checked, and applies
// it through the same path as a person's accept. Anything else stays pending.
//
// An item is released only when all hold:
//   - same tenant, same (active) sensor, same tool as the descriptor's
//     sensor; reason out_of_contract; pending; younger than the retention;
//   - the sensor's current manifest was sent by the sensor itself (not derived
//     from a heartbeat) and its contract for the tool carries a descriptor
//     that hashes to the contract digest;
//   - the item's payload now splits cleanly: nothing in it is out of contract
//     under the catalog stages and that descriptor.
// The apply itself is the accept path: scope checks and every v2 protection
// run as for a person's accept. The release is audited as
// sensor_result.auto_accepted with the system as actor.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/ctis/v2"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Release bounds: items examined per run, groups listed per run, and how many
// held items one sweep page reads.
const (
	ReleaseBudgetPerRun = 100
	releaseGroupLimit   = 200
	releasePage         = 25
)

// ReleaseOptions narrow a release run.
type ReleaseOptions struct {
	// TenantID / SensorID restrict the run (the descriptor-change trigger
	// names its sensor); nil: every tenant.
	TenantID, SensorID *shared.ID
	// Retention: items older than it are left to the purge/people.
	Retention time.Duration
	// Budget bounds the items examined (<=0: ReleaseBudgetPerRun).
	Budget int
}

// ReleaseStats is what one run did.
type ReleaseStats struct {
	Groups   int
	Examined int
	Released int
	Kept     int
	Failed   int
}

type releaseCursor struct {
	digest  string
	created time.Time
	id      shared.ID
}

type releaseGroupKey struct {
	tenant, sensor shared.ID
	tool           string
}

// releaseState is the in-memory progress of the sweeps: for each group, the
// descriptor digest last evaluated and how far its pending items were
// examined, so a stuck item is not re-read every run. A restart, or a new
// descriptor digest, starts again.
type releaseState struct {
	mu      sync.Mutex // one run at a time
	cursors map[releaseGroupKey]releaseCursor
	// apply replaces applyQuarantined in tests.
	apply func(ctx context.Context, tenantID shared.ID, item *sensorresult.Item, reason string) error
}

// verifiedContract returns the contract of tool in the manifest when it is a
// descriptor the platform can trust to read as "declared": sent by the sensor
// (a heartbeat-derived manifest is the platform's own projection and
// declares nothing), with a full descriptor kept, which SanitizeToolDescriptor
// keeps only when it hashes to the contract digest.
func verifiedContract(v *sensor.ManifestVersion, tool string) *sensor.ToolContract {
	if v == nil || v.Source != sensor.ManifestSourceSensor {
		return nil
	}
	c := v.Manifest.ToolContract(tool)
	if c == nil || c.Digest == "" || len(c.Descriptor) == 0 {
		return nil
	}
	return c
}

// ReleaseOutOfContract re-evaluates pending out-of-contract holds against
// their tools' current verified descriptors and releases those that are now
// in contract. It is safe to run again and concurrently: one run at a time
// (a run that finds another busy returns at once), and each item is claimed
// before it is applied.
func (s *Service) ReleaseOutOfContract(ctx context.Context, o ReleaseOptions) (ReleaseStats, error) {
	var st ReleaseStats
	if s.results == nil || s.contracts == nil {
		return st, nil
	}
	if !s.release.mu.TryLock() {
		return st, nil
	}
	defer s.release.mu.Unlock()
	if s.release.cursors == nil {
		s.release.cursors = map[releaseGroupKey]releaseCursor{}
	}
	budget := o.Budget
	if budget <= 0 {
		budget = ReleaseBudgetPerRun
	}
	retention := o.Retention
	if retention <= 0 {
		retention = 30 * 24 * time.Hour
	}
	notBefore := time.Now().Add(-retention)
	groups, err := s.results.PendingOutOfContractGroups(ctx, notBefore, o.TenantID, o.SensorID, releaseGroupLimit)
	if err != nil {
		return st, err
	}
	for _, g := range groups {
		if budget <= 0 || ctx.Err() != nil {
			break
		}
		st.Groups++
		n, err := s.releaseGroup(ctx, g, notBefore, budget, &st)
		budget -= n
		if err != nil {
			s.logger.Warn("auto-release of held results stopped for a sensor", "sensor_id", g.SensorID.String(),
				"tool", sanitizeIngestLogField(g.ToolName), "error", logger.SanitizeError(err))
		}
	}
	return st, nil
}

// releaseGroup examines up to budget items of one group and returns how many
// it examined.
func (s *Service) releaseGroup(ctx context.Context, g sensorresult.HeldGroup, notBefore time.Time, budget int, st *ReleaseStats) (int, error) {
	// Tenant-scoped read of the sensor's CURRENT manifest.
	mv, err := s.contracts.CurrentManifest(ctx, &g.TenantID, g.SensorID)
	if err != nil {
		return 0, nil // no manifest: nothing can be declared
	}
	contract := verifiedContract(mv, g.ToolName)
	if contract == nil {
		return 0, nil
	}
	key := releaseGroupKey{tenant: g.TenantID, sensor: g.SensorID, tool: g.ToolName}
	cur := s.release.cursors[key]
	if cur.digest != contract.Digest {
		cur = releaseCursor{digest: contract.Digest}
	}
	rules := outputRules{stages: outputContract(g.ToolName), declared: contract}
	examined := 0
	for examined < budget {
		refs, err := s.results.PendingInGroup(ctx, g, notBefore, cur.created, cur.id, min(releasePage, budget-examined))
		if err != nil {
			s.release.cursors[key] = cur
			return examined, err
		}
		if len(refs) == 0 {
			break
		}
		for _, ref := range refs {
			if examined >= budget {
				break
			}
			examined++
			st.Examined++
			switch s.releaseOne(ctx, g, ref.ID, rules) {
			case releaseDone:
				st.Released++
			case releaseFailed:
				st.Failed++
			default:
				st.Kept++
			}
			cur.created, cur.id = ref.CreatedAt, ref.ID
		}
	}
	s.release.cursors[key] = cur
	return examined, nil
}

type releaseOutcome int

const (
	releaseKept releaseOutcome = iota
	releaseDone
	releaseFailed
)

// releaseOne re-checks one held item and applies it when it is now whole
// within the contract.
func (s *Service) releaseOne(ctx context.Context, g sensorresult.HeldGroup, id shared.ID, rules outputRules) releaseOutcome {
	item, err := s.results.Get(ctx, g.TenantID, id)
	if err != nil {
		return releaseKept
	}
	if item.Status != sensorresult.StatusPending || item.Reason != sensorresult.ReasonOutOfContract ||
		item.TenantID != g.TenantID || item.SensorID != g.SensorID || item.ToolName != g.ToolName || len(item.Payload) == 0 {
		return releaseKept
	}
	var report ctis.Report
	if json.Unmarshal(item.Payload, &report) != nil {
		return releaseKept
	}
	if sp := splitByContract(&report, rules); sp.anyHeld() {
		return releaseKept
	}
	types := declaredTypesOf(&report)
	if len(types) == 0 {
		return releaseKept
	}
	reason := "the tool's signed descriptor now declares " + strings.Join(types, ", ")
	var applyErr error
	if s.release.apply != nil {
		applyErr = s.release.apply(ctx, g.TenantID, item, reason)
	} else {
		_, applyErr = s.applyQuarantined(ctx, auditapp.AuditContext{TenantID: g.TenantID.String()}, g.TenantID, item, nil, &autoRelease{Reason: reason})
	}
	if applyErr != nil {
		metrics.SensorUnsolicitedResultsTotal.WithLabelValues("out_of_contract_release_failed").Inc()
		return releaseFailed
	}
	metrics.SensorUnsolicitedResultsTotal.WithLabelValues("out_of_contract_released").Inc()
	return releaseDone
}

// declaredTypesOf names what a report carries, in the labels a descriptor
// declares ("asset:web_origin", "finding:vulnerability", "dependency"),
// sorted and bounded.
func declaredTypesOf(r *ctis.Report) []string {
	set := map[string]bool{}
	for i := range r.Assets {
		set[sensor.ProduceAsset+":"+sanitizeContractLabel(string(r.Assets[i].Type))] = true
	}
	for i := range r.Findings {
		set[sensor.ProduceFinding+":"+sanitizeContractLabel(string(r.Findings[i].Type))] = true
	}
	if len(r.Dependencies) > 0 {
		set[sensor.ProduceDependency] = true
	}
	if len(r.Endpoints) > 0 {
		set[sensor.ProduceEndpoint] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > maxContractTypesLogged {
		out = append(out[:maxContractTypesLogged], fmt.Sprintf("and %d more", len(set)-maxContractTypesLogged))
	}
	return out
}

// ReleaseHeldForSensor is the descriptor-change trigger: it runs a bounded
// release for one sensor off the caller's path. A run already in progress
// makes it a no-op (the periodic sweep covers what it skipped).
func (s *Service) ReleaseHeldForSensor(tenantID, sensorID shared.ID, retention time.Duration) {
	if s == nil || s.results == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if _, err := s.ReleaseOutOfContract(ctx, ReleaseOptions{TenantID: &tenantID, SensorID: &sensorID, Retention: retention}); err != nil {
			s.logger.Warn("release of held results after a descriptor change failed", "sensor_id", sensorID.String(), "error", logger.SanitizeError(err))
		}
	}()
}
