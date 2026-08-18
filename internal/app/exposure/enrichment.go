package exposure

import (
	"context"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	exposuredom "github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// Enrichment carries the CTEM signals attached to an exposure event at read
// time. It is computed additively — no exposure row is mutated or migrated — by
// reusing the SAME asset-reachability, effective-criticality and EPSS/KEV
// machinery that enriches findings, so an exposure now shows the business and
// threat context a finding does. Every field is optional (pointer / omitempty):
// an exposure with no linked asset or no CVE simply carries fewer signals.
type Enrichment struct {
	// EffectiveCriticality is MAX(asset own, its business unit, the services it
	// powers) — the same business-aligned criticality the priority engine uses.
	EffectiveCriticality string `json:"effective_criticality,omitempty"`
	// IsInternetAccessible reflects the linked asset's public exposure OR its
	// membership in a validated public→crown-jewel attack path.
	IsInternetAccessible *bool `json:"is_internet_accessible,omitempty"`
	// OnAttackPath is true when the linked asset sits on a validated attack path
	// from a public entry point to a KEV/crown-jewel target.
	OnAttackPath *bool `json:"on_attack_path,omitempty"`
	// EPSSScore / EPSSPercentile / IsInKEV / KEVDueDate are populated only when
	// the exposure carries a CVE id in its details (cve_id / cve).
	CVEID          string     `json:"cve_id,omitempty"`
	EPSSScore      *float64   `json:"epss_score,omitempty"`
	EPSSPercentile *float64   `json:"epss_percentile,omitempty"`
	IsInKEV        *bool      `json:"is_in_kev,omitempty"`
	KEVDueDate     *time.Time `json:"kev_due_date,omitempty"`
}

// EPSSData holds an EPSS score for a CVE. Mirrors the finding-side shape so the
// same threat-intel adapters can back both, without coupling this package to the
// finding package.
type EPSSData struct {
	Score      float64
	Percentile float64
}

// KEVData holds CISA KEV catalog info for a CVE.
type KEVData struct {
	DueDate *time.Time
}

// assetLookup is the minimal slice of asset.Repository the enricher needs. The
// concrete asset repository satisfies it.
type assetLookup interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*asset.Asset, error)
}

// businessContextLookup resolves per-asset business-unit / business-service
// criticality so an asset's EFFECTIVE criticality can be raised. Satisfied by
// the same postgres.NewBusinessContextLookupRepo the finding path uses.
type businessContextLookup interface {
	GetForAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]asset.BusinessContext, error)
}

// reachabilityOracle returns the tenant's set of attack-path-reachable asset ids
// (string form). Satisfied by the same oracle the priority engine uses.
type reachabilityOracle interface {
	ReachableFromPublic(ctx context.Context, tenantID shared.ID) (map[string]bool, error)
}

// epssLookup / kevLookup are the CVE-keyed threat-intel batch lookups. Wired
// from the same EPSS/KEV adapters the priority engine uses (adapted at the
// composition root to this package's data shapes).
type epssLookup interface {
	GetByCVEIDs(ctx context.Context, cveIDs []string) (map[string]EPSSData, error)
}
type kevLookup interface {
	GetByCVEIDs(ctx context.Context, cveIDs []string) (map[string]KEVData, error)
}

// ExposureEnricher computes read-time Enrichment for exposure events by reusing
// the finding-enrichment machinery. All dependencies are optional: a nil
// dependency simply omits that signal, so enrichment degrades gracefully and
// never blocks a list/get.
type ExposureEnricher struct {
	assetRepo       assetLookup
	businessContext businessContextLookup
	reachability    reachabilityOracle
	epss            epssLookup
	kev             kevLookup
	logger          *logger.Logger
}

// NewExposureEnricher creates an enricher. assetRepo may be nil (asset-derived
// signals are then simply not attached).
func NewExposureEnricher(assetRepo assetLookup, log *logger.Logger) *ExposureEnricher {
	return &ExposureEnricher{
		assetRepo: assetRepo,
		logger:    log.With("service", "exposure_enricher"),
	}
}

// SetBusinessContextLookup wires the BU / business-service criticality lookup
// used to raise an asset's effective criticality. Optional.
func (e *ExposureEnricher) SetBusinessContextLookup(l businessContextLookup) { e.businessContext = l }

// SetReachabilityOracle wires attack-path reachability. Optional.
func (e *ExposureEnricher) SetReachabilityOracle(o reachabilityOracle) { e.reachability = o }

// SetThreatIntel wires the EPSS + KEV CVE lookups. Optional.
func (e *ExposureEnricher) SetThreatIntel(epss epssLookup, kev kevLookup) {
	e.epss = epss
	e.kev = kev
}

// cveIDKeys are the details keys under which an exposure may carry a CVE id.
var cveIDKeys = []string{"cve_id", "cve"}

// EnrichBatch computes Enrichment for a batch of exposure events, keyed by event
// id. It is batch-first — one asset load per distinct asset, one reachability
// lookup, one business-context lookup, one EPSS + one KEV lookup for the whole
// batch — so it adds no per-event N+1. Best-effort: any dependency error is
// logged and that signal is simply omitted; a nil enricher yields an empty map.
func (e *ExposureEnricher) EnrichBatch(ctx context.Context, tenantID shared.ID, events []*exposuredom.ExposureEvent) map[shared.ID]Enrichment {
	out := make(map[shared.ID]Enrichment, len(events))
	if e == nil || len(events) == 0 {
		return out
	}

	// Distinct linked asset ids + distinct CVE ids across the batch.
	assetIDs := make([]shared.ID, 0)
	assetSeen := make(map[shared.ID]bool)
	cveByEvent := make(map[shared.ID]string)
	cveSet := make(map[string]bool)
	for _, ev := range events {
		if aid := ev.AssetID(); aid != nil && !aid.IsZero() && !assetSeen[*aid] {
			assetSeen[*aid] = true
			assetIDs = append(assetIDs, *aid)
		}
		if cve := extractCVE(ev); cve != "" {
			cveByEvent[ev.ID()] = cve
			cveSet[cve] = true
		}
	}

	// Load assets (one GetByID per distinct asset; a missing asset is skipped).
	assets := make(map[shared.ID]*asset.Asset, len(assetIDs))
	if e.assetRepo != nil {
		for _, aid := range assetIDs {
			a, err := e.assetRepo.GetByID(ctx, tenantID, aid)
			if err != nil {
				continue // asset gone / cross-tenant → simply no asset signal
			}
			assets[aid] = a
		}
	}

	// Batch business-context + reachability (each one tenant-scoped query).
	bizCtx := e.loadBusinessContext(ctx, tenantID, assetIDs)
	reachable := e.loadReachable(ctx, tenantID)

	// Batch EPSS + KEV over the distinct CVE ids.
	epssMap, kevMap := e.loadThreatIntel(ctx, cveSet)

	for _, ev := range events {
		var enr Enrichment

		if aid := ev.AssetID(); aid != nil && !aid.IsZero() {
			if a, ok := assets[*aid]; ok {
				eff, _ := asset.EffectiveCriticality(a.Criticality(), bizCtx[*aid])
				if eff == "" {
					eff = a.Criticality()
				}
				enr.EffectiveCriticality = string(eff)

				onPath := reachable[a.ID().String()]
				internet := a.IsInternetAccessible() || a.Exposure() == asset.ExposurePublic || onPath
				enr.IsInternetAccessible = boolPtr(internet)
				enr.OnAttackPath = boolPtr(onPath)
			}
		}

		if cve, ok := cveByEvent[ev.ID()]; ok {
			enr.CVEID = cve
			if d, ok := epssMap[cve]; ok {
				score := d.Score
				pct := d.Percentile
				enr.EPSSScore = &score
				enr.EPSSPercentile = &pct
			}
			if k, ok := kevMap[cve]; ok {
				enr.IsInKEV = boolPtr(true)
				enr.KEVDueDate = k.DueDate
			}
		}

		out[ev.ID()] = enr
	}

	return out
}

func (e *ExposureEnricher) loadBusinessContext(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) map[shared.ID]asset.BusinessContext {
	if e.businessContext == nil || len(assetIDs) == 0 {
		return nil
	}
	m, err := e.businessContext.GetForAssets(ctx, tenantID, assetIDs)
	if err != nil {
		e.logger.Warn("exposure enrichment: business context lookup failed",
			"tenant_id", tenantID.String(), "error", err.Error())
		return nil
	}
	return m
}

func (e *ExposureEnricher) loadReachable(ctx context.Context, tenantID shared.ID) map[string]bool {
	if e.reachability == nil {
		return nil
	}
	set, err := e.reachability.ReachableFromPublic(ctx, tenantID)
	if err != nil {
		e.logger.Warn("exposure enrichment: reachability lookup failed",
			"tenant_id", tenantID.String(), "error", err.Error())
		return nil
	}
	return set
}

func (e *ExposureEnricher) loadThreatIntel(ctx context.Context, cveSet map[string]bool) (map[string]EPSSData, map[string]KEVData) {
	if len(cveSet) == 0 {
		return nil, nil
	}
	cveIDs := make([]string, 0, len(cveSet))
	for cve := range cveSet {
		cveIDs = append(cveIDs, cve)
	}
	var epssMap map[string]EPSSData
	var kevMap map[string]KEVData
	if e.epss != nil {
		if m, err := e.epss.GetByCVEIDs(ctx, cveIDs); err == nil {
			epssMap = m
		} else {
			e.logger.Warn("exposure enrichment: EPSS lookup failed", "error", err.Error())
		}
	}
	if e.kev != nil {
		if m, err := e.kev.GetByCVEIDs(ctx, cveIDs); err == nil {
			kevMap = m
		} else {
			e.logger.Warn("exposure enrichment: KEV lookup failed", "error", err.Error())
		}
	}
	return epssMap, kevMap
}

// extractCVE reads a CVE id from an exposure's details (cve_id or cve),
// uppercased+trimmed to match the threat-intel catalog keys.
func extractCVE(ev *exposuredom.ExposureEvent) string {
	for _, key := range cveIDKeys {
		if v, ok := ev.GetDetail(key); ok {
			if s, ok := v.(string); ok {
				if s = strings.ToUpper(strings.TrimSpace(s)); strings.HasPrefix(s, "CVE-") {
					return s
				}
			}
		}
	}
	return ""
}

func boolPtr(b bool) *bool { return &b }
