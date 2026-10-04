package certmonitor

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Promotion turns names first seen in CT into inventory assets (RFC-036 P0/P1:
// "CT results never become assets"). It runs through the normal ingest path,
// so identity resolution, the exposure bridge and state history apply as for
// any other source, and records attribution evidence so every promoted asset
// says why it is believed to be the tenant's:
//
//   - under a verified domain: rule fqdn_under_verified_root (0.99, strong) →
//     confirmed (O4);
//   - under a domain asset or scope target the tenant did not verify: rule
//     fqdn_under_asserted_root (0.85) → needs_review. The asset is in the
//     inventory but no active check reaches it (scan targets skip it) until a
//     person confirms it.
//
// An asset that already existed keeps its standing: a legacy asset (no
// attribution record) is confirmed and stays so; evidence is added either
// way. Automation never lowers a state or overrides a human decision.

// AssetIngester is the slice of the ingest service promotion needs.
type AssetIngester interface {
	Ingest(ctx context.Context, agt *sensor.Sensor, input ingest.Input) (*ingest.Output, error)
}

// AssetNameLookup finds a tenant's existing assets by name.
type AssetNameLookup interface {
	GetByNames(ctx context.Context, tenantID shared.ID, names []string) (map[string]*assetdom.Asset, error)
}

// AttributionStore persists attribution and its evidence.
type AttributionStore interface {
	UpsertEvidence(ctx context.Context, tenantID shared.ID, ev []attribution.Evidence) error
	FiredRules(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string][]attribution.Rule, error)
	Records(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.Record, error)
	SaveAutomatic(ctx context.Context, tenantID shared.ID, assetID string, d attribution.Decision) error
}

// TombstoneChecker reports the names a person rejected (RFC-036 §6.4): for
// each name with an unexpired tombstone, the rules that supported it at
// rejection. Satisfied by *postgres.AttributionRepository.
type TombstoneChecker interface {
	Tombstoned(ctx context.Context, tenantID shared.ID, names []string) (map[string][]attribution.Rule, error)
	PurgeExpiredTombstones(ctx context.Context, tenantID shared.ID) (int64, error)
}

// SetTombstones makes promotion skip rejected names (nil: no check).
func (s *Service) SetTombstones(t TombstoneChecker) { s.tombstones = t }

// DefaultMaxPromotionsPerRun bounds how many CT names one tenant sweep turns
// into new assets. A wildcard-heavy or CDN domain can carry thousands of
// names; the rest are picked up on later runs (each run re-reads CT).
const DefaultMaxPromotionsPerRun = 500

// promotion is one name to promote, with the root that produced it.
type promotion struct {
	host   ctHost
	root   rootDomain
	source string
}

// SetPromotion enables promotion of CT names into assets. Any nil argument
// leaves promotion off (exposures only, the previous behavior).
func (s *Service) SetPromotion(ing AssetIngester, names AssetNameLookup, attr AttributionStore) {
	s.ingester, s.assetNames, s.attribution = ing, names, attr
}

func (s *Service) promotionEnabled() bool {
	return s.ingester != nil && s.assetNames != nil && s.attribution != nil
}

// ruleFor is the attribution rule a CT name earns from the root it was found
// under.
func ruleFor(root rootDomain) attribution.Rule {
	if root.origin == OriginVerified {
		return attribution.RuleVerifiedRoot
	}
	return attribution.RuleAssertedRoot
}

// promote writes the collected names as assets and evidence. It returns how
// many new assets were created. Failures are returned to the caller, which
// logs them; exposures were already written.
func (s *Service) promote(ctx context.Context, tenantID shared.ID, cands []promotion) (int, error) {
	if !s.promotionEnabled() || len(cands) == 0 {
		return 0, nil
	}
	// One entry per name: the strongest root wins (verified before asserted).
	byName := map[string]promotion{}
	for _, c := range cands {
		cur, ok := byName[c.host.Name]
		if !ok || originRank(c.root.origin) > originRank(cur.root.origin) {
			byName[c.host.Name] = c
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)

	existing, err := s.assetNames.GetByNames(ctx, tenantID, names)
	if err != nil {
		return 0, fmt.Errorf("look up existing assets: %w", err)
	}

	// New names, verified roots first, bounded per run. A name a person
	// rejected is not proposed again unless a rule that was not there at
	// rejection supports it now (tombstone, RFC-036 §6.4).
	var fresh []string
	for _, n := range names {
		if _, ok := existing[n]; !ok {
			fresh = append(fresh, n)
		}
	}
	if s.tombstones != nil && len(fresh) > 0 {
		dead, err := s.tombstones.Tombstoned(ctx, tenantID, fresh)
		if err != nil {
			return 0, fmt.Errorf("look up tombstones: %w", err)
		}
		kept := fresh[:0]
		for _, n := range fresh {
			if rules, ok := dead[n]; ok && containsRule(rules, ruleFor(byName[n].root)) {
				continue
			}
			kept = append(kept, n)
		}
		fresh = kept
	}
	sort.SliceStable(fresh, func(i, j int) bool {
		return originRank(byName[fresh[i]].root.origin) > originRank(byName[fresh[j]].root.origin)
	})
	if len(fresh) > s.maxPromotions {
		s.logger.Info("ct promotion: more new names than the per-run cap; the rest follow on later runs",
			"tenant_id", tenantID.String(), "cap", s.maxPromotions, "deferred", len(fresh)-s.maxPromotions)
		fresh = fresh[:s.maxPromotions]
	}

	created := map[string]string{} // name -> asset id
	if len(fresh) > 0 {
		report := s.promotionReport(tenantID, fresh, byName)
		agt := &sensor.Sensor{TenantID: &tenantID, Status: sensor.SensorStatusActive}
		out, err := s.ingester.Ingest(ctx, agt, ingest.Input{Report: report, CoverageType: ingest.CoverageTypePartial})
		if err != nil {
			return 0, fmt.Errorf("ingest CT names: %w", err)
		}
		for i := range report.Assets {
			if id, ok := out.AssetMap[report.Assets[i].ID]; ok && !id.IsZero() {
				created[report.Assets[i].Value] = id.String()
			}
		}
	}

	// Evidence for every name that is now an asset, new or old.
	assetIDs := make([]string, 0, len(byName))
	evidence := make([]attribution.Evidence, 0, len(names))
	for _, n := range names {
		var id string
		if a, ok := existing[n]; ok {
			id = a.ID().String()
		} else if cid, ok := created[n]; ok {
			id = cid
		} else {
			continue
		}
		p := byName[n]
		rule := ruleFor(p.root)
		w, _, _ := attribution.Weight(rule)
		evidence = append(evidence, attribution.Evidence{
			AssetID:   id,
			Rule:      rule,
			Technique: assetdom.DiscoverySourceCertTransparency,
			Source:    p.source,
			Weight:    w,
			Observed: map[string]any{
				"root":        p.root.name,
				"root_origin": p.root.origin,
				"first_seen":  p.host.FirstSeen.UTC().Format(time.RFC3339),
				"not_after":   p.host.NotAfter.UTC().Format(time.RFC3339),
				"issuer":      p.host.Issuer,
			},
		})
		assetIDs = append(assetIDs, id)
	}
	if err := s.attribution.UpsertEvidence(ctx, tenantID, evidence); err != nil {
		return len(created), err
	}

	fired, err := s.attribution.FiredRules(ctx, tenantID, assetIDs)
	if err != nil {
		return len(created), err
	}
	records, err := s.attribution.Records(ctx, tenantID, assetIDs)
	if err != nil {
		return len(created), err
	}
	isNew := map[string]bool{}
	for _, id := range created {
		isNew[id] = true
	}
	for _, id := range assetIDs {
		rec, hasRecord := records[id]
		if !hasRecord && !isNew[id] {
			// A legacy asset: confirmed by construction. Evidence only.
			continue
		}
		dec, err := attribution.Evaluate(fired[id])
		if err != nil {
			return len(created), err
		}
		var cur *attribution.Record
		if hasRecord {
			cur = &rec
		}
		if err := s.attribution.SaveAutomatic(ctx, tenantID, id, attribution.Merge(cur, dec)); err != nil {
			return len(created), err
		}
	}
	return len(created), nil
}

// promotionReport builds the CTIS report for the new names. root_domain is
// set only for roots the tenant owns an asset for or verified, so ingest's
// root auto-creation never invents a registrable domain from an unverified
// scope target.
func (s *Service) promotionReport(tenantID shared.ID, fresh []string, byName map[string]promotion) *ctis.Report {
	now := s.now()
	report := &ctis.Report{
		Version: "1.0",
		Metadata: ctis.ReportMetadata{
			ID:           "ct-promotion:" + tenantID.String() + ":" + now.Format(time.RFC3339),
			Timestamp:    now,
			SourceType:   "collector",
			CoverageType: "partial",
		},
		Tool: &ctis.Tool{Name: "cert-monitor", Vendor: "OpenCTEM", Capabilities: []string{"external"}},
	}
	for i, n := range fresh {
		p := byName[n]
		first := p.host.FirstSeen
		props := ctis.Properties{
			assetdom.PropKeyDiscoverySource: assetdom.DiscoverySourceCertTransparency,
			assetdom.PropKeyDiscoveryTool:   p.source,
		}
		if p.root.origin == OriginVerified || p.root.assetID != nil {
			props["root_domain"] = p.root.name
		}
		report.Assets = append(report.Assets, ctis.Asset{
			ID:           fmt.Sprintf("ct-%d", i),
			Type:         ctis.AssetTypeSubdomain,
			Value:        n,
			Name:         n,
			DiscoveredAt: &first,
			Properties:   props,
		})
	}
	return report
}

func containsRule(rules []attribution.Rule, r attribution.Rule) bool {
	for _, x := range rules {
		if x == r {
			return true
		}
	}
	return false
}
