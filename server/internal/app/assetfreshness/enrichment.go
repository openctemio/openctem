package assetfreshness

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/metrics"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	freshdom "github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Enrichment defaults (docs/architecture/asset-freshness.md).
const (
	DefaultDailyBudget = 2000
	DefaultBatch       = 500
	DefaultDebounce    = time.Minute
	DefaultBurst       = 200
	DefaultCooldown    = 6 * time.Hour
)

// AssetsByID loads the tenant's assets by id (*postgres.AssetRepository).
type AssetsByID interface {
	GetByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[string]*assetdom.Asset, error)
}

// EASMSettingsReader reads the tenant's attack-surface settings, where the
// automatic enrichment switch lives (*tenant.TenantService).
type EASMSettingsReader interface {
	GetEASMSettings(ctx context.Context, tenantID string) (*tenant.EASMSettings, error)
}

// RunStarter starts a passive run of a profile (*scan.Service).
type RunStarter interface {
	StartEnrichment(ctx context.Context, in scan.EnrichmentInput) (*scan.EnrichmentResult, error)
}

// EnricherConfig bounds the work. Zero values take the defaults.
type EnricherConfig struct {
	DailyBudget int
	Batch       int
	Debounce    time.Duration
	Burst       int
	Cooldown    time.Duration
}

func (c EnricherConfig) withDefaults() EnricherConfig {
	if c.DailyBudget <= 0 {
		c.DailyBudget = DefaultDailyBudget
	}
	if c.Batch <= 0 || c.Batch > DefaultBatch {
		c.Batch = DefaultBatch
	}
	if c.Debounce <= 0 {
		c.Debounce = DefaultDebounce
	}
	if c.Burst <= 0 {
		c.Burst = DefaultBurst
	}
	if c.Cooldown <= 0 {
		c.Cooldown = DefaultCooldown
	}
	return c
}

// Enricher records enrichment requests and turns them into passive runs of
// the built-in profiles.
type Enricher struct {
	requests freshdom.RequestRepository
	assets   AssetsByID
	settings EASMSettingsReader
	starter  RunStarter
	cfg      EnricherConfig
	now      func() time.Time
	logger   *logger.Logger
}

// NewEnricher creates the enricher.
func NewEnricher(requests freshdom.RequestRepository, assets AssetsByID, settings EASMSettingsReader, starter RunStarter, cfg EnricherConfig, log *logger.Logger) *Enricher {
	return &Enricher{requests: requests, assets: assets, settings: settings, starter: starter,
		cfg: cfg.withDefaults(), now: time.Now, logger: log.With("component", "asset-enrichment")}
}

// RequestAssets records a request for every asset a profile enriches. It
// never fails the caller (asset creation): an error is logged and counted.
func (e *Enricher) RequestAssets(ctx context.Context, tenantID shared.ID, assets []*assetdom.Asset, reason freshdom.Reason) {
	if e == nil || len(assets) == 0 {
		return
	}
	ids := make([]shared.ID, 0, len(assets))
	for _, a := range assets {
		if a == nil || a.Status() == assetdom.StatusArchived {
			continue
		}
		if _, ok := freshdom.ProfileFor(a.Type()); ok {
			ids = append(ids, a.ID())
		}
	}
	if len(ids) == 0 {
		return
	}
	n, err := e.requests.Request(ctx, tenantID, ids, reason, e.cfg.Cooldown)
	if err != nil {
		metrics.AssetEnrichmentSkippedTotal.WithLabelValues("request_error").Inc()
		e.logger.Warn("enrichment not requested", "tenant_id", tenantID.String(), "assets", len(ids),
			"error", logger.SanitizeError(err))
		return
	}
	metrics.AssetEnrichmentRequestsTotal.WithLabelValues(string(reason)).Add(float64(n))
}

// Run processes every tenant whose requests are due. Returns how many
// requests it settled. One tenant's failure does not stop the others.
func (e *Enricher) Run(ctx context.Context) (int, error) {
	tenants, err := e.requests.TenantsDue(ctx, e.cfg.Debounce, e.cfg.Burst)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, t := range tenants {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		n, err := e.runTenant(ctx, t)
		total += n
		if err != nil {
			e.logger.Warn("enrichment of a tenant failed", "tenant_id", t.String(), "error", logger.SanitizeError(err))
		}
	}
	return total, nil
}

func (e *Enricher) runTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	es, err := e.settings.GetEASMSettings(ctx, tenantID.String())
	if err != nil {
		// Fail closed: without the tenant's switch nothing is dispatched;
		// the requests stay pending for the next tick.
		return 0, fmt.Errorf("read settings: %w", err)
	}
	if es.EnrichmentDisabled {
		ids, err := e.requests.Claim(ctx, tenantID, e.cfg.Batch)
		if err != nil {
			return 0, err
		}
		metrics.AssetEnrichmentSkippedTotal.WithLabelValues("disabled").Add(float64(len(ids)))
		return len(ids), e.requests.Settle(ctx, tenantID, ids, freshdom.OutcomeDisabled, nil)
	}
	used, err := e.requests.DispatchedSince(ctx, tenantID, e.now().Add(-24*time.Hour))
	if err != nil {
		return 0, err
	}
	limit := min(e.cfg.Batch, e.cfg.DailyBudget-used)
	if limit <= 0 {
		metrics.AssetEnrichmentSkippedTotal.WithLabelValues("budget").Inc()
		return 0, nil
	}
	ids, err := e.requests.Claim(ctx, tenantID, limit)
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	found, err := e.assets.GetByIDs(ctx, tenantID, ids)
	if err != nil {
		// Claimed but not dispatched: settle as failed so they are visible.
		e.settle(ctx, tenantID, ids, freshdom.OutcomeFailed, nil)
		return len(ids), fmt.Errorf("load assets: %w", err)
	}
	groups, none := groupByProfile(ids, found)
	if len(none) > 0 {
		metrics.AssetEnrichmentSkippedTotal.WithLabelValues("no_profile").Add(float64(len(none)))
		if err := e.requests.Settle(ctx, tenantID, none, freshdom.OutcomeNoProfile, nil); err != nil {
			return len(ids), err
		}
	}
	for _, g := range groups {
		e.dispatch(ctx, tenantID, g)
	}
	return len(ids), nil
}

type profileBatch struct {
	profile freshdom.Profile
	byName  map[string][]shared.ID // lower-cased name -> assets
	names   []string
}

func groupByProfile(ids []shared.ID, found map[string]*assetdom.Asset) ([]*profileBatch, []shared.ID) {
	var none []shared.ID
	byKey := map[string]*profileBatch{}
	var order []*profileBatch
	for _, id := range ids {
		a := found[id.String()]
		if a == nil || a.Status() == assetdom.StatusArchived {
			none = append(none, id)
			continue
		}
		p, ok := freshdom.ProfileFor(a.Type())
		if !ok {
			none = append(none, id)
			continue
		}
		g := byKey[p.Key]
		if g == nil {
			g = &profileBatch{profile: p, byName: map[string][]shared.ID{}}
			byKey[p.Key] = g
			order = append(order, g)
		}
		key := strings.ToLower(strings.TrimSpace(a.Name()))
		if _, dup := g.byName[key]; !dup {
			g.names = append(g.names, strings.TrimSpace(a.Name()))
		}
		g.byName[key] = append(g.byName[key], id)
	}
	return order, none
}

// dispatch starts one run of a profile and settles its requests.
func (e *Enricher) dispatch(ctx context.Context, tenantID shared.ID, g *profileBatch) {
	all := make([]shared.ID, 0, len(g.byName))
	for _, ids := range g.byName {
		all = append(all, ids...)
	}
	res, err := e.starter.StartEnrichment(ctx, scan.EnrichmentInput{TenantID: tenantID, WorkflowID: g.profile.WorkflowID, Targets: g.names})
	if err != nil {
		metrics.AssetEnrichmentSkippedTotal.WithLabelValues("failed").Add(float64(len(all)))
		e.logger.Warn("enrichment run not started", "tenant_id", tenantID.String(), "profile", g.profile.Key,
			"targets", len(g.names), "error", logger.SanitizeError(err))
		e.settle(ctx, tenantID, all, freshdom.OutcomeFailed, nil)
		return
	}
	idsOf := func(names []string) []shared.ID {
		var out []shared.ID
		for _, n := range names {
			out = append(out, g.byName[strings.ToLower(strings.TrimSpace(n))]...)
		}
		return out
	}
	if dropped := idsOf(res.Dropped); len(dropped) > 0 {
		metrics.AssetEnrichmentSkippedTotal.WithLabelValues("refused").Add(float64(len(dropped)))
		e.settle(ctx, tenantID, dropped, freshdom.OutcomeRefused, nil)
	}
	if kept := idsOf(res.Kept); len(kept) > 0 && res.RunID != nil {
		metrics.AssetEnrichmentDispatchedTotal.WithLabelValues(g.profile.Key).Add(float64(len(kept)))
		e.settle(ctx, tenantID, kept, freshdom.OutcomeDispatched, res.RunID)
	}
}

// settle records an outcome; a failure is logged (the request stays claimed
// with no outcome, which the freshness panel shows as dispatched).
func (e *Enricher) settle(ctx context.Context, tenantID shared.ID, ids []shared.ID, o freshdom.Outcome, runID *shared.ID) {
	if err := e.requests.Settle(ctx, tenantID, ids, o, runID); err != nil {
		e.logger.Warn("enrichment outcome not recorded", "tenant_id", tenantID.String(), "outcome", string(o),
			"assets", len(ids), "error", logger.SanitizeError(err))
	}
}

// RequestStale asks for the passive enrichment of assets whose resolution
// evidence went stale (an active stage skipped them): the next run then
// knows whether they still resolve. Best effort, like RequestAssets.
func (e *Enricher) RequestStale(ctx context.Context, tenantID shared.ID, ids []shared.ID) {
	if e == nil || len(ids) == 0 {
		return
	}
	n, err := e.requests.Request(ctx, tenantID, ids, freshdom.ReasonStale, e.cfg.Cooldown)
	if err != nil {
		metrics.AssetEnrichmentSkippedTotal.WithLabelValues("request_error").Inc()
		e.logger.Warn("stale enrichment not requested", "tenant_id", tenantID.String(), "assets", len(ids),
			"error", logger.SanitizeError(err))
		return
	}
	metrics.AssetEnrichmentRequestsTotal.WithLabelValues(string(freshdom.ReasonStale)).Add(float64(n))
}
