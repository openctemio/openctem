// Package webverify plans the verification of sensitive web paths
// (docs/architecture/web-content-pipeline.md).
//
// A sensitive-path catalog match is a label: a status code alone never
// makes a finding. For the catalog entries that name signed templates
// (webendpoint.CatalogEntry.Verify), the planner schedules a template run
// on the endpoint's URL when the endpoint is new or changed, active,
// in scope and answered 2xx. The finding, when there is one, comes from the
// template hit in the normal ingest of the sensor's result; the planner
// itself writes no finding and no exposure.
//
// Safety:
//   - tenant-scoped: every read and write carries the tenant; a tenant's
//     candidates are visited with its own scope rules;
//   - an endpoint under a path exclusion (stored as out of scope) is never
//     selected, and the exclusions are loaded again at planning time: an
//     exclusion added after the sighting is honored, and a failed load
//     plans nothing for the tenant (fail closed);
//   - every URL passes the scan dispatch gate as the web_verify system
//     policy at tier T1 (scope entries, ownership, exclusions, zones), and
//     the web job guard adds the path limits at create;
//   - budgeted: a daily cap per tenant and a cap per pass, so a large
//     first crawl cannot flood a tenant's targets;
//   - never intrusive: the stage is T1 for every depth.
package webverify

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Defaults.
const (
	// DefaultDailyBudget is how many endpoints one tenant has verified per
	// rolling day.
	DefaultDailyBudget = 100
	// DefaultPassCap bounds the endpoints one pass plans for one tenant.
	DefaultPassCap = 25
	// DefaultTenantsPerPass bounds the tenants one pass visits.
	DefaultTenantsPerPass = 50
)

// Candidate is an endpoint waiting for verification.
type Candidate struct {
	EndpointID    shared.ID
	OriginAssetID shared.ID
	// OriginName is the origin asset's name, the origin URL.
	OriginName   string
	Method       string
	PathTemplate string
	ExamplePath  string
	CatalogKey   string
	ResponseSig  string
}

// Planned is a ledger row to write.
type Planned struct {
	EndpointID  shared.ID
	ResponseSig string
	CatalogKey  string
	RunID       *shared.ID
}

// Store is the ledger and the candidate query (*postgres.WebVerifyRepository).
type Store interface {
	TenantsWithCandidates(ctx context.Context, keys []string, limit int) ([]shared.ID, error)
	Candidates(ctx context.Context, tenantID shared.ID, keys []string, limit int) ([]Candidate, error)
	RunPlannedSince(ctx context.Context, tenantID shared.ID, since time.Time) (int, error)
	RecordPlanned(ctx context.Context, tenantID shared.ID, rows []Planned) error
}

// Dispatcher starts a verification run (*scan.Service).
type Dispatcher interface {
	StartWebVerification(ctx context.Context, in scanapp.WebVerifyInput) (*scanapp.WebVerifyResult, error)
}

// Blocker says which path exclusion, if any, blocks a request
// (*scope.WebRules).
type Blocker interface {
	Blocking(origin, method, path string) *scopedom.Exclusion
}

// Rules loads a tenant's path exclusions in effect.
type Rules interface {
	LoadBlocker(ctx context.Context, tenantID shared.ID) (Blocker, error)
}

// ScopeRules adapts the scope service to Rules.
type ScopeRules struct{ Svc *scopeapp.Service }

// LoadBlocker loads the tenant's path exclusions.
func (r ScopeRules) LoadBlocker(ctx context.Context, tenantID shared.ID) (Blocker, error) {
	return r.Svc.LoadWebRules(ctx, tenantID)
}

// Plan is what a depth allows.
type Plan struct {
	// Enabled: a passive depth sends no traffic, so it verifies nothing.
	Enabled bool
	// Tier is the probe tier of the verification: T1 for every depth.
	Tier scopedom.Tier
	// BudgetFactor scales the daily budget.
	BudgetFactor int
}

// ForDepth returns what a scan depth allows. A depth never raises the tier:
// deep verifies more, never more intrusively.
func ForDepth(d scanworkflow.Depth) Plan {
	switch d {
	case scanworkflow.DepthPassive:
		return Plan{Enabled: false, Tier: scopedom.TierPassive, BudgetFactor: 0}
	case scanworkflow.DepthDeep:
		return Plan{Enabled: true, Tier: scopedom.TierActive, BudgetFactor: 2}
	default:
		return Plan{Enabled: true, Tier: scopedom.TierActive, BudgetFactor: 1}
	}
}

// Config bounds the planner.
type Config struct {
	DailyBudget    int
	PassCap        int
	TenantsPerPass int
}

func (c Config) withDefaults() Config {
	if c.DailyBudget <= 0 {
		c.DailyBudget = DefaultDailyBudget
	}
	if c.PassCap <= 0 {
		c.PassCap = DefaultPassCap
	}
	if c.TenantsPerPass <= 0 {
		c.TenantsPerPass = DefaultTenantsPerPass
	}
	return c
}

// Planner schedules verification runs.
type Planner struct {
	store Store
	disp  Dispatcher
	rules Rules
	cfg   Config
	log   *logger.Logger
	now   func() time.Time
	keys  []string
	tmpl  map[string][]string // catalog key -> template ids
}

// NewPlanner builds the planner over the default catalog.
func NewPlanner(store Store, disp Dispatcher, rules Rules, cfg Config, log *logger.Logger) *Planner {
	if log == nil {
		log = logger.NewNop()
	}
	p := &Planner{store: store, disp: disp, rules: rules, cfg: cfg.withDefaults(), log: log,
		now: func() time.Time { return time.Now().UTC() }, tmpl: map[string][]string{}}
	for _, e := range webendpoint.DefaultCatalog.Entries {
		if e.Verify != nil {
			p.keys = append(p.keys, e.Key)
			p.tmpl[e.Key] = e.Verify.Templates
		}
	}
	sort.Strings(p.keys)
	return p
}

// Result counts one tenant's pass.
type Result struct {
	Candidates int
	Excluded   int
	Invalid    int
	Refused    int
	Planned    int
	Busy       int
	BudgetLeft int
}

// RunAll visits the tenants that have candidates. It reports how many
// endpoints it planned; a tenant's failure is logged and does not stop the
// others.
func (p *Planner) RunAll(ctx context.Context) (int, error) {
	tenants, err := p.store.TenantsWithCandidates(ctx, p.keys, p.cfg.TenantsPerPass)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, t := range tenants {
		res, err := p.RunTenant(ctx, t)
		if err != nil {
			p.log.Warn("web verification pass failed", "tenant_id", t.String(), "error", logger.SanitizeError(err))
			continue
		}
		total += res.Planned
	}
	return total, nil
}

// RunTenant plans one pass for one tenant.
func (p *Planner) RunTenant(ctx context.Context, tenantID shared.ID) (Result, error) {
	var res Result
	plan := ForDepth(scanworkflow.DepthStandard)
	budget := p.cfg.DailyBudget * plan.BudgetFactor
	used, err := p.store.RunPlannedSince(ctx, tenantID, p.now().Add(-24*time.Hour))
	if err != nil {
		return res, err
	}
	res.BudgetLeft = max(budget-used, 0)
	limit := min(res.BudgetLeft, p.cfg.PassCap)
	if limit == 0 {
		return res, nil
	}
	cands, err := p.store.Candidates(ctx, tenantID, p.keys, limit)
	if err != nil {
		return res, err
	}
	res.Candidates = len(cands)
	if len(cands) == 0 {
		return res, nil
	}
	if p.rules == nil {
		return res, errors.New("web verification: scope exclusions are not wired; nothing planned")
	}
	// Fail closed: without the exclusions nothing says which paths must
	// never be requested.
	rules, err := p.rules.LoadBlocker(ctx, tenantID)
	if err != nil {
		return res, fmt.Errorf("web verification: scope exclusions could not be read, nothing planned: %w", err)
	}

	type group struct {
		templates []string
		urls      []string
		assets    map[string]string
		byURL     map[string]Candidate
	}
	groups := map[string]*group{}
	var order []string
	var ledger []Planned
	for _, c := range cands {
		path := c.ExamplePath
		if path == "" {
			path = c.PathTemplate
		}
		path = webendpoint.FillTemplate(path)
		if rules.Blocking(c.OriginName, c.Method, path) != nil || rules.Blocking(c.OriginName, c.Method, c.PathTemplate) != nil {
			res.Excluded++
			continue
		}
		u, ok := targetURL(c.OriginName, path)
		if !ok {
			res.Invalid++
			continue
		}
		tpls := p.tmpl[c.CatalogKey]
		if len(tpls) == 0 {
			res.Invalid++
			continue
		}
		gk := scanapp.WebVerifyGroupKey(tpls)
		g := groups[gk]
		if g == nil {
			g = &group{templates: tpls, assets: map[string]string{}, byURL: map[string]Candidate{}}
			groups[gk] = g
			order = append(order, gk)
		}
		lu := strings.ToLower(u)
		if _, dup := g.byURL[lu]; dup {
			continue
		}
		g.urls = append(g.urls, u)
		g.assets[u] = c.OriginAssetID.String()
		g.byURL[lu] = c
	}
	sort.Strings(order)
	for _, gk := range order {
		g := groups[gk]
		out, err := p.disp.StartWebVerification(ctx, scanapp.WebVerifyInput{
			TenantID: tenantID, TemplateIDs: g.templates, Targets: g.urls, Assets: g.assets})
		if errors.Is(err, scanapp.ErrWebVerifyBusy) {
			res.Busy += len(g.urls)
			continue
		}
		if err != nil {
			p.log.Warn("web verification not started", "tenant_id", tenantID.String(), "targets", len(g.urls), "error", logger.SanitizeError(err))
			continue
		}
		kept := map[string]bool{}
		for _, k := range out.Kept {
			kept[strings.ToLower(k)] = true
		}
		for lu, c := range g.byURL {
			row := Planned{EndpointID: c.EndpointID, ResponseSig: c.ResponseSig, CatalogKey: c.CatalogKey}
			if kept[lu] {
				row.RunID = out.RunID
				res.Planned++
			} else {
				res.Refused++
			}
			ledger = append(ledger, row)
		}
	}
	if err := p.store.RecordPlanned(ctx, tenantID, ledger); err != nil {
		return res, err
	}
	return res, nil
}

// targetURL joins an origin and a path into a request URL, or false when it
// is not a plain http(s) URL (user info, query, fragment or a missing host).
func targetURL(origin, path string) (string, bool) {
	if path == "" || path[0] != '/' || strings.ContainsAny(path, "?#") {
		return "", false
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", false
	}
	return u.Scheme + "://" + strings.ToLower(u.Host) + path, true
}
