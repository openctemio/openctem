package ingest

// Web endpoints (docs/rfcs/RFC-056-web-attack-surface.md): a report's
// endpoints[] (CTIS 1.6) land in the web surface sub-inventory under their
// origin's http_service asset, never as one asset per URL. A legacy
// discovered_url asset is folded into an endpoint the same way and is no
// longer created.
//
// Security:
//   - the origin asset is resolved from the report's own assets after the
//     output binding (an http_service asset with the endpoint's origin), or
//     added to the report as one, so it passes the same scope, exclusion and
//     binding checks as any asset; an id in the report never chooses it;
//   - a command-bound report writes endpoints only under origins its
//     command's targets cover; endpoints land only on an origin asset this
//     ingest may change (alterScope.allowedAsset: created by it, covered by
//     its command, inside the upload actor's data scope);
//   - the platform recomputes the template and the dedup key and drops
//     query values, user info and fragments (webendpoint.Observe);
//   - the source is set from the bound command's capability, never taken
//     from the report: a path discovery job's endpoints are guess and are
//     refused without response evidence (webendpoint.BindSource).

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/weburl"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SetWebEndpointRepository wires the web surface sub-inventory. Unwired,
// endpoints are dropped (and discovered_url assets are still not created).
func (s *Service) SetWebEndpointRepository(repo webendpoint.Repository) { s.webEndpoints = repo }

// WebRuleSource loads a tenant's path exclusions in effect (*scope.Service).
type WebRuleSource interface {
	LoadWebRules(ctx context.Context, tenantID shared.ID) (*scopeapp.WebRules, error)
}

// markExcluded stores an endpoint a path exclusion blocks (for its method)
// as excluded-untested, naming the exclusion. It never drops it: the tenant
// learns what lies behind an exclusion without anything being sent there.
func markExcluded(rules *scopeapp.WebRules, obs []webendpoint.Observation) {
	for i := range obs {
		if e := rules.Blocking(obs[i].Origin, obs[i].Method, obs[i].ExamplePath); e != nil {
			id := e.ID()
			obs[i].OutOfScope, obs[i].ExclusionID = true, &id
		}
	}
}

// endpointPlan is the endpoints of one report, grouped by the report asset
// ref of their origin.
type endpointPlan struct {
	byOrigin map[string][]webendpoint.Observation
	origins  map[string]string // origin ref -> normalised origin
}

const syntheticOriginRefPrefix = "openctem-web-origin-"

// planEndpoints normalises every endpoint and makes sure each origin is a
// web_origin asset of the report. It returns the report to process (a copy when anything changed).
func (s *Service) planEndpoints(report *ctis.Report, binding Binding, output *Output) (*ctis.Report, *endpointPlan) {
	if report == nil || len(report.Endpoints) == 0 {
		return report, nil
	}
	r := *report
	r.Assets = append([]ctis.Asset(nil), report.Assets...)
	r.Findings = append([]ctis.Finding(nil), report.Findings...)
	r.Endpoints = append([]ctis.Endpoint(nil), report.Endpoints...)

	refs := newOriginRefs(&r)

	var targets []coverTarget
	bound := binding.Kind == BindingCommand || binding.Kind == BindingCIRun
	if bound {
		targets = newCoverTargets(binding.Targets)
	}
	plan := &endpointPlan{byOrigin: map[string][]webendpoint.Observation{}, origins: map[string]string{}}
	for _, e := range r.Endpoints {
		obs, err := webendpoint.Observe(e)
		if err == nil {
			// The source comes from the bound command's capability: a path
			// discovery job's endpoints are guess and need evidence; no
			// other job can produce guess.
			err = webendpoint.BindSource(&obs, binding.Capability, e)
		}
		switch {
		case errors.Is(err, webendpoint.ErrStatic):
			output.EndpointsStatic++
			continue
		case errors.Is(err, webendpoint.ErrNoEvidence):
			output.EndpointsRefused++
			output.EndpointsNoEvidence++
			continue
		case err != nil, bound && !targetsCoverOrigin(targets, obs.Origin):
			output.EndpointsRefused++
			continue
		}
		ref := refs.refFor(&r, obs.Origin)
		plan.byOrigin[ref] = append(plan.byOrigin[ref], obs)
		plan.origins[ref] = obs.Origin
	}
	r.Endpoints = nil // stored through the plan only
	return &r, plan
}

func targetsCoverOrigin(targets []coverTarget, origin string) bool {
	host, _ := parseLocator(origin)
	for _, t := range targets {
		if t.coversLocator(host, "") {
			return true
		}
	}
	return false
}

// originRefs names the http_service asset of each origin in a report.
type originRefs struct {
	byOrigin map[string]string
	used     map[string]bool
	next     int
}

// newOriginRefs indexes the report's web_origin assets, giving an id to one
// that has none.
func newOriginRefs(r *ctis.Report) *originRefs {
	o := &originRefs{byOrigin: map[string]string{}, used: map[string]bool{}}
	for i := range r.Assets {
		if r.Assets[i].ID != "" {
			o.used[r.Assets[i].ID] = true
		}
	}
	for i := range r.Assets {
		a := &r.Assets[i]
		if a.Type != ctis.AssetTypeWebOrigin {
			continue
		}
		u, err := weburl.Parse(a.Value)
		if err != nil || u.Path != "/" {
			continue
		}
		if _, ok := o.byOrigin[u.Origin()]; ok {
			continue
		}
		if a.ID == "" {
			a.ID = o.fresh()
		}
		o.byOrigin[u.Origin()] = a.ID
	}
	return o
}

// fresh returns an asset id the report does not use yet.
func (o *originRefs) fresh() string {
	for {
		id := syntheticOriginRefPrefix + strconv.Itoa(o.next)
		o.next++
		if !o.used[id] {
			o.used[id] = true
			return id
		}
	}
}

// refFor returns the asset ref of origin, adding a web_origin asset for it
// to the report when it has none.
func (o *originRefs) refFor(r *ctis.Report, origin string) string {
	if ref, ok := o.byOrigin[origin]; ok {
		return ref
	}
	ref := o.fresh()
	o.byOrigin[origin] = ref
	r.Assets = append(r.Assets, ctis.Asset{ID: ref, Type: ctis.AssetTypeWebOrigin, Value: origin})
	return ref
}

// recordEndpoints writes the planned endpoints under their persisted origin
// assets. Best-effort per origin: a failure is reported on the output and
// the rest of the report still lands.
func (s *Service) recordEndpoints(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, binding Binding,
	scope *alterScope, plan *endpointPlan, assetMap map[string]shared.ID, report *ctis.Report, output *Output,
) {
	if plan == nil || len(plan.byOrigin) == 0 {
		return
	}
	if s.webEndpoints == nil {
		for _, obs := range plan.byOrigin {
			output.EndpointsRefused += len(obs)
		}
		return
	}
	prov := webendpoint.Provenance{RunID: binding.StepRunID, Tool: binding.Tool}
	if prov.Tool == "" && report != nil && report.Tool != nil {
		prov.Tool = report.Tool.Name
	}
	if agt != nil && !agt.ID.IsZero() {
		id := agt.ID
		prov.SensorID = &id
	}
	var rules *scopeapp.WebRules
	if s.webRules != nil {
		var err error
		if rules, err = s.webRules.LoadWebRules(ctx, tenantID); err != nil {
			// Fail closed: without the exclusions nothing says which
			// endpoints must never be targeted.
			for _, obs := range plan.byOrigin {
				output.EndpointsRefused += len(obs)
			}
			addError(output, "web endpoints: scope exclusions could not be read")
			return
		}
	}
	for ref, obs := range plan.byOrigin {
		id, ok := assetMap[ref]
		if !ok || id.IsZero() || !scope.allowedAsset(id) || !isOriginAsset(scope, id) {
			output.EndpointsRefused += len(obs)
			continue
		}
		markExcluded(rules, obs)
		res, err := s.webEndpoints.Record(ctx, tenantID, id, obs, prov)
		if err != nil {
			s.logger.Warn("ingest: web endpoints not recorded",
				"tenant_id", tenantID.String(), "origin_asset_id", id.String(), "endpoints", len(obs),
				"error", logger.SanitizeError(err))
			addError(output, fmt.Sprintf("web endpoints: %d not recorded", len(obs)))
			continue
		}
		output.EndpointsCreated += res.Created
		output.EndpointsUpdated += res.Updated
		output.EndpointsOverCap += res.OverCap + res.ParamsOverCap
	}
}

// isOriginAsset reports whether the persisted asset this ingest wrote is an
// http_service (the identity pipeline may have matched a report asset to an
// asset of another type; endpoints never land on one).
func isOriginAsset(scope *alterScope, id shared.ID) bool {
	if scope == nil || scope.seen == nil {
		return false
	}
	seen, ok := scope.seen[id]
	return ok && seen.typ.Type == asset.AssetTypeService && strings.EqualFold(seen.typ.SubType, "http")
}
