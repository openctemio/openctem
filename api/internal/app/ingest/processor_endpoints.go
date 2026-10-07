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
//     query values, user info and fragments (webendpoint.Observe).

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/weburl"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SetWebEndpointRepository wires the web surface sub-inventory. Unwired,
// endpoints are dropped (and discovered_url assets are still not created).
func (s *Service) SetWebEndpointRepository(repo webendpoint.Repository) { s.webEndpoints = repo }

// endpointPlan is the endpoints of one report, grouped by the report asset
// ref of their origin.
type endpointPlan struct {
	byOrigin map[string][]webendpoint.Observation
	origins  map[string]string // origin ref -> normalised origin
}

const syntheticOriginRefPrefix = "openctem-web-origin-"

// planEndpoints folds legacy discovered_url assets into endpoints, normalises
// every endpoint, and makes sure each origin is an http_service asset of the
// report. It returns the report to process (a copy when anything changed).
func (s *Service) planEndpoints(report *ctis.Report, binding Binding, output *Output) (*ctis.Report, *endpointPlan) {
	if report == nil || (len(report.Endpoints) == 0 && !hasLegacyURLs(report)) {
		return report, nil
	}
	r := *report
	r.Assets = append([]ctis.Asset(nil), report.Assets...)
	r.Findings = append([]ctis.Finding(nil), report.Findings...)
	r.Endpoints = append([]ctis.Endpoint(nil), report.Endpoints...)

	legacyOrigin := foldLegacyURLs(&r, output)
	refs := newOriginRefs(&r)

	var targets []coverTarget
	bound := binding.Kind == BindingCommand || binding.Kind == BindingCIRun
	if bound {
		targets = newCoverTargets(binding.Targets)
	}
	plan := &endpointPlan{byOrigin: map[string][]webendpoint.Observation{}, origins: map[string]string{}}
	for _, e := range r.Endpoints {
		obs, err := webendpoint.Observe(e)
		switch {
		case errors.Is(err, webendpoint.ErrStatic):
			output.EndpointsStatic++
			continue
		case err != nil, bound && !targetsCoverOrigin(targets, obs.Origin):
			output.EndpointsRefused++
			continue
		}
		ref := refs.refFor(&r, obs.Origin)
		plan.byOrigin[ref] = append(plan.byOrigin[ref], obs)
		plan.origins[ref] = obs.Origin
	}
	// A finding on a folded URL lands on the URL's origin.
	for i := range r.Findings {
		if o, ok := legacyOrigin[r.Findings[i].AssetRef]; ok {
			if ref, ok := refs.byOrigin[o]; ok {
				r.Findings[i].AssetRef = ref
			}
		}
	}
	r.Endpoints = nil // stored through the plan only
	return &r, plan
}

func hasLegacyURLs(r *ctis.Report) bool {
	for i := range r.Assets {
		if r.Assets[i].Type == ctis.AssetTypeDiscoveredURL {
			return true
		}
	}
	return false
}

// foldLegacyURLs turns the report's discovered_url assets into endpoints and
// removes them; it returns the origin of each folded asset ref.
func foldLegacyURLs(r *ctis.Report, output *Output) map[string]string {
	legacyOrigin := map[string]string{}
	keep := r.Assets[:0]
	for _, a := range r.Assets {
		if a.Type != ctis.AssetTypeDiscoveredURL {
			keep = append(keep, a)
			continue
		}
		output.LegacyURLAssetsFolded++
		ep, ok := legacyEndpoint(a)
		if !ok {
			continue
		}
		r.Endpoints = append(r.Endpoints, ep)
		if a.ID != "" {
			legacyOrigin[a.ID] = ep.Origin
		}
	}
	r.Assets = keep
	return legacyOrigin
}

// legacyEndpoint is the endpoint of a discovered_url asset: its URL's origin
// and path, its query parameter NAMES, never their values.
func legacyEndpoint(a ctis.Asset) (ctis.Endpoint, bool) {
	raw := a.Value
	if raw == "" {
		raw = a.Name
	}
	u, err := weburl.Parse(raw)
	if err != nil {
		return ctis.Endpoint{}, false
	}
	method, _ := a.Properties["method"].(string)
	if m, ok := weburl.NormalizeMethod(method); !ok || m == weburl.MethodAny {
		method = "GET"
	}
	ep := ctis.Endpoint{Origin: u.Origin(), Method: method, Path: u.Path, Source: ctis.EndpointSourceCrawl}
	if sc, ok := a.Properties["status_code"].(float64); ok {
		ep.StatusCode = int(sc)
	}
	if ct, ok := a.Properties["content_type"].(string); ok {
		ep.ContentType = ct
	}
	for _, n := range u.Params {
		ep.Params = append(ep.Params, ctis.EndpointParam{Location: ctis.ParamLocationQuery, Name: n})
	}
	return ep, true
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

// newOriginRefs indexes the report's http_service assets that are origins
// (no path), giving an id to one that has none.
func newOriginRefs(r *ctis.Report) *originRefs {
	o := &originRefs{byOrigin: map[string]string{}, used: map[string]bool{}}
	for i := range r.Assets {
		if r.Assets[i].ID != "" {
			o.used[r.Assets[i].ID] = true
		}
	}
	for i := range r.Assets {
		a := &r.Assets[i]
		if a.Type != ctis.AssetTypeHTTPService {
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

// refFor returns the asset ref of origin, adding an http_service asset for
// it to the report when it has none.
func (o *originRefs) refFor(r *ctis.Report, origin string) string {
	if ref, ok := o.byOrigin[origin]; ok {
		return ref
	}
	ref := o.fresh()
	o.byOrigin[origin] = ref
	r.Assets = append(r.Assets, ctis.Asset{ID: ref, Type: ctis.AssetTypeHTTPService, Value: origin, Name: origin})
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
	for ref, obs := range plan.byOrigin {
		id, ok := assetMap[ref]
		if !ok || id.IsZero() || !scope.allowedAsset(id) || !isOriginAsset(scope, id) {
			output.EndpointsRefused += len(obs)
			continue
		}
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
