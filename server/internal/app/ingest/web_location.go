package ingest

// The web location of a finding (CTIS finding.web): the method, the
// parameter's location and name, the response status, and the web endpoint
// the finding belongs to (docs/architecture/web-surface.md, "Findings on a
// path").
//
// Security:
//   - the endpoint link is resolved inside one tenant: the origin asset and
//     the endpoint row are read with the tenant id of the ingest, so a ref (or
//     a hash) never reaches another tenant's endpoint;
//   - the report's endpoint_ref only names an endpoint of the same report; the
//     origin it resolves to is the asset this ingest persisted, never an id
//     the report carries;
//   - no parameter value is stored: the CTIS web location has none, and a
//     name is cut at "=".

import (
	"context"

	ctis "github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/weburl"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// webRefTarget is the endpoint a report's endpoint_ref names: the origin
// asset the ingest persisted and the endpoint's dedup key on it.
type webRefTarget struct {
	originAssetID string
	templateHash  string
}

// webRefs resolves the report's endpoints for its findings.
type webRefs struct {
	byRef    map[string]webRefTarget // endpoint id in the report
	byOrigin map[string]string       // normalised origin -> origin asset id
}

type webRefsKey struct{}

func withWebRefs(ctx context.Context, r *webRefs) context.Context {
	if r == nil {
		return ctx
	}
	return context.WithValue(ctx, webRefsKey{}, r)
}

func webRefsOf(ctx context.Context) *webRefs {
	r, _ := ctx.Value(webRefsKey{}).(*webRefs)
	return r
}

// resolveRefs maps the planned endpoints to the origin assets the ingest
// persisted. An origin that was not persisted (refused) is left out.
func (p *endpointPlan) resolveRefs(assetMap map[string]shared.ID) *webRefs {
	if p == nil {
		return nil
	}
	out := &webRefs{byRef: map[string]webRefTarget{}, byOrigin: map[string]string{}}
	for ref, origin := range p.origins {
		if id, ok := assetMap[ref]; ok && !id.IsZero() {
			out.byOrigin[origin] = id.String()
		}
	}
	for id, t := range p.refs {
		if aid, ok := assetMap[t.originRef]; ok && !aid.IsZero() {
			out.byRef[id] = webRefTarget{originAssetID: aid.String(), templateHash: t.templateHash}
		}
	}
	return out
}

// webLocationUpdate is the web location of one report finding, or ok=false
// when it has none.
func webLocationUpdate(refs *webRefs, fingerprint string, f *ctis.Finding) (vulnerability.WebLocationUpdate, bool) {
	if f == nil || f.Web == nil {
		return vulnerability.WebLocationUpdate{}, false
	}
	w := f.Web
	u := vulnerability.WebLocationUpdate{Fingerprint: fingerprint, Method: w.Method, StatusCode: w.StatusCode}
	if w.Parameter != nil {
		u.ParamLocation, u.ParamName = string(w.Parameter.Location), w.Parameter.Name
	}
	switch t, ok := refs.target(w.EndpointRef); {
	case ok:
		u.OriginAssetID, u.EndpointHash = t.originAssetID, t.templateHash
	case w.URL != "":
		// No (resolvable) ref: the method and the URL template name the
		// endpoint, on the origin this report stored or the finding's asset.
		if origin, tmpl, _, err := weburl.Template(w.URL); err == nil && tmpl != "" {
			u.EndpointHash = weburl.PathHash(methodOrAny(w.Method), tmpl)
			u.AnyMethodHash = weburl.PathHash("ANY", tmpl)
			if refs != nil {
				u.OriginAssetID = refs.byOrigin[origin]
			}
		}
	}
	u = u.Normalize()
	return u, !u.IsEmpty()
}

func (r *webRefs) target(ref string) (webRefTarget, bool) {
	if r == nil || ref == "" {
		return webRefTarget{}, false
	}
	t, ok := r.byRef[ref]
	return t, ok
}

func methodOrAny(m string) string {
	if n, ok := weburl.NormalizeMethod(m); ok {
		return n
	}
	return "ANY"
}

// webLocationWriter is the optional repository side that stores web
// locations (postgres.FindingRepository).
type webLocationWriter interface {
	StoreWebLocations(ctx context.Context, tenantID shared.ID, updates []vulnerability.WebLocationUpdate) error
}

// storeWebLocations writes the batch's web locations. Best effort: the
// findings are stored, so a failure is logged and never fails the ingest.
func (p *FindingProcessor) storeWebLocations(ctx context.Context, tenantID shared.ID, updates []vulnerability.WebLocationUpdate) {
	w, ok := p.repo.(webLocationWriter)

	if !ok || len(updates) == 0 {
		return
	}
	if err := w.StoreWebLocations(ctx, tenantID, updates); err != nil {
		p.logger.Warn("finding web locations not stored", "tenant_id", tenantID.String(),
			"count", len(updates), "error", logger.SanitizeError(err))
	}
}
