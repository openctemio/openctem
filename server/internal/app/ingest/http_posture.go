package ingest

// The response header posture of a web origin (docs/architecture/web-content-pipeline.md):
// a CTIS 2.0 producer reports the security headers of a web_origin in
// technical.http.security_headers. The platform keeps only the allow-listed,
// typed posture derived from them (webendpoint.PostureFromSecurityHeaders):
// flags and enums, never a header or cookie value. properties carry no
// meaning, so a producer's properties.http_posture is dropped.
//
// The keys a template scanner's info matches prove (a missing header,
// docs/architecture/template-facts.md) are added for the keys the report's
// own headers do not decide. Across reports they only fill the keys the
// stored http_posture lacks: a stored reading (a probe's headers) wins over
// a template match (keepStoredPosture); stored keys they do not name are
// kept by the deep property merge.

import (
	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/webendpoint"
)

func sanitizeHTTPPosture(report *ctis.Report, scope *alterScope) {
	if report == nil {
		return
	}
	for i := range report.Assets {
		a := &report.Assets[i]
		delete(a.Properties, webendpoint.PostureKey)
		if a.Type != ctis.AssetTypeWebOrigin {
			continue
		}
		var p map[string]any
		if a.Technical != nil && a.Technical.HTTP != nil {
			p = webendpoint.PostureFromSecurityHeaders(a.Technical.HTTP.SecurityHeaders)
		}
		if t := webendpoint.SanitizePosture(scope.templatePostureFor(a.ID)); len(t) > 0 {
			if p == nil {
				p = map[string]any{}
			}
			for k, v := range t {
				if _, decided := p[k]; !decided {
					p[k] = v
				}
			}
		}
		if p != nil {
			if a.Properties == nil {
				a.Properties = ctis.Properties{}
			}
			a.Properties[webendpoint.PostureKey] = p
		}
	}
}

// keepStoredPosture restores, in merged, every key the stored http_posture
// already holds: the report is a template scanner's, whose keys only fill
// the ones missing. The deep property merge lets the report's value win;
// this puts the stored value back.
func keepStoredPosture(stored, merged map[string]any) {
	old, ok := stored[webendpoint.PostureKey].(map[string]any)
	if !ok || len(old) == 0 {
		return
	}
	cur, ok := merged[webendpoint.PostureKey].(map[string]any)
	if !ok {
		return
	}
	out := make(map[string]any, len(cur)+len(old))
	for k, v := range cur {
		out[k] = v
	}
	for k, v := range old {
		out[k] = v
	}
	merged[webendpoint.PostureKey] = out
}
