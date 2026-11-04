package ingest

// The response header posture of a web origin (docs/architecture/web-content-pipeline.md):
// a CTIS 2.0 producer reports the security headers of a web_origin in
// technical.http.security_headers. The platform keeps only the allow-listed,
// typed posture derived from them (webendpoint.PostureFromSecurityHeaders):
// flags and enums, never a header or cookie value. properties carry no
// meaning, so a producer's properties.http_posture is dropped.

import (
	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
)

func sanitizeHTTPPosture(report *ctis.Report) {
	if report == nil {
		return
	}
	for i := range report.Assets {
		a := &report.Assets[i]
		delete(a.Properties, webendpoint.PostureKey)
		if a.Type != ctis.AssetTypeWebOrigin || a.Technical == nil || a.Technical.HTTP == nil {
			continue
		}
		if p := webendpoint.PostureFromSecurityHeaders(a.Technical.HTTP.SecurityHeaders); p != nil {
			if a.Properties == nil {
				a.Properties = ctis.Properties{}
			}
			a.Properties[webendpoint.PostureKey] = p
		}
	}
}
