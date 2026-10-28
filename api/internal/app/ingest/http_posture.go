package ingest

// The response header posture of a web origin (docs/architecture/web-content-pipeline.md):
// a producer may attach `http_posture` to an http_service asset. The platform
// keeps only the allow-listed, typed keys (webendpoint.SanitizePosture);
// everything else, and the key on any other asset type, is dropped, so a
// header or cookie value can never be stored through it. A report without
// the key changes nothing (producers add it at their own pace).

import (
	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
)

func sanitizeHTTPPosture(report *ctis.Report) {
	if report == nil {
		return
	}
	for i := range report.Assets {
		a := &report.Assets[i]
		raw, ok := a.Properties[webendpoint.PostureKey]
		if !ok {
			continue
		}
		stored := resolveCTISAssetType(a).stored
		isHTTP := stored.Type == asset.AssetTypeService && stored.SubType == "http"
		if clean := webendpoint.SanitizePosture(raw); isHTTP && clean != nil {
			a.Properties[webendpoint.PostureKey] = clean
			continue
		}
		delete(a.Properties, webendpoint.PostureKey)
	}
}
