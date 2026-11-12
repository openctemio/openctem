package ingest

// Service kinds at ingest (docs/architecture/service-kinds.md): every
// service asset a report creates or may change is classified from the
// protocol, port and transport the report names for it. The source of that
// protocol is the platform's own fact: the capability the output binding
// bound the report to (a command's tool), never the producer's claim. A
// report bound to no capability (a push, an import) is "reported"; a port
// without a protocol is a port guess.

import (
	"github.com/openctemio/contract/capability"
	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// capabilityKindSource is the kind source of a protocol named by a report
// bound to the capability.
var capabilityKindSource = map[string]asset.KindSource{
	"detect.services": asset.KindSourceFingerprint,
	"check.tls":       asset.KindSourceTLSALPN,
	"probe.http":      asset.KindSourceHTTPProbe,
}

// serviceKindEvidence is the source of the service protocols the report
// names.
func serviceKindEvidence(report *ctis.Report) asset.KindSource {
	if id, _, ok := capability.ParseRef(reportCapability(report)); ok {
		if src, ok := capabilityKindSource[id]; ok {
			return src
		}
	}
	return asset.KindSourceReported
}

// classifyReportedService classifies a service asset from what the report
// says of it (technical.service), with the report's source.
func classifyReportedService(a *asset.Asset, ca *ctis.Asset, evidence asset.KindSource) {
	if a == nil || ca == nil || a.Type() != asset.AssetTypeService {
		return
	}
	incoming := map[string]any{}
	if ca.Technical != nil && ca.Technical.Service != nil {
		svc := ca.Technical.Service
		if svc.AppProtocol != "" {
			incoming["protocol"] = svc.AppProtocol
		}
		if svc.Port > 0 {
			incoming["port"] = svc.Port
		}
		if svc.Transport != "" {
			incoming["transport"] = string(svc.Transport)
		}
	}
	a.ClassifyService(incoming, evidence)
}
