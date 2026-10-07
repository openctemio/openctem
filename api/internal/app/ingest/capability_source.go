package ingest

import (
	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/capability"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// capabilitySource is the finding source (the detection technique) of each
// capability of the taxonomy (RFC-055). A report the output binding bound to
// a capability takes its technique from it, so a third-party tool needs no
// entry in a name table; the name table stays for reports without one
// (pushed reports from external tools).
var capabilitySource = map[string]vulnerability.FindingSource{
	"discover.subdomains":  vulnerability.FindingSourceEASM,
	"intel.passive":        vulnerability.FindingSourceEASM,
	"resolve.dns":          vulnerability.FindingSourceEASM,
	"scan.ports":           vulnerability.FindingSourceEASM,
	"detect.services":      vulnerability.FindingSourceEASM,
	"probe.http":           vulnerability.FindingSourceEASM,
	"fingerprint.tech":     vulnerability.FindingSourceEASM,
	"check.tls":            vulnerability.FindingSourceEASM,
	"capture.screenshot":   vulnerability.FindingSourceEASM,
	"crawl.web":            vulnerability.FindingSourceEASM,
	"check.takeover":       vulnerability.FindingSourceEASM,
	"discover.cloud":       vulnerability.FindingSourceCSPM,
	"cloud.posture":        vulnerability.FindingSourceCSPM,
	"vuln.templates":       vulnerability.FindingSourceDAST,
	"dast.web":             vulnerability.FindingSourceDAST,
	"sast.code":            vulnerability.FindingSourceSAST,
	"secrets.code":         vulnerability.FindingSourceSecret,
	"sca.deps":             vulnerability.FindingSourceSCA,
	"sbom.generate":        vulnerability.FindingSourceSCA,
	"container.image":      vulnerability.FindingSourceContainer,
	"iac.misconfig":        vulnerability.FindingSourceIaC,
	"network_va.connector": vulnerability.FindingSourceVA,
	"host.credentialed":    vulnerability.FindingSourceVA,
	"config.benchmark":     vulnerability.FindingSourceVA,
	"import.file":          vulnerability.FindingSourceExternal,
}

// reportFindingSource is the technique of a report's findings: its bound
// capability when it has one the table knows, else the tool's own
// capabilities and name (detectFindingSource).
func reportFindingSource(report *ctis.Report) vulnerability.FindingSource {
	if report == nil {
		return detectFindingSource("", nil)
	}
	if id, _, ok := capability.ParseRef(report.Metadata.Capability); ok {
		if src, ok := capabilitySource[id]; ok {
			return src
		}
	}
	if report.Tool == nil {
		return detectFindingSource("", nil)
	}
	return detectFindingSource(report.Tool.Name, report.Tool.Capabilities)
}
