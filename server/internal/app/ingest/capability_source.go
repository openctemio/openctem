package ingest

import (
	"github.com/openctemio/contract/capability"
	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
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
	"lookup.rdap":          vulnerability.FindingSourceEASM,
	"lookup.asn":           vulnerability.FindingSourceEASM,
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
// capability when it has one the table knows, else the tool's techniques
// and name (detectFindingSource).
func reportFindingSource(report *ctis.Report) vulnerability.FindingSource {
	if report == nil {
		return detectFindingSource("")
	}
	if id, _, ok := capability.ParseRef(reportCapability(report)); ok {
		if src, ok := capabilitySource[id]; ok {
			return src
		}
	}
	if report.Tool == nil {
		return detectFindingSource("")
	}
	return detectFindingSource(report.Tool.Name, report.Tool.Techniques...)
}

// reportCapability is the capability a report answers. The output binding
// writes the capability of the command it bound the report to into
// metadata.extensions["io.openctem"].capability (boundCapability); before
// that it is the producer's claim, a hint that never widens what the report
// may create (CTIS receiver profile, section 3).
func reportCapability(report *ctis.Report) string {
	if report == nil {
		return ""
	}
	v, _ := report.Metadata.Extensions.Get(ctis.OpenCTEMNamespace, capabilityExtKey)
	c, _ := v.(string)
	return c
}

// capabilityExtKey is the io.openctem key of the capability on metadata.
const capabilityExtKey = "capability"

// setReportCapability records the capability a report is bound to (empty:
// none) in the receiver's copy of the document.
func setReportCapability(report *ctis.Report, ref string) {
	if ref == "" {
		if ns := report.Metadata.Extensions[ctis.OpenCTEMNamespace]; ns != nil {
			delete(ns, capabilityExtKey)
		}
		return
	}
	report.Metadata.Extensions.Set(ctis.OpenCTEMNamespace, capabilityExtKey, ref)
}

// findingTechnique is the source of one finding of a report. A report bound
// to a command's capability takes the source of that capability whatever the
// finding says: the capability is the receiver's fact, finding.technique is
// the producer's claim and never moves a finding to another source (it is
// recorded on its own, findingClaimedTechnique). An unbound report takes the
// finding's technique, else the tool's techniques. A scanner with several
// techniques (trivy: dependencies, misconfigurations, secrets in one run)
// that names none per finding lists sca first, so the finding's type decides
// between them.
func findingTechnique(report *ctis.Report, f *ctis.Finding) vulnerability.FindingSource {
	if id, _, ok := capability.ParseRef(reportCapability(report)); ok {
		if src, ok := capabilitySource[id]; ok {
			return src
		}
	}
	if f != nil && f.Technique != "" {
		if src, ok := techniqueSource[f.Technique]; ok {
			return src
		}
	}
	src := reportFindingSource(report)
	if report == nil || f == nil || src != vulnerability.FindingSourceSCA {
		return src
	}
	if _, _, bound := capability.ParseRef(reportCapability(report)); bound {
		return src
	}
	switch f.Type {
	case ctis.FindingTypeMisconfiguration:
		return vulnerability.FindingSourceIaC
	case ctis.FindingTypeSecret:
		return vulnerability.FindingSourceSecret
	default:
		return src
	}
}

// findingMetaTechnique is the finding metadata key of the technique the
// producer named for the finding (finding.technique), kept apart from its
// source.
const findingMetaTechnique = "technique"

// findingClaimedTechnique is the finding's own technique when it is one the
// receiver knows (a closed set, so nothing unbounded is stored), else "".
func findingClaimedTechnique(f *ctis.Finding) string {
	if f == nil {
		return ""
	}
	if _, ok := techniqueSource[f.Technique]; !ok {
		return ""
	}
	return string(f.Technique)
}
