package vuls

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/api/internal/infra/adapters/core"
	"github.com/openctemio/ctis"
)

// Adapter converts Vuls JSON output to CTIS.
type Adapter struct{}

// NewAdapter creates a new Vuls adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return "vuls"
}

// InputFormats returns supported input formats.
func (a *Adapter) InputFormats() []string {
	return []string{"vuls", "json"}
}

// OutputFormat returns the output format.
func (a *Adapter) OutputFormat() string {
	return "ctis"
}

// CanConvert checks if the input can be converted.
func (a *Adapter) CanConvert(input []byte) bool {
	var report VulsReport
	if err := json.Unmarshal(input, &report); err != nil {
		return false
	}
	return report.ServerName != "" && report.ScannedCves != nil
}

// Convert transforms Vuls JSON input to CTIS Report.
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	var vulsReport VulsReport
	if err := json.Unmarshal(input, &vulsReport); err != nil {
		return nil, fmt.Errorf("parse vuls: %w", err)
	}

	report := ctis.NewReport()
	report.Metadata.SourceType = "scanner"
	report.Metadata.CoverageType = "full"
	report.Tool = &ctis.Tool{
		Name:         "vuls",
		Vendor:       "future-architect",
		InfoURL:      "https://vuls.io",
		Capabilities: []string{"vulnerability"},
	}

	// Create host asset
	asset := a.buildAsset(&vulsReport)
	report.Assets = append(report.Assets, asset)

	// Create dependencies from packages
	for _, pkg := range vulsReport.Packages {
		dep := a.buildDependency(pkg, &vulsReport)
		report.Dependencies = append(report.Dependencies, dep)
	}

	// Convert CVEs to findings (1 CVE = 1 finding)
	for i, cve := range vulsReport.ScannedCves {
		finding := a.convertCVE(cve, &vulsReport, i)
		if finding == nil {
			continue
		}

		// Filter by min severity
		if opts != nil && opts.MinSeverity != "" {
			if !meetsMinSeverity(finding.Severity, ctis.Severity(opts.MinSeverity)) {
				continue
			}
		}

		report.Findings = append(report.Findings, *finding)
	}

	return report, nil
}

// buildAsset creates a CTIS asset from the Vuls server info.
func (a *Adapter) buildAsset(vr *VulsReport) ctis.Asset {
	asset := ctis.Asset{
		ID:   "host-1",
		Type: ctis.AssetTypeHost,
		Name: vr.ServerName,
	}

	// Use first IPv4 as primary value, fallback to hostname
	if len(vr.ScannedIPv4) > 0 {
		asset.Value = vr.ScannedIPv4[0]
		asset.Type = ctis.AssetTypeIPAddress
		asset.Technical = &ctis.AssetTechnical{
			IPAddress: &ctis.IPAddressTechnical{
				Version:  4,
				Hostname: vr.ServerName,
			},
		}
	} else {
		asset.Value = vr.ServerName
	}

	asset.Tags = []string{"vuls", vr.Family, vr.Release}

	return asset
}

// buildDependency creates a CTIS dependency from a Vuls package.
func (a *Adapter) buildDependency(pkg VulsPackage, vr *VulsReport) ctis.Dependency {
	version := pkg.Version
	if pkg.Release != "" {
		version = pkg.Version + "-" + pkg.Release
	}

	dep := ctis.Dependency{
		Name:      pkg.Name,
		Version:   version,
		Type:      "os",
		Ecosystem: mapOSFamily(vr.Family),
		PURL:      buildPURL(vr.Family, vr.Release, pkg.Name, version, pkg.Arch),
	}

	return dep
}

// convertCVE converts a single Vuls CVE result to a CTIS finding.
func (a *Adapter) convertCVE(cve VulsCveResult, vr *VulsReport, idx int) *ctis.Finding {
	if cve.CveID == "" {
		return nil
	}

	// Extract best CVE content (prefer NVD, then any source)
	content := a.extractBestContent(cve.CveContents)

	finding := &ctis.Finding{
		ID:       fmt.Sprintf("finding-%d", idx+1),
		Type:     ctis.FindingTypeVulnerability,
		RuleID:   cve.CveID,
		AssetRef: "host-1",
		Tags:     []string{"vuls", vr.ServerName},
	}

	// Title
	if content != nil && content.Title != "" {
		finding.Title = content.Title
	} else {
		finding.Title = cve.CveID
	}

	// Description
	if content != nil && content.Summary != "" {
		finding.Description = content.Summary
	}

	// Build vulnerability details
	vulnDetails := &ctis.VulnerabilityDetails{
		CVEID: cve.CveID,
	}

	// CVSS scoring - prefer v4.0, then v3, then v2
	if content != nil {
		if content.Cvss40Score > 0 {
			vulnDetails.CVSSScore = content.Cvss40Score
			vulnDetails.CVSSVector = content.Cvss40Vector
			vulnDetails.CVSSVersion = "4.0"
		} else if content.Cvss3Score > 0 {
			vulnDetails.CVSSScore = content.Cvss3Score
			vulnDetails.CVSSVector = content.Cvss3Vector
			vulnDetails.CVSSVersion = "3.1"
		} else if content.Cvss2Score > 0 {
			vulnDetails.CVSSScore = content.Cvss2Score
			vulnDetails.CVSSVector = content.Cvss2Vector
			vulnDetails.CVSSVersion = "2.0"
		}

		// CWE IDs
		if len(content.CweIDs) > 0 {
			vulnDetails.CWEIDs = content.CweIDs
			vulnDetails.CWEID = content.CweIDs[0]
		}
	}

	// Affected packages
	if len(cve.AffectedPackages) > 0 {
		pkg := cve.AffectedPackages[0]
		vulnDetails.Package = pkg.Name
		if pkg.FixedIn != "" {
			vulnDetails.FixedVersion = pkg.FixedIn
		}

		// Build PURL for affected package
		if p, ok := vr.Packages[pkg.Name]; ok {
			version := p.Version
			if p.Release != "" {
				version = p.Version + "-" + p.Release
			}
			vulnDetails.AffectedVersion = version
			vulnDetails.PURL = buildPURL(vr.Family, vr.Release, pkg.Name, version, p.Arch)
			vulnDetails.Ecosystem = mapOSFamily(vr.Family)
		}
	}

	finding.Vulnerability = vulnDetails

	// Severity from CVSS score
	finding.Severity = cvssToSeverity(vulnDetails.CVSSScore)

	// Confidence
	if len(cve.Confidences) > 0 {
		finding.Confidence = cve.Confidences[0].Score
	}

	// References
	if content != nil {
		if content.SourceLink != "" {
			finding.References = append(finding.References, content.SourceLink)
		}
		for _, ref := range content.References {
			if ref.Link != "" {
				finding.References = append(finding.References, ref.Link)
			}
		}
	}

	// Remediation
	if len(cve.AffectedPackages) > 0 && cve.AffectedPackages[0].FixedIn != "" {
		pkg := cve.AffectedPackages[0]
		finding.Remediation = &ctis.Remediation{
			Recommendation: fmt.Sprintf("Update %s to version %s", pkg.Name, pkg.FixedIn),
		}
	} else if len(cve.AffectedPackages) > 0 && cve.AffectedPackages[0].NotFixedYet {
		finding.Remediation = &ctis.Remediation{
			Recommendation: "No fix available yet. Consider mitigation or alternative packages.",
		}
	}

	// Fingerprint: package + version + CVE
	if vulnDetails.Package != "" {
		finding.Fingerprint = core.GenerateScaFingerprint(
			vulnDetails.Package, vulnDetails.AffectedVersion, cve.CveID,
		)
	} else {
		finding.Fingerprint = core.GenerateScaFingerprint(
			vr.ServerName, "", cve.CveID,
		)
	}

	return finding
}

// extractBestContent selects the best CVE content from available sources.
// Priority: nvd > redhat > ubuntu > debian > any other.
func (a *Adapter) extractBestContent(contents VulsCveContents) *VulsCveContent {
	if contents == nil {
		return nil
	}

	priority := []string{"nvd", "redhat", "ubuntu", "debian", "oracle", "amazon", "suse"}

	for _, source := range priority {
		if items, ok := contents[source]; ok && len(items) > 0 {
			return &items[0]
		}
	}

	// Fallback: any source
	for _, items := range contents {
		if len(items) > 0 {
			return &items[0]
		}
	}

	return nil
}

// buildPURL generates a Package URL for an OS package.
func buildPURL(family, release, name, version, arch string) string {
	// Map OS family to PURL type and namespace
	purlType, namespace := mapFamilyToPURL(family, release)

	purl := fmt.Sprintf("pkg:%s/%s/%s@%s", purlType, namespace, name, version)

	// Add qualifiers
	qualifiers := make([]string, 0, 2)
	if arch != "" {
		qualifiers = append(qualifiers, "arch="+arch)
	}
	if release != "" {
		qualifiers = append(qualifiers, "distro="+release)
	}

	if len(qualifiers) > 0 {
		purl += "?" + strings.Join(qualifiers, "&")
	}

	return purl
}

// mapFamilyToPURL maps Vuls OS family to PURL type and namespace.
func mapFamilyToPURL(family, _ string) (purlType, namespace string) {
	lf := strings.ToLower(family)

	switch lf {
	case "debian", "ubuntu", "raspbian":
		return "deb", lf
	case "redhat", "centos", "alma", "rocky":
		return "rpm", lf
	case "fedora":
		return "rpm", "fedora"
	case "amazon":
		return "rpm", "amzn"
	case "oracle":
		return "rpm", "oraclelinux"
	case "alpine":
		return "apk", "alpine"
	case "freebsd":
		return "pkg", "freebsd"
	default:
		if strings.Contains(lf, "suse") || strings.Contains(lf, "sles") || strings.Contains(lf, "opensuse") {
			return "rpm", "opensuse"
		}
		return "generic", lf
	}
}

// mapOSFamily maps Vuls OS family to ecosystem name.
func mapOSFamily(family string) string {
	lf := strings.ToLower(family)

	switch lf {
	case "debian", "ubuntu", "raspbian":
		return "deb"
	case "redhat", "centos", "alma", "rocky", "fedora", "amazon", "oracle", "suse":
		return "rpm"
	case "alpine":
		return "apk"
	default:
		return lf
	}
}

// cvssToSeverity converts a CVSS score to a CTIS severity level.
func cvssToSeverity(score float64) ctis.Severity {
	switch {
	case score >= 9.0:
		return ctis.SeverityCritical
	case score >= 7.0:
		return ctis.SeverityHigh
	case score >= 4.0:
		return ctis.SeverityMedium
	case score > 0:
		return ctis.SeverityLow
	default:
		return ctis.SeverityInfo
	}
}

// meetsMinSeverity checks if severity meets minimum threshold.
func meetsMinSeverity(s, min ctis.Severity) bool {
	order := map[ctis.Severity]int{
		ctis.SeverityCritical: 5,
		ctis.SeverityHigh:     4,
		ctis.SeverityMedium:   3,
		ctis.SeverityLow:      2,
		ctis.SeverityInfo:     1,
	}
	return order[s] >= order[min]
}

// Ensure Adapter implements core.Adapter
var _ core.Adapter = (*Adapter)(nil)

// ParseToCTIS is a convenience function to parse Vuls JSON to CTIS format.
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	adapter := NewAdapter()

	var adapterOpts *core.AdapterOptions
	if opts != nil {
		adapterOpts = &core.AdapterOptions{
			MinSeverity: opts.ToolType, // Reuse as severity filter if needed
		}
	}

	return adapter.Convert(context.Background(), data, adapterOpts)
}
