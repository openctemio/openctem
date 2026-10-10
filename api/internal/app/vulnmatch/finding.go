package vulnmatch

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// BuildFinding turns a match into a finding: technique va, the reserved
// tool name, the network identity scanners use for the same CVE on the same
// asset and port, and the evidence of why it matched.
func BuildFinding(tenantID shared.ID, m softwarematch.Match, confidence int, label vulnmatch.Label,
	reasons []string, key vulnerability.IdentityKey,
) (*vulnerability.Finding, error) {
	sev, err := vulnerability.ParseSeverity(severityOf(m.CVE.Severity))
	if err != nil {
		return nil, err
	}
	product := strings.TrimSpace(m.Product)
	f, err := vulnerability.NewFinding(tenantID, m.AssetID, vulnerability.FindingSourceVA, softwarematch.ToolName, sev,
		fmt.Sprintf("%s %s may be affected by %s (version-based match)", product, m.Version, m.Result.CVEID))
	if err != nil {
		return nil, err
	}
	f.SetTitle(fmt.Sprintf("%s in %s %s", m.Result.CVEID, product, m.Version))
	if m.CVE.Description != "" {
		f.SetDescription(m.CVE.Description)
	}
	f.SetRuleID(m.Result.CVEID)
	if err := f.SetClassification(m.Result.CVEID, m.CVE.CVSSScore, m.CVE.CVSSVector, m.CVE.CWEs, nil); err != nil {
		return nil, err
	}
	c := confidence
	if err := f.SetConfidence(&c); err != nil {
		return nil, err
	}
	if m.Port > 0 {
		f.SetNetwork(vulnerability.NetworkLocation{Port: m.Port, Transport: m.Transport})
	}
	f.SetFingerprint(key.Fingerprint())
	if err := f.SetIdentity(key); err != nil {
		return nil, err
	}
	if reasons == nil {
		reasons = []string{}
	}
	f.SetMetadata("version_match", map[string]any{
		"label":      string(label),
		"confidence": confidence,
		"product":    product,
		"vendor":     m.Vendor,
		"product_id": m.ProductID.String(),
		"version":    m.Version,
		"version_id": m.VersionID.String(),
		"qualifier":  m.Qualifier,
		"location":   m.Location,
		"evidence":   m.Evidence,
		"range":      m.Result.RangeText,
		"reasons":    reasons,
		"source":     "nvd",
	})
	return f, nil
}

func severityOf(s string) string {
	switch strings.ToLower(s) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(s)
	}
	return "info"
}
