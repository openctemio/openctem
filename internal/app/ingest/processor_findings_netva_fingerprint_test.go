package ingest

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/ctis"
)

// A network/host vulnerability — a CVE observed on a host by a scanner such as
// Nessus, Qualys or Tenable — carries a CVE but no package and no code file
// location. Before the fix generateFindingFingerprint left these to the generic
// algorithm (rule id + file + message), so the SAME CVE on the SAME host reported
// by two scanners with different plugin ids and messages produced two distinct
// fingerprints and therefore two findings. The base must key on CVE(+port) alone
// so the composite (asset id + base) dedups across scanners.
func TestGenerateFindingFingerprint_NetworkVA_SameCVESameHostDifferentScanner_Dedups(t *testing.T) {
	assetID := shared.NewID() // same host asset for both scanner reports

	nessus := &ctis.Finding{
		Type:    ctis.FindingTypeVulnerability,
		Title:   "Nessus: OpenSSL Remote Code Execution",
		RuleID:  "nessus-plugin-118987",
		Message: "The remote host is affected by a vulnerability in OpenSSL.",
		Vulnerability: &ctis.VulnerabilityDetails{
			CVEID: "CVE-2022-3602",
		},
		Network: &ctis.NetworkLocation{Host: "10.0.0.5", Port: 443, Protocol: "tcp"},
	}
	qualys := &ctis.Finding{
		Type:    ctis.FindingTypeVulnerability,
		Title:   "QID 376023: OpenSSL X.509 buffer overflow",
		RuleID:  "qualys-qid-376023",
		Message: "OpenSSL is prone to a buffer overflow; upgrade to a fixed version.",
		Vulnerability: &ctis.VulnerabilityDetails{
			CVEID: "CVE-2022-3602",
		},
		Network: &ctis.NetworkLocation{Host: "10.0.0.5", Port: 443, Protocol: "tcp"},
	}

	nComposite, nBase := generateFindingFingerprint(assetID, nessus, nil)
	qComposite, qBase := generateFindingFingerprint(assetID, qualys, nil)

	if nBase != qBase {
		t.Errorf("base fingerprint differs across scanners for the same CVE+host+port:\n  nessus=%s\n  qualys=%s", nBase, qBase)
	}
	if nComposite != qComposite {
		t.Errorf("composite fingerprint differs across scanners → two findings for one CVE on one host:\n  nessus=%s\n  qualys=%s", nComposite, qComposite)
	}
}

// The primary CVEID field and the grouped CVEIDs list must agree: a scanner that
// reports the CVE in CVEIDs must dedup with one that reports it in CVEID.
func TestGenerateFindingFingerprint_NetworkVA_CVEIDvsCVEIDsAgree(t *testing.T) {
	assetID := shared.NewID()

	primary := &ctis.Finding{
		Type:          ctis.FindingTypeVulnerability,
		RuleID:        "scanner-a-1",
		Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2021-44228"},
		Network:       &ctis.NetworkLocation{Host: "host.example.com", Port: 8080},
	}
	list := &ctis.Finding{
		Type:          ctis.FindingTypeVulnerability,
		RuleID:        "scanner-b-2",
		Vulnerability: &ctis.VulnerabilityDetails{CVEIDs: []string{"CVE-2021-44228"}},
		Network:       &ctis.NetworkLocation{Host: "host.example.com", Port: 8080},
	}

	_, pBase := generateFindingFingerprint(assetID, primary, nil)
	_, lBase := generateFindingFingerprint(assetID, list, nil)
	if pBase != lBase {
		t.Errorf("CVEID and CVEIDs placement produced different base fingerprints:\n  cveid=%s\n  cveids=%s", pBase, lBase)
	}
}

// Port is part of the key: the same CVE on two different ports of one host is two
// findings, so their fingerprints must differ.
func TestGenerateFindingFingerprint_NetworkVA_DifferentPortDoesNotDedup(t *testing.T) {
	assetID := shared.NewID()

	p443 := &ctis.Finding{
		Type:          ctis.FindingTypeVulnerability,
		RuleID:        "plugin-1",
		Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2023-0001"},
		Network:       &ctis.NetworkLocation{Host: "10.0.0.9", Port: 443},
	}
	p8443 := &ctis.Finding{
		Type:          ctis.FindingTypeVulnerability,
		RuleID:        "plugin-1",
		Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2023-0001"},
		Network:       &ctis.NetworkLocation{Host: "10.0.0.9", Port: 8443},
	}

	_, base443 := generateFindingFingerprint(assetID, p443, nil)
	_, base8443 := generateFindingFingerprint(assetID, p8443, nil)
	if base443 == base8443 {
		t.Error("same CVE on different ports produced the same fingerprint; port must be part of the network-VA key")
	}
}

// An SCA finding (has a package) must NOT be treated as a network VA — its
// existing package+version+CVE dedup behavior is preserved.
func TestGenerateFindingFingerprint_SCA_NotTreatedAsNetworkVA(t *testing.T) {
	assetID := shared.NewID()

	scaA := &ctis.Finding{
		Type:    ctis.FindingTypeVulnerability,
		RuleID:  "trivy-1",
		Message: "lodash prototype pollution",
		Vulnerability: &ctis.VulnerabilityDetails{
			CVEID:           "CVE-2019-10744",
			Package:         "lodash",
			AffectedVersion: "4.17.11",
		},
	}
	scaB := &ctis.Finding{
		Type:    ctis.FindingTypeVulnerability,
		RuleID:  "grype-2",
		Message: "different message entirely",
		Vulnerability: &ctis.VulnerabilityDetails{
			CVEID:           "CVE-2019-10744",
			Package:         "lodash",
			AffectedVersion: "4.17.11",
		},
	}

	_, baseA := generateFindingFingerprint(assetID, scaA, nil)
	_, baseB := generateFindingFingerprint(assetID, scaB, nil)
	// Same package+version+CVE → SCA algorithm dedups these regardless of scanner,
	// and it must remain the SCA key (unchanged behavior), which also happens to be
	// scanner-independent.
	if baseA != baseB {
		t.Errorf("SCA dedup regressed: same package+version+CVE gave different base fingerprints:\n  a=%s\n  b=%s", baseA, baseB)
	}
}
