package ingest

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/branch"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// interopRepo records interop writes and VEX calls.
type interopRepo struct {
	stubFindingRepository
	updates  []vulnerability.InteropUpdate
	vexCalls int
	vexDry   []bool
	vexItems []vulnerability.VEXNotAffected
	vexMatch []shared.ID
	tenants  []shared.ID
}

func (r *interopRepo) UpdateInteropBatch(_ context.Context, tenantID shared.ID, u []vulnerability.InteropUpdate) (int64, error) {
	r.tenants = append(r.tenants, tenantID)
	r.updates = append(r.updates, u...)
	return int64(len(u)), nil
}

func (r *interopRepo) ApplyVEXNotAffected(_ context.Context, tenantID shared.ID, items []vulnerability.VEXNotAffected, dryRun bool) ([]shared.ID, error) {
	r.tenants = append(r.tenants, tenantID)
	r.vexCalls++
	r.vexDry = append(r.vexDry, dryRun)
	r.vexItems = items
	return r.vexMatch, nil
}

func nessusInteropFinding() ctis.Finding {
	v := 8.1
	cred := true
	return ctis.Finding{
		Type: ctis.FindingTypeVulnerability, Title: "OpenSSH regreSSHion", Severity: ctis.SeverityHigh,
		AssetRef: "h", Network: &ctis.NetworkLocation{Port: 22, Protocol: "tcp"},
		Vulnerability: &ctis.VulnerabilityDetails{
			CVSSScore: 8.1, CVSSVersion: "3.1", CVSSVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", CVSSSource: "nvd",
			IDs: []ctis.VulnerabilityID{{Type: ctis.VulnerabilityIDCVE, ID: "cve-2024-6387"}, {Type: ctis.VulnerabilityIDVendor, ID: "USN-6859-1"}},
		},
		Native: &ctis.NativeIdentity{Scheme: ctis.NativeSchemeNessus, VulnID: "201194", Severity: "3", Credentialed: &cred},
		Scores: []ctis.Score{{System: ctis.ScoreSystemCVSS, Version: "4.0", Vector: "CVSS:4.0/AV:N", Value: &v, Source: "vendor"}},
	}
}

func TestFillFromInterop(t *testing.T) {
	f := nessusInteropFinding()
	fillFromInterop(&f)
	assert.Equal(t, "CVE-2024-6387", f.Vulnerability.CVEID, "the CVE comes from the typed ids")
	assert.Equal(t, []string{"CVE-2024-6387"}, f.Vulnerability.CVEIDs)
	assert.Equal(t, "201194", f.RuleID, "the rule comes from the native id")

	// A finding that already names its CVE and rule keeps them.
	g := nessusInteropFinding()
	g.RuleID = "nessus-201194"
	g.Vulnerability.CVEID = "CVE-2023-0001"
	fillFromInterop(&g)
	assert.Equal(t, "CVE-2023-0001", g.Vulnerability.CVEID)
	assert.Nil(t, g.Vulnerability.CVEIDs)
	assert.Equal(t, "nessus-201194", g.RuleID)

	// No CVE and no native id: the preferred other id is the rule.
	h := ctis.Finding{Vulnerability: &ctis.VulnerabilityDetails{Package: "x", IDs: []ctis.VulnerabilityID{{Type: ctis.VulnerabilityIDGHSA, ID: "GHSA-JFH8-C2JP-5V3Q"}}}}
	fillFromInterop(&h)
	assert.Equal(t, "GHSA-jfh8-c2jp-5v3q", h.RuleID)
	fillFromInterop(nil)
}

// A report that already sets cve_id and rule_id keeps exactly its identity
// key when it also sends the CTIS 1.4 members, so no stored fingerprint
// changes; and a report that sends the CVE only in vulnerability.ids gets
// the same key as one that sends it in cve_id.
func TestInterop_IdentityUnchanged(t *testing.T) {
	assetID := shared.NewID()
	legacy := ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "OpenSSH", Severity: ctis.SeverityHigh,
		RuleID: "201194", Network: &ctis.NetworkLocation{Port: 22, Protocol: "tcp"},
		Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2024-6387"}}
	withInterop := legacy
	vv := *legacy.Vulnerability
	withInterop.Vulnerability = &vv
	withInterop.Vulnerability.IDs = []ctis.VulnerabilityID{{Type: ctis.VulnerabilityIDCVE, ID: "CVE-2024-9999"}}
	withInterop.Native = &ctis.NativeIdentity{VulnID: "999999"}
	fillFromInterop(&withInterop)

	k1, ok1 := identityV2(assetID, &legacy, nil, "", 0)
	k2, ok2 := identityV2(assetID, &withInterop, nil, "", 0)
	require.True(t, ok1 && ok2)
	assert.Equal(t, k1.Fingerprint(), k2.Fingerprint())
	fp1, _ := generateFindingFingerprint(assetID, &legacy, nil)
	fp2, _ := generateFindingFingerprint(assetID, &withInterop, nil)
	assert.Equal(t, fp1, fp2)

	onlyIDs := nessusInteropFinding()
	onlyIDs.Native = nil
	onlyIDs.RuleID = "201194"
	fillFromInterop(&onlyIDs)
	k3, ok3 := identityV2(assetID, &onlyIDs, nil, "", 0)
	require.True(t, ok3)
	assert.Equal(t, k1.Fingerprint(), k3.Fingerprint(), "the CVE from ids keys the finding like cve_id")
}

func TestInteropUpdate(t *testing.T) {
	f := nessusInteropFinding()
	f.SourceExtra = map[string]string{"plugin_type": "remote"}
	f.VEX = &ctis.VEX{Status: ctis.VEXStatusAffected, Source: "vendor"}
	u := interopUpdate("fp", &f)
	require.False(t, u.Data.IsEmpty())
	require.NotNil(t, u.Data.Native)
	assert.Equal(t, "201194", u.Data.Native.VulnID)
	require.Len(t, u.Data.Scores, 2, "the 4.0 score and the legacy 3.1 score")
	assert.Equal(t, "4.0", u.Data.Scores[0].Version)
	assert.Equal(t, "3.1", u.Data.Scores[1].Version)
	assert.Equal(t, "nvd", u.Data.Scores[1].Source)
	require.Len(t, u.Data.VulnerabilityIDs, 2)
	assert.Equal(t, "CVE-2024-6387", u.Data.VulnerabilityIDs[0].ID)
	assert.Equal(t, "net:22/tcp", u.Data.LocationKey, "derived by the server")
	assert.Equal(t, "remote", u.Data.SourceExtra["plugin_type"])
	assert.Equal(t, "affected", u.Data.VEX.Status)

	// A legacy finding still gets its single scores as a list.
	legacy := ctis.Finding{Vulnerability: &ctis.VulnerabilityDetails{CVSSScore: 7.5, CVSSVersion: "3.1", VPRScore: 6.1}}
	u = interopUpdate("fp", &legacy)
	assert.Len(t, u.Data.Scores, 2)
}

func runInterop(t *testing.T, mode VEXMode, scope *alterScope, findings []ctis.Finding, repo *interopRepo) (*Output, shared.ID) {
	t.Helper()
	tenantID := shared.NewID()
	p := NewFindingProcessor(repo, nil, nil, logger.NewNop())
	p.vexMode = mode
	out := &Output{}
	report := &ctis.Report{Version: "1.4", Tool: &ctis.Tool{Name: "trivy"}, Findings: findings}
	err := p.processBatch(context.Background(), newTestSensor(t, tenantID), tenantID, report,
		map[string]shared.ID{"h": shared.NewID()}, branch.BranchTypeRules{}, out, map[string]shared.ID{}, false, scope)
	require.NoError(t, err)
	return out, tenantID
}

func vexFinding(status ctis.VEXStatus, justification ctis.VEXJustification) ctis.Finding {
	return ctis.Finding{
		Type: ctis.FindingTypeVulnerability, Title: "xz backdoor", Severity: ctis.SeverityCritical, AssetRef: "h",
		Vulnerability: &ctis.VulnerabilityDetails{Package: "xz-utils", PURL: "pkg:deb/ubuntu/xz-utils@5.6.0", CVEID: "CVE-2024-3094"},
		VEX:           &ctis.VEX{Status: status, Justification: justification, Source: "https://vex.example/doc.json"},
	}
}

func TestVEX_DryRunIsTheDefaultAndStoresTheStatement(t *testing.T) {
	repo := &interopRepo{vexMatch: []shared.ID{shared.NewID()}}
	out, tenant := runInterop(t, "", boundScope(), []ctis.Finding{vexFinding(ctis.VEXStatusNotAffected, ctis.VEXJustificationComponentNotPresent)}, repo)
	require.Equal(t, 1, repo.vexCalls)
	assert.Equal(t, []bool{true}, repo.vexDry)
	assert.Equal(t, 1, out.FindingsVEXNotAffected)
	assert.Equal(t, 1, out.FindingsVEXWouldClose)
	assert.Equal(t, 0, out.FindingsVEXClosed)
	require.Len(t, repo.vexItems, 1)
	assert.Contains(t, repo.vexItems[0].Resolution, "component_not_present")
	assert.Contains(t, repo.vexItems[0].Resolution, "vex.example")
	require.Len(t, repo.updates, 1)
	assert.Equal(t, "not_affected", repo.updates[0].Data.VEX.Status)
	assert.Equal(t, "pkg:deb/ubuntu/xz-utils", repo.updates[0].Data.LocationKey)
	for _, tid := range repo.tenants {
		assert.Equal(t, tenant, tid, "every write is scoped to the ingesting tenant")
	}
}

func TestVEX_EnforceClosesOnlyWhenCommandBound(t *testing.T) {
	repo := &interopRepo{vexMatch: []shared.ID{shared.NewID()}}
	out, _ := runInterop(t, SourceResolveEnforce, boundScope(), []ctis.Finding{vexFinding(ctis.VEXStatusNotAffected, ctis.VEXJustificationComponentNotPresent)}, repo)
	assert.Equal(t, []bool{false}, repo.vexDry)
	assert.Equal(t, 1, out.FindingsVEXClosed)
	assert.Len(t, out.VEXIDs, 1)

	// Not bound to a command, or mode off: no state change at all.
	for _, c := range []struct {
		mode  VEXMode
		scope *alterScope
	}{{SourceResolveEnforce, nil}, {SourceResolveEnforce, newAlterScope(Binding{})}, {SourceResolveOff, boundScope()}} {
		repo := &interopRepo{vexMatch: []shared.ID{shared.NewID()}}
		out, _ := runInterop(t, c.mode, c.scope, []ctis.Finding{vexFinding(ctis.VEXStatusNotAffected, ctis.VEXJustificationComponentNotPresent)}, repo)
		assert.Equal(t, 0, repo.vexCalls, "mode %s", c.mode)
		assert.Equal(t, 1, out.FindingsVEXNotAffected)
		assert.Len(t, repo.updates, 1, "the statement is still stored")
	}
}

func TestVEX_OnlyNotAffectedWithAReason(t *testing.T) {
	bare := vexFinding(ctis.VEXStatusNotAffected, "")
	affected := vexFinding(ctis.VEXStatusAffected, "")
	forged := vexFinding(ctis.VEXStatusNotAffected, "made_up")
	repo := &interopRepo{}
	out, _ := runInterop(t, SourceResolveEnforce, boundScope(), []ctis.Finding{bare}, repo)
	assert.Equal(t, 0, repo.vexCalls)
	assert.Equal(t, 0, out.FindingsVEXNotAffected)
	for _, f := range []ctis.Finding{affected, forged} {
		repo := &interopRepo{}
		runInterop(t, SourceResolveEnforce, boundScope(), []ctis.Finding{f}, repo)
		assert.Equal(t, 0, repo.vexCalls)
	}
}

func TestParseVEXMode(t *testing.T) {
	assert.Equal(t, SourceResolveEnforce, ParseVEXMode("ENFORCE"))
	assert.Equal(t, SourceResolveOff, ParseVEXMode("off"))
	assert.Equal(t, SourceResolveDryRun, ParseVEXMode("yes please"))
}

func TestIdentityHints(t *testing.T) {
	ca := &ctis.Asset{Type: ctis.AssetTypeHost, Value: "10.20.0.15", IdentityHints: &ctis.IdentityHints{
		FQDN: "db01.corp.example.com", NetBIOSName: "DB01", MACAddresses: []string{"00:50:56:9a:1b:2c"},
		OSCPE: "cpe:/o:canonical:ubuntu_linux:22.04", AgentID: "agent\n-1", CloudResourceID: "i-0abc123def4567890",
	}}
	ids := identifiersFor(ca, asset.AssetTypeHost, "10.20.0.15")
	kinds := map[asset.IdentifierKind]bool{}
	for _, id := range ids {
		kinds[id.Kind] = true
	}
	for _, k := range []asset.IdentifierKind{asset.IdentifierFQDN, asset.IdentifierHostname, asset.IdentifierMAC, asset.IdentifierCloudID} {
		assert.True(t, kinds[k], "identity hint %s not used for matching", k)
	}

	// A typed identifiers block wins over a hint of the same kind.
	ca.Identifiers = &ctis.AssetIdentifiers{MACAddresses: []string{"00:50:56:00:00:01"}}
	var macs []string
	for _, id := range identifiersFor(ca, asset.AssetTypeHost, "10.20.0.15") {
		if id.Kind == asset.IdentifierMAC {
			macs = append(macs, id.Value)
		}
	}
	assert.Len(t, macs, 1)

	props := identityHintProperties(ca.IdentityHints)
	assert.Equal(t, "agent-1", props["agent_id"], "control characters are stripped")
	assert.Equal(t, "cpe:/o:canonical:ubuntu_linux:22.04", props["os_cpe"])
	assert.Nil(t, identityHintProperties(nil))
	assert.Nil(t, identityHintProperties(&ctis.IdentityHints{FQDN: "  "}))
	long := identityHintProperties(&ctis.IdentityHints{FQDN: strings.Repeat("a", 1000), MACAddresses: make([]string, 100)})
	assert.Len(t, long["fqdn"], maxHintLen)
	_, hasMACs := long["mac_addresses"]
	assert.False(t, hasMACs, "empty MACs are dropped")
}
