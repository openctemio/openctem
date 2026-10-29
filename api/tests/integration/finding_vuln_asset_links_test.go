package integration

// Same-issue links across techniques on one asset: the same CVE on the same
// asset, found by a version match, an active template check or a network
// scanner import, is linked (never merged). The earliest finding is the
// original and is never demoted; a link changes no status or SLA; an active
// check confirms a version match (it counts on the attack path again); a
// finding that joins an open original raises no second "new finding"
// notification; another tenant, another asset, another port and a person's
// unlink are never linked.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type vaRig struct {
	r    *v2Rig
	e    *matchEnv
	repo *postgres.FindingIssueLinkRepository

	mu       sync.Mutex
	notified []string // tool names of the findings the created callback saw
}

func newVARig(t *testing.T, wired bool) *vaRig {
	t.Helper()
	v := &vaRig{}
	v.r = newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		v.repo = postgres.NewFindingIssueLinkRepository(db)
		v.repo.SetPriorityQueue(postgres.NewScoringRepository(db))
		if wired {
			svc.SetIssueLinkStore(v.repo)
		}
		svc.SetSecretFingerprinter(vulnerability.NewSecretFingerprinter([]byte("vuln-asset-links-server-secret-0123456789")))
		svc.SetFindingCreatedCallback(func(_ context.Context, _ shared.ID, fs []*vulnerability.Finding) {
			v.mu.Lock()
			defer v.mu.Unlock()
			for _, f := range fs {
				v.notified = append(v.notified, f.ToolName())
			}
		})
	})
	v.e = newMatchEnv(t)
	if wired {
		v.e.svc.SetIssueLinker(v.repo)
	}
	return v
}

func (v *vaRig) notifiedCount(tool string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	n := 0
	for _, x := range v.notified {
		if x == tool {
			n++
		}
	}
	return n
}

// vaTenant is a tenant with version matching on and one domain asset.
type vaTenant struct {
	v2Tenant
	host  string
	asset shared.ID
}

func (v *vaRig) tenant(t *testing.T, host string) vaTenant {
	t.Helper()
	tn := v.r.newTenant("nuclei", "nessus", "trivy")
	_, err := v.r.db.Exec(`UPDATE tenants SET settings = '{"general": {"timezone": "UTC"}, "vuln_matching": {"enabled": true}}'::jsonb WHERE id = $1`, tn.tenant.String())
	require.NoError(t, err)
	out := vaTenant{v2Tenant: tn, host: host}
	// A harmless informational result puts the asset in place.
	v.scan(t, out, "nuclei", ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "Technology detected", Severity: ctis.SeverityInfo,
		RuleID: "tech-detect", Location: &ctis.FindingLocation{Path: "https://" + host + "/"}})
	require.NoError(t, v.r.db.QueryRow(`SELECT id FROM assets WHERE tenant_id = $1 AND lower(name) = lower($2)`, tn.tenant.String(), host).Scan(&out.asset))
	return out
}

func (v *vaRig) scan(t *testing.T, tn vaTenant, tool string, fs ...ctis.Finding) {
	t.Helper()
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	for i := range fs {
		fs[i].AssetRef = "a"
	}
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool},
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
		Assets:   []ctis.Asset{{ID: "a", Type: ctis.AssetTypeDomain, Value: tn.host}},
		Findings: fs}
	out, err := v.r.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep})
	require.NoError(t, err)
	require.Empty(t, out.Errors)
}

func nucleiCVE(cve, url string) ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "CVE template " + cve, Severity: ctis.SeverityHigh,
		RuleID: cve, Location: &ctis.FindingLocation{Path: url}, Vulnerability: &ctis.VulnerabilityDetails{CVEID: cve}}
}

func networkCVE(cve string, port int) ctis.Finding {
	f := ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "Scanner plugin " + cve, Severity: ctis.SeverityHigh,
		RuleID: "plugin-" + cve, Vulnerability: &ctis.VulnerabilityDetails{CVEID: cve}}
	if port > 0 {
		f.Network = &ctis.NetworkLocation{Port: port, Protocol: "tcp"}
	}
	return f
}

func scaCVE(cve string) ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "Vulnerable package", Severity: ctis.SeverityHigh,
		RuleID: cve, Vulnerability: &ctis.VulnerabilityDetails{CVEID: cve, Package: "widget", PURL: "pkg:generic/widget@1.4.2"}}
}

func (v *vaRig) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, v.r.db.QueryRow(q, args...).Scan(&n), q)
	return n
}

// matchFinding runs the matcher for the tenant's asset and returns the id of
// its version-match finding.
func (v *vaRig) matchFinding(t *testing.T, tn vaTenant) string {
	t.Helper()
	v.e.observe(tn.tenant, tn.asset, "1.4.2")
	v.e.run()
	var id string
	require.NoError(t, v.r.db.QueryRow(`SELECT id FROM findings WHERE tenant_id = $1 AND tool_name = 'version-match' AND cve_id = $2`,
		tn.tenant.String(), v.e.cveID).Scan(&id))
	return id
}

func (v *vaRig) idOfTool(t *testing.T, tn vaTenant, tool string) string {
	t.Helper()
	var id string
	require.NoError(t, v.r.db.QueryRow(`SELECT id FROM findings WHERE tenant_id = $1 AND cve_id = $2 AND tool_name = $3 AND status <> 'duplicate'`,
		tn.tenant.String(), v.e.cveID, tool).Scan(&id), tool)
	return id
}

func (v *vaRig) links(t *testing.T, tn vaTenant) int {
	t.Helper()
	return v.count(t, `SELECT count(*) FROM finding_issue_links WHERE tenant_id = $1 AND state = 'active' AND rule = 'vuln_asset'`, tn.tenant.String())
}

func (v *vaRig) linkedPair(t *testing.T, tn vaTenant, primary, member string) bool {
	t.Helper()
	return v.count(t, `SELECT count(*) FROM finding_issue_links WHERE tenant_id = $1 AND state = 'active' AND rule = 'vuln_asset'
		AND primary_id = $2 AND member_id = $3 AND basis = '{asset,vuln,port}'`, tn.tenant.String(), primary, member) == 1
}

func (v *vaRig) cveFindings(t *testing.T, tn vaTenant) int {
	t.Helper()
	return v.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND cve_id = $2 AND status <> 'duplicate'`, tn.tenant.String(), v.e.cveID)
}

func (v *vaRig) confirmedBy(t *testing.T, id string) string {
	t.Helper()
	var tool string
	require.NoError(t, v.r.db.QueryRow(`SELECT COALESCE(metadata->'version_match'->'confirmed_by'->>'tool', '') FROM findings WHERE id = $1`, id).Scan(&tool))
	return tool
}

func (v *vaRig) leadOnAttackPath(t *testing.T, tn vaTenant) string {
	t.Helper()
	got, err := postgres.NewFindingRepository(&postgres.DB{DB: v.r.db}).AttackPathFindings(context.Background(), tn.tenant, []string{tn.asset.String()})
	require.NoError(t, err)
	if l := got[tn.asset.String()].Lead; l != nil && l.CVEID == v.e.cveID {
		return l.ID
	}
	return ""
}

func TestVulnAssetLinks_VersionMatchThenNuclei(t *testing.T) {
	v := newVARig(t, true)
	tn := v.tenant(t, "va1-"+shared.NewID().String()[:8]+".example.com")

	vm := v.matchFinding(t, tn)
	require.Equal(t, 1, v.cveFindings(t, tn))
	// A banner match below the likely threshold is a potential vulnerability:
	// it does not lead the attack path.
	_, err := v.r.db.Exec(`UPDATE findings SET confidence = 65 WHERE id = $1`, vm)
	require.NoError(t, err)
	require.Empty(t, v.leadOnAttackPath(t, tn), "an unconfirmed potential match leads the attack path")

	v.scan(t, tn, "nuclei", nucleiCVE(v.e.cveID, "https://"+tn.host+"/"))
	require.Equal(t, 2, v.cveFindings(t, tn), "a version match and a template check are two findings")
	nu := v.idOfTool(t, tn, "nuclei")

	// One link: the earlier finding is the original, the template check a member.
	require.Equal(t, 1, v.links(t, tn))
	require.True(t, v.linkedPair(t, tn, vm, nu), "the version match is the original")
	// Nothing about either finding moved.
	require.Equal(t, 2, v.count(t, `SELECT count(*) FROM findings WHERE id IN ($1, $2) AND status = 'new' AND duplicate_of IS NULL`, vm, nu))
	// The original's timeline learns that another technique saw it.
	require.Equal(t, 1, v.count(t, `SELECT count(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'detected_by_another_source'`, vm))
	// No second "new finding" notification for the member: the issue is open.
	require.Equal(t, 0, v.notifiedCount("nuclei")-v.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND tool_name = 'nuclei' AND rule_id = 'tech-detect'`, tn.tenant.String()),
		"the member of an open original raised a second notification")

	// The active check confirmed the version match: it is on the attack path
	// again, recorded with the confirming tool, and its asset is queued for a
	// priority pass that no longer caps it.
	require.Equal(t, "nuclei", v.confirmedBy(t, vm))
	require.Equal(t, vm, v.leadOnAttackPath(t, tn))
	require.Equal(t, 1, v.count(t, `SELECT count(*) FROM finding_priority_queue WHERE tenant_id = $1 AND asset_id = $2`, tn.tenant.String(), tn.asset.String()))

	// The dashboard facts count the group once.
	_, err = v.r.db.Exec(`SELECT dash_recompute_asset($1, $2)`, tn.tenant.String(), tn.asset.String())
	require.NoError(t, err)
	require.Equal(t, 1, v.count(t, `SELECT COALESCE(sum(finding_count), 0) FROM dash_asset_state WHERE tenant_id = $1 AND asset_id = $2 AND severity = 'high' AND lens = 'open'`,
		tn.tenant.String(), tn.asset.String()))

	// A later sighting of both changes nothing: one link, still one confirmation.
	v.scan(t, tn, "nuclei", nucleiCVE(v.e.cveID, "https://"+tn.host+"/"))
	v.e.run()
	require.Equal(t, 1, v.links(t, tn))
	require.Equal(t, 2, v.cveFindings(t, tn))

	// A person unlinks: the pair is never linked again.
	pID, _ := shared.IDFromString(vm)
	mID, _ := shared.IDFromString(nu)
	_, _, err = v.repo.Unlink(context.Background(), tn.tenant, pID, mID, "")
	require.NoError(t, err)
	v.scan(t, tn, "nuclei", nucleiCVE(v.e.cveID, "https://"+tn.host+"/"))
	_, err = v.repo.BackfillLinks(context.Background(), tn.tenant, true, 10)
	require.NoError(t, err)
	require.Equal(t, 0, v.links(t, tn), "an unlinked pair was linked again")
}

func TestVulnAssetLinks_NucleiThenVersionMatchIsOneFinding(t *testing.T) {
	v := newVARig(t, true)
	tn := v.tenant(t, "va2-"+shared.NewID().String()[:8]+".example.com")
	v.scan(t, tn, "nuclei", nucleiCVE(v.e.cveID, "https://"+tn.host+"/"))
	require.Equal(t, 1, v.cveFindings(t, tn))

	v.e.observe(tn.tenant, tn.asset, "1.4.2")
	v.e.run()
	require.Equal(t, 1, v.cveFindings(t, tn), "the matcher created a second finding for a CVE open on the asset")
	require.Equal(t, 0, v.links(t, tn))
}

func TestVulnAssetLinks_NetworkImportVersusNuclei(t *testing.T) {
	v := newVARig(t, true)
	tn := v.tenant(t, "va3-"+shared.NewID().String()[:8]+".example.com")
	v.scan(t, tn, "nuclei", nucleiCVE(v.e.cveID, "https://"+tn.host+"/"))
	nu := v.idOfTool(t, tn, "nuclei")

	// The same CVE on the same port from a scanner import: two findings, linked.
	v.scan(t, tn, "nessus", networkCVE(v.e.cveID, 443))
	require.Equal(t, 2, v.cveFindings(t, tn))
	nx := v.idOfTool(t, tn, "nessus")
	require.True(t, v.linkedPair(t, tn, nu, nx), "the earlier template finding is the original")
	require.Equal(t, 1, v.notifiedCount("nuclei")-v.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND rule_id = 'tech-detect'`, tn.tenant.String()),
		"the template finding raised its own notification")
	require.Equal(t, 0, v.notifiedCount("nessus"), "the scanner member of an open original raised a second notification")
	// No version match is in the group: nothing is confirmed.
	require.Equal(t, 0, v.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND metadata->'version_match'->'confirmed_by' IS NOT NULL`, tn.tenant.String()))

	// A report at host level agrees with the port-level finding.
	v.scan(t, tn, "nessus", networkCVE(v.e.cveID, 0))
	require.Equal(t, 3, v.cveFindings(t, tn))
	require.Equal(t, 2, v.links(t, tn))
}

func TestVulnAssetLinks_DifferentPortOrAssetOrCVEIsNotLinked(t *testing.T) {
	v := newVARig(t, true)
	tn := v.tenant(t, "va4-"+shared.NewID().String()[:8]+".example.com")
	other := v.tenant(t, "va4b-"+shared.NewID().String()[:8]+".example.com")
	v.scan(t, tn, "nuclei", nucleiCVE(v.e.cveID, "https://"+tn.host+"/"))
	v.scan(t, tn, "nessus", networkCVE(v.e.cveID, 8443))
	require.Equal(t, 0, v.links(t, tn), "findings on different ports were linked")

	// The same CVE on another asset of the same tenant (out of this asset's
	// reach): two assets are never linked automatically.
	v.scan(t, other, "nessus", networkCVE(v.e.cveID, 443))
	require.Equal(t, 0, v.links(t, other))
	require.Equal(t, 0, v.count(t, `SELECT count(*) FROM finding_issue_links l JOIN findings a ON a.id = l.primary_id JOIN findings b ON b.id = l.member_id
		WHERE a.asset_id <> b.asset_id AND l.rule = 'vuln_asset'`))

	// Another CVE on the same asset and port.
	v.scan(t, tn, "nessus", networkCVE("CVE-2099-1", 443))
	require.Equal(t, 0, v.links(t, tn))
}

func TestVulnAssetLinks_ScannerPackageReportDoesNotConfirm(t *testing.T) {
	v := newVARig(t, true)
	tn := v.tenant(t, "va5-"+shared.NewID().String()[:8]+".example.com")
	vm := v.matchFinding(t, tn)
	// A package inventory is not an active check: it may be linked, never a confirmation.
	v.scan(t, tn, "trivy", scaCVE(v.e.cveID))
	require.Equal(t, "", v.confirmedBy(t, vm))
}

func TestVulnAssetLinks_NeverAcrossTenants(t *testing.T) {
	v := newVARig(t, true)
	a := v.tenant(t, "va6-"+shared.NewID().String()[:8]+".example.com")
	b := v.tenant(t, a.host) // the same asset name in another tenant
	vm := v.matchFinding(t, a)
	v.scan(t, b, "nuclei", nucleiCVE(v.e.cveID, "https://"+b.host+"/"))
	v.scan(t, b, "nessus", networkCVE(v.e.cveID, 443))
	// Tenant B links its own pair; tenant A's version match is untouched.
	require.Equal(t, 1, v.links(t, b))
	require.Equal(t, 0, v.links(t, a))
	require.Equal(t, "", v.confirmedBy(t, vm), "another tenant's template check confirmed this tenant's version match")
	require.Equal(t, 0, v.count(t, `SELECT count(*) FROM finding_issue_links l JOIN findings f ON f.id IN (l.primary_id, l.member_id) WHERE f.tenant_id <> l.tenant_id`))
	// The backfill of one tenant reads only that tenant.
	rep, err := v.repo.BackfillLinks(context.Background(), a.tenant, true, 10)
	require.NoError(t, err)
	require.Equal(t, 0, rep.Linked)
}

func TestVulnAssetLinks_BackfillMatchesIngest(t *testing.T) {
	v := newVARig(t, false)
	tn := v.tenant(t, "va7-"+shared.NewID().String()[:8]+".example.com")
	vm := v.matchFinding(t, tn)
	v.scan(t, tn, "nuclei", nucleiCVE(v.e.cveID, "https://"+tn.host+"/"))
	require.Equal(t, 0, v.links(t, tn), "links without the store")
	nu := v.idOfTool(t, tn, "nuclei")

	ctx := context.Background()
	dry, err := v.repo.BackfillLinks(ctx, tn.tenant, false, 1)
	require.NoError(t, err)
	require.Equal(t, 1, dry.Linked)
	require.Equal(t, 0, v.links(t, tn), "the dry run wrote links")
	require.Equal(t, "", v.confirmedBy(t, vm), "the dry run confirmed a finding")

	rep, err := v.repo.BackfillLinks(ctx, tn.tenant, true, 1)
	require.NoError(t, err)
	require.Equal(t, 1, rep.Linked)
	require.Equal(t, 1, rep.Confirmed)
	require.True(t, v.linkedPair(t, tn, vm, nu))
	require.Equal(t, "nuclei", v.confirmedBy(t, vm))

	again, err := v.repo.BackfillLinks(ctx, tn.tenant, true, 1)
	require.NoError(t, err)
	require.Equal(t, 0, again.Linked)
	require.Equal(t, 0, again.Confirmed)
}
