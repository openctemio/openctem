package integration

// RFC-043 P0 (interim cross-tool guard): default-branch auto-resolve decided
// on findings.tool_name (the FIRST tool that reported a finding) while
// findings.scan_id is the LAST sighting. A finding that two tools report was
// closed by whichever tool missed it, although the other still saw it.
// The guard: only the tool that last saw a finding may close it.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type crossToolRig struct {
	r   *v2Rig
	tn  v2Tenant
	svc *ingest.Service
	agt *sensor.Sensor
}

func newCrossToolRig(t *testing.T) *crossToolRig {
	t.Helper()
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("trivy", "grype")
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	return &crossToolRig{r: r, tn: tn, svc: svc, agt: agt}
}

// fullScan ingests a full default-branch scan of the tenant's repository by tool.
func (c *crossToolRig) fullScan(t *testing.T, tool string, fs ...ctis.Finding) {
	t.Helper()
	for i := range fs {
		fs[i].AssetRef = "repo"
	}
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool},
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC(), CoverageType: "full",
			Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true, RepositoryURL: "https://" + c.tn.repo}},
		Assets:   []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: c.tn.repo}},
		Findings: fs}
	out, err := c.svc.Ingest(context.Background(), c.agt, ingest.Input{Report: rep, CoverageType: ingest.CoverageTypeFull})
	if err != nil {
		t.Fatalf("ingest %s: %v", tool, err)
	}
	if len(out.Errors) > 0 {
		t.Fatalf("ingest %s errors: %v", tool, out.Errors)
	}
}

func (c *crossToolRig) status(t *testing.T, ruleID string) string {
	t.Helper()
	var st string
	if err := c.r.db.QueryRowContext(context.Background(),
		`SELECT status FROM findings WHERE tenant_id = $1 AND rule_id = $2`, c.tn.tenant.String(), ruleID).Scan(&st); err != nil {
		t.Fatalf("read %s: %v", ruleID, err)
	}
	return st
}

func lodashFinding() ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "lodash prototype pollution", Severity: ctis.SeverityHigh,
		RuleID:        "CVE-2021-23337",
		Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2021-23337", Package: "lodash", AffectedVersion: "4.17.15"}}
}

func anchorFinding() ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "anchor", Severity: ctis.SeverityLow,
		RuleID: "anchor-1", Location: &ctis.FindingLocation{Path: "a.go", StartLine: 1}}
}

// trivy reports a finding, grype reports the same one (same SCA identity, one
// row), then trivy's next full scan does not report it. grype saw it last, so
// trivy must not close it.
func TestAutoResolve_CrossToolFindingStaysOpenWhileTheLastToolSeesIt(t *testing.T) {
	c := newCrossToolRig(t)
	c.fullScan(t, "trivy", lodashFinding(), anchorFinding())
	c.fullScan(t, "grype", lodashFinding())
	c.fullScan(t, "trivy", anchorFinding())

	if got := c.status(t, "CVE-2021-23337"); got == "resolved" {
		t.Fatalf("finding last seen by grype was auto-resolved by trivy's scan (status %q)", got)
	}
}

// The tool that saw the finding last closes it when its own full scan no
// longer reports it — single-tool behaviour is unchanged.
func TestAutoResolve_LastSeeingToolStillResolves(t *testing.T) {
	c := newCrossToolRig(t)
	c.fullScan(t, "trivy", lodashFinding(), anchorFinding())
	c.fullScan(t, "trivy", anchorFinding())
	if got := c.status(t, "CVE-2021-23337"); got != "resolved" {
		t.Fatalf("single-tool: status = %q, want resolved", got)
	}

	c2 := newCrossToolRig(t)
	c2.fullScan(t, "trivy", lodashFinding(), anchorFinding())
	c2.fullScan(t, "grype", lodashFinding(), anchorFinding())
	c2.fullScan(t, "grype", anchorFinding())
	if got := c2.status(t, "CVE-2021-23337"); got != "resolved" {
		t.Fatalf("grype saw it last and stopped seeing it: status = %q, want resolved", got)
	}
}
