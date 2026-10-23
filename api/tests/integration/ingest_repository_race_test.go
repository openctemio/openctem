package integration

// Concurrent uploads that create the same new repository (CI matrix jobs,
// parallel pipelines of one repository): the uploads that lose the insert
// race on assets (tenant_id, name) must attach their findings to the stored
// asset. They used to key asset_repositories by their own unsaved asset id,
// fail its foreign key and drop the whole upload.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestIngest_ConcurrentUploadsCreateOneRepository(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("semgrep")
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	tid := tn.tenant
	repoName := "github.com/acme/race-" + tn.tenant.String()[:8]

	const uploads, perUpload = 20, 25
	report := func(i int) *ctis.Report {
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "semgrep"},
			Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC(),
				Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true, RepositoryURL: "https://" + repoName}},
			Assets: []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: repoName}}}
		for j := 0; j < perUpload; j++ {
			k := i*perUpload + j
			rep.Findings = append(rep.Findings, ctis.Finding{Type: ctis.FindingTypeVulnerability,
				Title: fmt.Sprintf("Injection sink %d", k), Severity: ctis.SeverityHigh, RuleID: fmt.Sprintf("rule.%d", k%7),
				AssetRef: "repo", Location: &ctis.FindingLocation{Path: fmt.Sprintf("src/f%d.go", k), StartLine: 10}})
		}
		return rep
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]string, uploads)
	for i := 0; i < uploads; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Name: "ci-run", Status: sensor.SensorStatusActive}
			<-start
			out, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: report(i), Options: ingest.Options{
				Route: "ci", RequireAssetForFindings: true, NoCatalogWrites: true, DeferSensorStats: true}})
			switch {
			case err != nil:
				errs[i] = err.Error()
			case len(out.Errors) > 0:
				errs[i] = strings.Join(out.Errors, "; ")
			case out.FindingsCreated != perUpload:
				errs[i] = fmt.Sprintf("created %d findings, want %d", out.FindingsCreated, perUpload)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	for i, e := range errs {
		if e != "" {
			t.Errorf("upload %d: %.300s", i, e)
		}
	}

	var assets, extensions, attached, orphans int
	if err := r.db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = $2`, tid.String(), repoName).Scan(&assets); err != nil {
		t.Fatal(err)
	}
	if err := r.db.QueryRow(`SELECT count(*) FROM asset_repositories ar JOIN assets a ON a.id = ar.asset_id
		WHERE a.tenant_id = $1 AND a.name = $2`, tid.String(), repoName).Scan(&extensions); err != nil {
		t.Fatal(err)
	}
	if err := r.db.QueryRow(`SELECT count(*) FILTER (WHERE a.name = $2), count(*) FILTER (WHERE a.id IS NULL)
		FROM findings f LEFT JOIN assets a ON a.id = f.asset_id WHERE f.tenant_id = $1`, tid.String(), repoName).Scan(&attached, &orphans); err != nil {
		t.Fatal(err)
	}
	if assets != 1 || extensions != 1 {
		t.Errorf("repository rows: assets=%d asset_repositories=%d, want 1 and 1", assets, extensions)
	}
	if attached != uploads*perUpload || orphans != 0 {
		t.Errorf("findings on the repository: %d (orphans %d), want %d", attached, orphans, uploads*perUpload)
	}
}
