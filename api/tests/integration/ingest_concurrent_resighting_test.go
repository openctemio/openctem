package integration

// Concurrent re-runs of one repository (CI re-runs, matrix jobs reporting the
// same findings): every upload must succeed and every sighting must be
// counted. The batched writes locked rows in plan order, deadlocked, fell back
// to a sighting-only update that deadlocked too, and dropped sightings (a
// 20-way load test recorded 3,000 of 10,000).

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

func TestIngest_ConcurrentResightingsAreAllRecorded(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("semgrep")
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	tid := tn.tenant
	repoName := "github.com/acme/rerun-" + tn.tenant.String()[:8]
	ctx := context.Background()

	// report holds findings [from, to) of the repository, in the order given.
	report := func(from, to int, reverse bool) *ctis.Report {
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "semgrep"},
			Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC(),
				Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true, RepositoryURL: "https://" + repoName}},
			Assets: []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: repoName}}}
		for j := from; j < to; j++ {
			k := j
			if reverse {
				k = to - 1 - (j - from)
			}
			rep.Findings = append(rep.Findings, ctis.Finding{Type: ctis.FindingTypeVulnerability,
				Title: fmt.Sprintf("Injection sink %d", k), Severity: ctis.SeverityHigh, RuleID: fmt.Sprintf("rule.%d", k%9),
				AssetRef: "repo", Location: &ctis.FindingLocation{Path: fmt.Sprintf("src/f%d.go", k), StartLine: 10 + k%40}})
		}
		return rep
	}
	upload := func(rep *ctis.Report) error {
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Name: "ci-run", Status: sensor.SensorStatusActive}
		out, err := svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{
			Route: "ci", RequireAssetForFindings: true, NoCatalogWrites: true, DeferSensorStats: true}})
		if err != nil {
			return err
		}
		if len(out.Errors) > 0 {
			return fmt.Errorf("%s", strings.Join(out.Errors, "; "))
		}
		return nil
	}
	concurrently := func(n int, rep func(i int) *ctis.Report) {
		t.Helper()
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				r := rep(i)
				<-start
				errs[i] = upload(r)
			}(i)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Errorf("upload %d: %.400v", i, err)
			}
		}
	}
	occurrences := func() (rows, sum, minOcc int) {
		t.Helper()
		if err := r.db.QueryRow(`SELECT count(*), COALESCE(sum(occurrence_count), 0), COALESCE(min(occurrence_count), 0)
			FROM findings WHERE tenant_id = $1`, tid.String()).Scan(&rows, &sum, &minOcc); err != nil {
			t.Fatal(err)
		}
		return rows, sum, minOcc
	}

	const findings, runs = 200, 12
	// The repository and its findings exist (one serial first run).
	if err := upload(report(0, findings, false)); err != nil {
		t.Fatalf("first run: %v", err)
	}

	// Every re-run reports the same findings; half of them in reverse order.
	concurrently(runs, func(i int) *ctis.Report { return report(0, findings, i%2 == 1) })
	if rows, sum, minOcc := occurrences(); rows != findings || sum != findings*(1+runs) || minOcc != 1+runs {
		t.Errorf("after %d concurrent re-runs: rows=%d sum(occurrence_count)=%d min=%d, want %d, %d, %d",
			runs, rows, sum, minOcc, findings, findings*(1+runs), 1+runs)
	}

	// Overlapping new findings: every run adds the same 100 new ones and sees
	// the existing ones again.
	concurrently(runs, func(i int) *ctis.Report { return report(0, findings+100, i%2 == 1) })
	if rows, sum, _ := occurrences(); rows != findings+100 || sum != findings*(1+2*runs)+100*runs {
		t.Errorf("after overlapping new findings: rows=%d sum(occurrence_count)=%d, want %d, %d",
			rows, sum, findings+100, findings*(1+2*runs)+100*runs)
	}
}
