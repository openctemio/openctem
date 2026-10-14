package integration

// A finding an approved suppression rule decides at ingest (false positive,
// accepted) is born decided: it raises no created event (notifications,
// tickets), gets no SLA deadline, and the undecided finding of the same
// report still does. Rules are the tenant's own.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type slaRecorder struct {
	mu    sync.Mutex
	rules []string
}

func (s *slaRecorder) ApplyBatch(_ context.Context, _ shared.ID, fs []*vulnerability.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range fs {
		s.rules = append(s.rules, f.RuleID())
	}
	return nil
}

type noopClassifier struct{}

func (noopClassifier) EnrichAndClassifyBatch(context.Context, shared.ID, []*vulnerability.Finding, map[shared.ID]*asset.Asset) error {
	return nil
}

func TestIngest_SuppressedAtIngestIsQuiet(t *testing.T) {
	var created []string
	sla := &slaRecorder{}
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		svc.SetSuppressionChecker(suppression.NewService(postgres.NewSuppressionRepository(db), logger.NewNop()))
		svc.SetPriorityClassifier(noopClassifier{})
		svc.SetSLAApplier(sla)
		svc.SetFindingCreatedCallback(func(_ context.Context, _ shared.ID, fs []*vulnerability.Finding) {
			for _, f := range fs {
				created = append(created, f.RuleID())
			}
		})
	})
	ctx := context.Background()
	tn, other := r.newTenant(), r.newTenant()
	// An approved false-positive rule for py.md5 in this tenant, and one for
	// py.cmdi in the other tenant (must not apply here).
	for _, x := range []struct {
		tenant shared.ID
		rule   string
	}{{tn.tenant, "py.md5"}, {other.tenant, "py.cmdi"}} {
		if _, err := r.db.ExecContext(ctx, `INSERT INTO suppression_rules (id, tenant_id, name, rule_id, suppression_type, status, approved_at)
			VALUES ($1, $2, 'fp', $3, 'false_positive', 'approved', NOW())`, shared.NewID().String(), x.tenant.String(), x.rule); err != nil {
			t.Fatal(err)
		}
	}
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	mk := func(rule string, line int) ctis.Finding {
		return ctis.Finding{AssetRef: "a", Type: ctis.FindingTypeVulnerability, Title: rule, RuleID: rule, Severity: "high",
			Location: &ctis.FindingLocation{Path: "app/run.py", StartLine: line, Snippet: rule + "()"}}
	}
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "semgrep"},
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
		Assets:   []ctis.Asset{{ID: "a", Type: ctis.AssetTypeRepository, Value: "github.com/acme/quiet-" + tn.tenant.String()[:8]}},
		Findings: []ctis.Finding{mk("py.md5", 3), mk("py.cmdi", 9)}}
	if out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep}); err != nil || len(out.Errors) > 0 {
		t.Fatalf("ingest: %v %+v", err, out)
	}

	status := func(rule string) string {
		var s string
		if err := r.db.QueryRowContext(ctx, `SELECT status FROM findings WHERE tenant_id = $1 AND rule_id = $2`, tn.tenant.String(), rule).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if status("py.md5") != "false_positive" || status("py.cmdi") == "false_positive" {
		t.Fatalf("statuses: md5 %s cmdi %s (another tenant's rule applied?)", status("py.md5"), status("py.cmdi"))
	}
	if len(created) != 1 || created[0] != "py.cmdi" {
		t.Fatalf("created events for %v, want only py.cmdi", created)
	}
	if len(sla.rules) != 1 || sla.rules[0] != "py.cmdi" {
		t.Fatalf("SLA applied to %v, want only py.cmdi", sla.rules)
	}
}
