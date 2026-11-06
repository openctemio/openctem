package vulnmatch

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type insertingWriter struct{}

func (insertingWriter) CreateBatchWithResult(_ context.Context, fs []*vulnerability.Finding) (*vulnerability.BatchCreateResult, error) {
	res := &vulnerability.BatchCreateResult{Created: len(fs), Inserted: map[int]bool{}}
	for i := range fs {
		res.Inserted[i] = true
	}
	return res, nil
}

type recordingAlertQueue struct {
	tenant shared.ID
	vulns  []string
}

func (q *recordingAlertQueue) QueueVulns(_ context.Context, tenantID shared.ID, vulnIDs []string) error {
	q.tenant, q.vulns = tenantID, append(q.vulns, vulnIDs...)
	return nil
}

// Matched findings were stored with no notification at all; their
// vulnerabilities now go to the emerging-threat planner, which announces
// them through the alert (RFC-117).
func TestReconcile_QueuesAlertsForNewFindings(t *testing.T) {
	store := newFakeStore()
	store.matches = []softwarematch.Match{match(shared.NewID(), "CVE-2021-23017", 90)}
	svc := NewService(store, fakePolicy{tenant.VulnMatchingSettings{Enabled: true}}, insertingWriter{}, logger.NewNop())
	q := &recordingAlertQueue{}
	svc.SetAlertQueue(q)
	tid := shared.NewID()
	var st Stats
	if err := svc.ReconcileTenant(context.Background(), tid, &st); err != nil {
		t.Fatal(err)
	}
	if q.tenant != tid || len(q.vulns) != 1 || q.vulns[0] != "CVE-2021-23017" {
		t.Fatalf("queued %v for %v", q.vulns, q.tenant)
	}
	// Nothing new: nothing queued.
	q.vulns = nil
	store.matches = nil
	if err := svc.ReconcileTenant(context.Background(), tid, &st); err != nil {
		t.Fatal(err)
	}
	if len(q.vulns) != 0 {
		t.Fatalf("queued without new findings: %v", q.vulns)
	}
}
