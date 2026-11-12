package scan

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeOneOffArchiver struct {
	scan.Repository
	olderThan time.Duration
	out       []scan.ArchivedScan
}

func (f *fakeOneOffArchiver) ArchiveNeverRunOneOffs(_ context.Context, olderThan time.Duration, _ int) ([]scan.ArchivedScan, error) {
	f.olderThan = olderThan
	return f.out, nil
}

type archiveAuditRec struct{ entries []AuditContext }

func (r *archiveAuditRec) LogEvent(_ context.Context, actx AuditContext, e AuditEvent) error {
	if e.Action == audit.ActionScanConfigDisabled && e.Metadata["archived"] == true {
		r.entries = append(r.entries, actx)
	}
	return nil
}

// Each archived one-off scan is audited in its own tenant (the job runs
// across tenants), and the default threshold applies.
func TestArchiveStaleOneOffScans_AuditsEachInItsTenant(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	repo := &fakeOneOffArchiver{out: []scan.ArchivedScan{
		{TenantID: a, ID: shared.NewID(), Name: "Quick Scan - 1"},
		{TenantID: b, ID: shared.NewID(), Name: "Quick Scan - 2"},
	}}
	rec := &archiveAuditRec{}
	s := &Service{scanRepo: repo, auditService: rec, logger: logger.NewNop()}

	n, err := s.ArchiveStaleOneOffScans(context.Background(), 0)
	if err != nil || n != 2 {
		t.Fatalf("archived %d, err %v; want 2", n, err)
	}
	if repo.olderThan != OneOffArchiveAfter {
		t.Errorf("threshold %v, want %v", repo.olderThan, OneOffArchiveAfter)
	}
	if len(rec.entries) != 2 || rec.entries[0].TenantID != a.String() || rec.entries[1].TenantID != b.String() {
		t.Fatalf("audit entries %+v, want one per scan in its own tenant", rec.entries)
	}
}
