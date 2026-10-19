package repomerge

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeMerger map[string]*postgres.RepositoryMergeReport

func (f fakeMerger) MergeDuplicateRepositories(_ context.Context, t shared.ID, apply, _ bool) (*postgres.RepositoryMergeReport, error) {
	r := *f[t.String()]
	r.TenantID, r.Applied = t.String(), apply
	return &r, nil
}

type recorder struct{ logs []*audit.AuditLog }

func (r *recorder) Create(_ context.Context, l *audit.AuditLog) error {
	r.logs = append(r.logs, l)
	return nil
}

// An applied run writes one assets.merged entry for each tenant that merged
// something, in that tenant; a dry run and an untouched tenant write none.
func TestRun_AuditsAppliedTenantsOnly(t *testing.T) {
	a, b, c := shared.NewID(), shared.NewID(), shared.NewID()
	m := fakeMerger{
		a.String(): {Groups: 1, AssetsMerged: 2, Findings: 7},
		b.String(): {Groups: 3, AssetsMerged: 4},
		c.String(): {},
	}
	rec := &recorder{}
	if code := run(context.Background(), m, rec, []shared.ID{a, b, c}, true, false, true); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(rec.logs) != 2 {
		t.Fatalf("%d entries, want 2", len(rec.logs))
	}
	seen := map[string]bool{}
	for _, l := range rec.logs {
		if l.Action() != audit.ActionAssetsMerged || l.ActorUserAgent() != "repomerge" || l.TenantID() == nil {
			t.Errorf("entry = %s %q %v", l.Action(), l.ActorUserAgent(), l.TenantID())
		}
		seen[l.TenantID().String()] = true
	}
	if !seen[a.String()] || !seen[b.String()] || seen[c.String()] {
		t.Errorf("tenants audited = %v", seen)
	}
	if rec.logs[0].Metadata()["run_id"] != rec.logs[1].Metadata()["run_id"] {
		t.Error("one run must share one run id")
	}

	rec = &recorder{}
	run(context.Background(), m, rec, []shared.ID{a, b}, false, false, true)
	if len(rec.logs) != 0 {
		t.Errorf("a dry run wrote %d entries", len(rec.logs))
	}
}
