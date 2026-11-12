package exposure

import (
	"context"
	"testing"

	moduledom "github.com/openctemio/openctem/server/pkg/domain/module"
	"github.com/openctemio/openctem/server/pkg/domain/remediation"
)

type remediationOffGuard struct{ off string }

func (g remediationOffGuard) TenantDisabledModules(_ context.Context, tenantID string) map[string]bool {
	if tenantID == g.off {
		return map[string]bool{moduledom.ModuleRemediation: true}
	}
	return nil
}

// A campaign of a tenant with the remediation module off keeps its status
// even when all its tasks are done; with the module on it completes.
func TestCampaignProgress_SkipsTenantWithRemediationOff(t *testing.T) {
	f := newCampaignFixture(t)
	_ = f.c.Activate()
	f.repo.whole = remediation.CampaignSummary{Tasks: 1, DoneTasks: 1}

	f.svc.SetModuleGuard(remediationOffGuard{off: f.tid})
	if n, err := f.svc.ReconcileProgress(context.Background()); err != nil || n != 0 || f.c.Status() != remediation.CampaignStatusActive {
		t.Fatalf("a tenant with remediation off must be left alone: n=%d err=%v status=%s", n, err, f.c.Status())
	}
	f.svc.SetModuleGuard(remediationOffGuard{})
	if n, _ := f.svc.ReconcileProgress(context.Background()); n != 1 || f.c.Status() != remediation.CampaignStatusCompleted {
		t.Fatalf("with remediation on the campaign completes: n=%d status=%s", n, f.c.Status())
	}
}
