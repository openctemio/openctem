package scan

import (
	"testing"

	"github.com/openctemio/openctem/server/internal/app/actscope"
	"github.com/openctemio/openctem/server/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
)

// A provider's shared address held until answered (research/531 D3, E2) is
// skipped with its own reason, never silently and never as "no entry".
func TestScanPlan_SharedAddressWithoutConfirm_SkippedWithReason(t *testing.T) {
	if got := RefusalCodeForState(attribution.StateProviderHeld); got != scopedom.RefusalProviderAddress {
		t.Fatalf("gate state: %q", got)
	}
	if got := RefusalCodeForActReason(actscope.ReasonProviderHeld); got != scopedom.RefusalProviderAddress {
		t.Fatalf("act-scope reason: %q", got)
	}
	if scopedom.RefusalMessages[scopedom.RefusalProviderAddress] == "" {
		t.Fatal("no message for provider_address")
	}
	out := &resolvedTargets{}
	err := countRefusals(out, []RefusedTarget{
		{Target: "192.0.2.1", Reason: ReasonOwnershipNotConfirmed, Code: scopedom.RefusalProviderAddress},
		{Target: "192.0.2.2:443", Reason: actscope.ReasonProviderHeld, Code: scopedom.RefusalProviderAddress},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.ProviderHeld != 2 || out.OutOfScope != 0 || out.Unconfirmed != 0 {
		t.Fatalf("counts: %+v", out)
	}
	groups := skipGroups(10, nil, out, nil, nil)
	if len(groups) != 1 || groups[0].Reason != SkipProviderAddress || groups[0].Count != 2 || len(groups[0].Targets) != 2 {
		t.Fatalf("skip groups: %+v", groups)
	}
}
