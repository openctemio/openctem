package unit

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// The outbound webhooks feature stored endpoints and signing secrets but had
// no delivery worker, so nothing was ever sent (owner decision B9). Its API,
// permissions and module toggle are removed; this keeps them from coming back
// without a sender. The route side is held by the route baselines
// (undocumented-routes.txt) and the permission side by migration 001032.
func TestOutboundWebhooks_StayRemoved(t *testing.T) {
	for _, p := range permission.AllPermissions() {
		if strings.HasPrefix(string(p), "integrations:webhooks:") {
			t.Errorf("permission %q is back; outbound webhooks have no sender", p)
		}
	}
	if _, ok := module.ModulePermissionMapping[module.ModuleWebhooks]; ok {
		t.Errorf("module %q still maps to a permission", module.ModuleWebhooks)
	}
	for _, p := range module.ModulePresets {
		for _, m := range p.EnabledModules {
			if m == module.ModuleIntegrationsWebhooks {
				t.Errorf("preset %q enables %q, which turns on nothing", p.ID, m)
			}
		}
	}
}
