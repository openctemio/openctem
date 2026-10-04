package ingest

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Only a command-bound report stamps tenant_scanned, and only on the assets
// it may change: never a trusted server-side ingest (CT promotion, uploads)
// or an unsolicited report.
func TestScanStampTargets(t *testing.T) {
	allowed, other := shared.NewID(), shared.NewID()
	assetMap := map[string]shared.ID{"a": allowed, "b": other, "c": allowed, "z": {}}

	cmd := newAlterScope(Binding{Kind: BindingCommand, Targets: []string{"x"}})
	cmd.allow(allowed)
	got := scanStampTargets(Binding{Kind: BindingCommand}, cmd, assetMap)
	if len(got) != 1 || got[0] != allowed {
		t.Fatalf("command-bound = %v, want only the allowed asset once", got)
	}

	trusted := newAlterScope(TrustedBinding())
	trusted.allow(allowed)
	if got := scanStampTargets(TrustedBinding(), trusted, assetMap); len(got) != 0 {
		t.Fatalf("trusted ingest stamped %v", got)
	}
	if got := scanStampTargets(Binding{}, newAlterScope(Binding{}), assetMap); len(got) != 0 {
		t.Fatalf("unsolicited report stamped %v", got)
	}
}
