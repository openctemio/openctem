package asset

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A client never sets a service's kind: create and import refuse the keys
// (any spelling), and a patch may only echo the stored value back.
func TestReservedProperties_ServiceKind(t *testing.T) {
	for _, k := range []string{"service_kind", "serviceKind", "service_category", "kind_source", "kindSource"} {
		err := RejectReservedProperties(map[string]any{k: "rdp"})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v, want a validation error", k, err)
		}
	}
	current := map[string]any{"service_kind": "ssh", "kind_source": "fingerprint"}
	echo := map[string]any{"service_kind": "ssh", "kind_source": "fingerprint", "product": "OpenSSH"}
	if err := stripUnchangedReservedProperties(echo, current); err != nil {
		t.Fatalf("echo refused: %v", err)
	}
	if _, ok := echo["service_kind"]; ok {
		t.Error("echoed kind not dropped from the patch")
	}
	forged := map[string]any{"kind_source": "port_guess"}
	if err := stripUnchangedReservedProperties(forged, current); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("changed source accepted: %v", err)
	}
}
