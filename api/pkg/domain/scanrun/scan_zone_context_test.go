package scanrun

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestScanZoneFromContext(t *testing.T) {
	id := shared.NewID()
	if got := ScanZoneFromContext(map[string]any{RunContextKeyScanZoneID: id.String()}); got == nil || *got != id {
		t.Errorf("ScanZoneFromContext = %v, want %s", got, id)
	}
	for _, ctx := range []map[string]any{nil, {}, {RunContextKeyScanZoneID: ""}, {RunContextKeyScanZoneID: "x"}, {RunContextKeyScanZoneID: 7}} {
		if got := ScanZoneFromContext(ctx); got != nil {
			t.Errorf("ScanZoneFromContext(%v) = %v, want nil", ctx, got)
		}
	}
}
