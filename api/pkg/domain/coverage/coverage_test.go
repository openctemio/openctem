package coverage

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestPairValidate(t *testing.T) {
	ok := Pair{TenantID: shared.NewID(), AssetID: shared.NewID(), Capability: "probe.http"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid pair refused: %v", err)
	}
	for name, p := range map[string]Pair{
		"no tenant":        {AssetID: shared.NewID(), Capability: "probe.http"},
		"no asset":         {TenantID: shared.NewID(), Capability: "probe.http"},
		"bare word":        {TenantID: shared.NewID(), AssetID: shared.NewID(), Capability: "nuclei"},
		"upper case":       {TenantID: shared.NewID(), AssetID: shared.NewID(), Capability: "Probe.HTTP"},
		"injection":        {TenantID: shared.NewID(), AssetID: shared.NewID(), Capability: "dns.x'; drop"},
		"too long":         {TenantID: shared.NewID(), AssetID: shared.NewID(), Capability: "a." + strings.Repeat("b", 70)},
		"vantage too long": {TenantID: shared.NewID(), AssetID: shared.NewID(), Capability: "scan.ports", Vantage: strings.Repeat("v", 65)},
	} {
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStateIsValid(t *testing.T) {
	for _, s := range []State{StateDue, StateQueued, StateCovered, StateFailed, StateBlocked, StatePaused, StateNotApplicable} {
		if !s.IsValid() {
			t.Errorf("%s is not valid", s)
		}
	}
	if State("done").IsValid() {
		t.Error("an unknown state is valid")
	}
}

func TestClipKeepsUTF8(t *testing.T) {
	s := strings.Repeat("é", 40) // 80 bytes
	got := Clip(s, 63)
	if len(got) > 63 || !utf8.ValidString(got) {
		t.Fatalf("clip = %q (%d bytes)", got, len(got))
	}
	if Clip("short", 64) != "short" {
		t.Error("a short value changed")
	}
}
