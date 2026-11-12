package coverage

import (
	"strings"
	"testing"
	"time"
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

func TestNotClaimedRetry(t *testing.T) {
	for streak, want := range map[int]time.Duration{
		0: 2 * time.Hour, 3: 2 * time.Hour, 4: 4 * time.Hour, 5: 8 * time.Hour,
		7: 32 * time.Hour, 8: 48 * time.Hour, 50: 48 * time.Hour,
	} {
		if got := NotClaimedRetry(streak); got != want {
			t.Errorf("streak %d: %v, want %v", streak, got, want)
		}
	}
	if !IsReadinessReason(ReadyNotClaimed) || ReadinessText(ReadyNotClaimed) == ReadyNotClaimed {
		t.Fatal("not_claimed is a readiness reason with a text")
	}
	if a := ActionFor(AlertCondition{Kind: AlertReadiness, Reason: ReadyNotClaimed}); a.URL != "/sensors" {
		t.Fatalf("action %+v", a)
	}
	if (Hold{Streak: NotClaimedStreak - 1}).Active() || !(Hold{Streak: NotClaimedStreak}).Active() {
		t.Fatal("a hold is active from NotClaimedStreak")
	}
}
