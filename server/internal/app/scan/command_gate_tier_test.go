package scan

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// POST /commands applies the tier ceiling of a scan trigger: a target whose
// scope entries allow less than the scanner probes at (ProbeTier) refuses
// the command, and the checked tier is returned for the claim-time re-check.
func TestGateCommandPayload_TierCeiling(t *testing.T) {
	gate := &stubGate{ceiling: map[string]scopedom.Tier{
		"passive-only.example.com": scopedom.TierPassive,
		"safe.example.com":         scopedom.TierActive,
	}}
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: gate, logger: logger.NewNop()}
	gateCmd := func(payload string) (*GatedCommand, error) {
		return svc.GateCommandPayload(context.Background(), shared.NewID(), nil, json.RawMessage(payload))
	}

	_, err := gateCmd(`{"scanner":"nuclei","targets":["safe.example.com","passive-only.example.com"]}`)
	requireRefused(t, err, "passive-only.example.com")
	if !errors.Is(err, ErrCommandTargetRefused) {
		t.Fatalf("want ErrCommandTargetRefused, got %v", err)
	}
	if rs := refusalsOf(t, err); len(rs) != 1 || rs[0].Code != scopedom.RefusalTierExceeds {
		t.Fatalf("refusals %+v", rs)
	}

	// An intrusive scanner needs a t2 entry.
	_, err = gateCmd(`{"scanner":"zap","target":"safe.example.com"}`)
	requireRefused(t, err, "safe.example.com")

	// A command naming no known scanner probes at t1.
	_, err = gateCmd(`{"target":"passive-only.example.com"}`)
	requireRefused(t, err, "passive-only.example.com")

	// Within the ceiling: accepted, with the tier it was checked at.
	for payload, want := range map[string]scopedom.Tier{
		`{"scanner":"nuclei","target":"safe.example.com"}`:            scopedom.TierActive,
		`{"scanner":"subfinder","target":"passive-only.example.com"}`: scopedom.TierPassive,
		`{"scanner_name":"nuclei","target":"safe.example.com"}`:       scopedom.TierActive,
	} {
		got, err := gateCmd(payload)
		if err != nil {
			t.Fatalf("%s: %v", payload, err)
		}
		if got.Tier != want {
			t.Fatalf("%s: tier %s, want %s", payload, got.Tier, want)
		}
	}

	// A failed tier lookup refuses (fail closed).
	gate.err = errors.New("scope store down")
	if _, err := gateCmd(`{"scanner":"nuclei","target":"safe.example.com"}`); err == nil {
		t.Fatal("a failed tier check accepted the command")
	}
}
