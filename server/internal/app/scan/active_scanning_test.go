package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/limits"
	"github.com/openctemio/openctem/server/pkg/domain/scan"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type fakeFeatures struct {
	denied map[shared.ID]bool
	err    error
	asked  []shared.ID
}

func (f *fakeFeatures) Allowed(_ context.Context, t shared.ID, feature string) (bool, error) {
	if feature != limits.FeatureActiveScanning {
		return true, nil
	}
	f.asked = append(f.asked, t)
	if f.err != nil {
		return false, f.err
	}
	return !f.denied[t], nil
}

func scanOf(t *testing.T, tenant shared.ID, scanner, intensity string) *scan.Scan {
	t.Helper()
	sc := &scan.Scan{TenantID: tenant, ScanType: scan.ScanTypeSingle, ScannerName: scanner, Targets: []string{"a.example.com"}}
	if intensity != "" {
		if err := sc.SetIntensity(scan.Intensity(intensity)); err != nil {
			t.Fatal(err)
		}
	}
	return sc
}

// SECURITY: a scan above passive is refused for an organization without
// active scanning, and only for it: another organization is unaffected at
// the same time. The tier is the server's (intensity or tool tier), so a
// passive intensity cannot carry an active tool.
func TestRequireActiveScanning(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	f := &fakeFeatures{denied: map[shared.ID]bool{a: true}}
	s := &Service{activeScan: f, logger: logger.NewNop()}
	ctx := context.Background()

	mustCode := func(err error) {
		t.Helper()
		var de *shared.DomainError
		if !errors.As(err, &de) || de.Code != CodeActiveScanningNotEntitled || !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want %s validation error, got %v", CodeActiveScanningNotEntitled, err)
		}
	}
	mustCode(s.requireActiveScanning(ctx, scanOf(t, a, "nuclei", "active")))
	mustCode(s.requireActiveScanning(ctx, scanOf(t, a, "nuclei", "intrusive")))
	// A forged "passive" intensity does not lower the tool's own tier.
	mustCode(s.requireActiveScanning(ctx, scanOf(t, a, "nuclei", "passive")))
	// Tenant B, allowed, in the same run.
	if err := s.requireActiveScanning(ctx, scanOf(t, b, "nuclei", "active")); err != nil {
		t.Fatalf("allowed organization refused: %v", err)
	}
	// Passive work of A still works.
	if err := s.requireActiveScanning(ctx, scanOf(t, a, "subfinder", "passive")); err != nil {
		t.Fatalf("passive scan refused: %v", err)
	}
	// The lookup is by the scan's own tenant.
	if f.asked[0] != a || f.asked[len(f.asked)-1] != b {
		t.Fatalf("lookups: %v", f.asked)
	}
}

// SECURITY: a lookup that fails refuses above passive (fail closed) and
// leaves passive alone; an unwired gate allows (no entitlements).
func TestRequireActiveScanning_FailClosed(t *testing.T) {
	a := shared.NewID()
	s := &Service{activeScan: &fakeFeatures{err: errors.New("db down")}, logger: logger.NewNop()}
	if err := s.requireActiveScanning(context.Background(), scanOf(t, a, "nuclei", "active")); err == nil {
		t.Fatal("active scan allowed on a failed lookup")
	}
	if err := s.requireActiveScanning(context.Background(), scanOf(t, a, "subfinder", "passive")); err != nil {
		t.Fatalf("passive scan refused on a failed lookup: %v", err)
	}
	if err := (&Service{}).requireActiveScanning(context.Background(), scanOf(t, a, "nuclei", "active")); err != nil {
		t.Fatalf("unwired gate refused: %v", err)
	}
}

// WithSharedScanLimits wires the active scanning gate from the one
// entitlement service the server passes it.
type limitsAndFeatures struct{ fakeFeatures }

func (*limitsAndFeatures) Check(context.Context, shared.ID, limits.Key, int) error { return nil }

func TestWithSharedScanLimits_WiresActiveScanning(t *testing.T) {
	s := &Service{}
	WithSharedScanLimits(&limitsAndFeatures{})(s)
	if s.activeScan == nil {
		t.Fatal("active scanning gate not wired from the entitlement service")
	}
}

// SECURITY: the capability read answers for the organization asked about
// only (another one is unaffected at the same time), returns a failed lookup
// as an error (never as allowed), and allows when no gate is wired.
func TestActiveScanningAllowed(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	f := &fakeFeatures{denied: map[shared.ID]bool{a: true}}
	s := &Service{activeScan: f, logger: logger.NewNop()}
	ctx := context.Background()
	if ok, err := s.ActiveScanningAllowed(ctx, a); err != nil || ok {
		t.Fatalf("passive-only organization: ok=%v err=%v", ok, err)
	}
	if ok, err := s.ActiveScanningAllowed(ctx, b); err != nil || !ok {
		t.Fatalf("other organization: ok=%v err=%v", ok, err)
	}
	if f.asked[0] != a || f.asked[1] != b {
		t.Fatalf("lookups: %v", f.asked)
	}
	failing := &Service{activeScan: &fakeFeatures{err: errors.New("db down")}, logger: logger.NewNop()}
	if ok, err := failing.ActiveScanningAllowed(ctx, a); err == nil || ok {
		t.Fatalf("failed lookup: ok=%v err=%v", ok, err)
	}
	if ok, err := (&Service{}).ActiveScanningAllowed(ctx, a); err != nil || !ok {
		t.Fatalf("unwired gate: ok=%v err=%v", ok, err)
	}
}
