package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// noLimits allows every shared-sensor scan.
type noLimits struct{}

func (noLimits) Check(context.Context, shared.ID, limits.Key, int) error { return nil }

// fixedLimits answers one error for every check, recording the key asked.
type fixedLimits struct {
	err  error
	keys *[]limits.Key
}

func (l fixedLimits) Check(_ context.Context, _ shared.ID, key limits.Key, _ int) error {
	if l.keys != nil {
		*l.keys = append(*l.keys, key)
	}
	return l.err
}

// The daily limit of shared-sensor scans: an explicit 'platform' scan over
// the limit is refused with the limit; 'auto' stays on the organization's
// own sensors; an unreadable limit or no limit check at all refuses (fail
// closed). Within the limit nothing changes.
func TestSharedScanDailyLimit(t *testing.T) {
	ctx := context.Background()
	public := []string{"app.example.com"}
	over := &limits.ErrLimitReached{Key: limits.PlatformScansPerDay, Limit: 10, Used: 10}
	unreadable := &limits.ErrLimitReached{Key: limits.PlatformScansPerDay, Unavailable: true}
	for _, tc := range []struct {
		name    string
		limits  SharedScanLimits
		pref    scan.SensorPreference
		want    bool
		wantErr string
	}{
		{"explicit, within the limit", noLimits{}, scan.SensorPreferencePlatform, true, ""},
		{"explicit, over the limit", fixedLimits{err: over}, scan.SensorPreferencePlatform, false, "its 10 scans"},
		{"explicit, limit unreadable", fixedLimits{err: unreadable}, scan.SensorPreferencePlatform, false, "could not be checked"},
		{"explicit, no limit check wired", nil, scan.SensorPreferencePlatform, false, "cannot be checked"},
		{"auto, within the limit", noLimits{}, scan.SensorPreferenceAuto, true, ""},
		{"auto, over the limit", fixedLimits{err: over}, scan.SensorPreferenceAuto, false, ""},
		{"auto, limit unreadable", fixedLimits{err: errors.New("db down")}, scan.SensorPreferenceAuto, false, ""},
	} {
		svc := &Service{sensorSelector: stubSelector{false, true}, logger: logger.NewNop(),
			zoneResolver: publicResolver{}, sharedLimits: tc.limits}
		sc := testScan("nuclei")
		sc.SensorPreference = tc.pref
		got, err := svc.shouldUsePlatformSensor(ctx, sc, public)
		if got != tc.want {
			t.Errorf("%s: platform = %v, want %v (err %v)", tc.name, got, tc.want, err)
		}
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: error %v, want one containing %q", tc.name, err, tc.wantErr)
		}
	}

	// The check asks for the daily key, never a limits.
	var keys []limits.Key
	svc := &Service{sensorSelector: stubSelector{false, true}, logger: logger.NewNop(),
		zoneResolver: publicResolver{}, sharedLimits: fixedLimits{keys: &keys}}
	sc := testScan("nuclei")
	sc.SensorPreference = scan.SensorPreferencePlatform
	if _, err := svc.shouldUsePlatformSensor(ctx, sc, public); err != nil || len(keys) != 1 || keys[0] != limits.PlatformScansPerDay {
		t.Fatalf("checked keys %v (err %v), want [platform_scans_per_day]", keys, err)
	}

	// A workflow scan over the limit stays on the organization's sensors.
	wf := &Service{sensorSelector: stubSelector{false, true}, logger: logger.NewNop(),
		zoneResolver: publicResolver{}, sharedLimits: fixedLimits{err: over}}
	wsc := testScan("nuclei")
	wsc.SensorPreference = scan.SensorPreferenceAuto
	r, err := wf.decideWorkflowRouting(ctx, wsc, public)
	if err != nil || r.Routing != sensorRoutingTenant {
		t.Fatalf("workflow over the limit: routing %v err %v, want tenant", r.Routing, err)
	}
}
