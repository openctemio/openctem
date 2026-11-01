package sensor

import (
	"context"
	"testing"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordingForgetter struct {
	calls []shared.ID
}

func (f *recordingForgetter) ForgetRefusalsOf(_ context.Context, tenantID, _ shared.ID) (int64, error) {
	f.calls = append(f.calls, tenantID)
	return 1, nil
}

// A change of the reported local policy (state, digest or kill switch)
// offers the sensor what it refused again, in its own tenant only; an
// unchanged report and a platform sensor change nothing.
func TestLocalPolicyChanged(t *testing.T) {
	tenant := shared.NewID()
	d1 := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	d2 := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	stored := &sensordom.LocalPolicyReport{State: sensordom.LocalPolicyEnforced, Digest: d1}
	for name, tc := range map[string]struct {
		tenantID *shared.ID
		prev     *sensordom.LocalPolicyReport
		next     *sensordom.LocalPolicyReport
		want     int
	}{
		"digest changed":       {&tenant, stored, &sensordom.LocalPolicyReport{State: sensordom.LocalPolicyEnforced, Digest: d2}, 1},
		"policy removed":       {&tenant, stored, &sensordom.LocalPolicyReport{State: sensordom.LocalPolicyAbsent}, 1},
		"kill switch released": {&tenant, &sensordom.LocalPolicyReport{State: sensordom.LocalPolicyEnforced, Digest: d1, KillSwitch: true}, stored, 1},
		"first report":         {&tenant, nil, stored, 1},
		"unchanged":            {&tenant, stored, &sensordom.LocalPolicyReport{State: sensordom.LocalPolicyEnforced, Digest: d1}, 0},
		"platform sensor":      {nil, stored, &sensordom.LocalPolicyReport{State: sensordom.LocalPolicyEnforced, Digest: d2}, 0},
		"no report":            {&tenant, stored, nil, 0},
	} {
		f := &recordingForgetter{}
		s := &SensorService{refusalForgetter: f, logger: logger.NewNop()}
		s.localPolicyChanged(context.Background(), &sensordom.Sensor{ID: shared.NewID(), TenantID: tc.tenantID, LocalPolicy: tc.prev}, tc.next)
		if len(f.calls) != tc.want {
			t.Errorf("%s: %d calls, want %d", name, len(f.calls), tc.want)
		}
		for _, got := range f.calls {
			if got != tenant {
				t.Errorf("%s: forgot in tenant %s, want the sensor's own", name, got)
			}
		}
	}
}
