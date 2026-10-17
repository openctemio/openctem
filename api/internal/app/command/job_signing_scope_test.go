package command

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// capturingSigner records the statement it is asked to sign.
type capturingSigner struct{ got *jobsign.Statement }

func (c capturingSigner) SignJob(_ context.Context, st jobsign.Statement) (json.RawMessage, error) {
	*c.got = st
	return json.RawMessage(`{}`), nil
}

// A job queued for shared sensors is signed for a shared sensor
// (sensor_scope "instance"), so the signer applies the shared-job rules and
// an organization's sensor refuses it; an organization's job carries no
// scope.
func TestSignJob_SharedJobsCarryTheInstanceScope(t *testing.T) {
	for _, platform := range []bool{false, true} {
		var got jobsign.Statement
		s := &Service{jobs: capturingSigner{got: &got}, logger: logger.NewNop(), now: time.Now}
		c, err := commanddom.NewCommand(shared.NewID(), commanddom.CommandTypeScan, commanddom.CommandPriorityNormal,
			json.RawMessage(`{"scanner":"nuclei","targets":["app.example.com"]}`))
		if err != nil {
			t.Fatal(err)
		}
		if platform {
			if err := c.SetPlatformJob(50); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.signJob(context.Background(), shared.NewID().String(), c, false); err != nil {
			t.Fatal(err)
		}
		want := ""
		if platform {
			want = jobsign.SensorScopeInstance
		}
		if got.SensorScope != want || got.TenantID != c.TenantID.String() {
			t.Errorf("platform=%v: scope %q tenant %s, want scope %q and the command's tenant", platform, got.SensorScope, got.TenantID, want)
		}
	}
}
