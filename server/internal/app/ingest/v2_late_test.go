package ingest

import (
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestDecideLate(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	me, them := shared.NewID(), shared.NewID()
	held := func(tid shared.ID, holder *shared.ID, epoch int, platform bool) *command.Command {
		return &command.Command{ID: shared.NewID(), TenantID: tid, SensorID: holder, LeaseEpoch: epoch, IsPlatformJob: platform}
	}
	ep := func(n int) *int { return &n }
	for name, tc := range map[string]struct {
		cmd   *command.Command
		epoch *int
		want  lateOutcome
	}{
		"not found":               {nil, ep(1), lateUnknown},
		"other tenant":            {held(other, &me, 2, false), ep(1), lateUnknown},
		"shared job":              {held(tenant, &me, 2, true), ep(1), lateUnknown},
		"no epoch":                {held(tenant, &me, 2, false), nil, lateUnknown},
		"epoch zero":              {held(tenant, &me, 2, false), ep(0), lateUnknown},
		"future epoch":            {held(tenant, &me, 2, false), ep(3), lateUnknown},
		"claimed again":           {held(tenant, &me, 3, false), ep(2), lateSuperseded},
		"held by another sensor":  {held(tenant, &them, 2, false), ep(2), lateSuperseded},
		"taken back, not claimed": {held(tenant, nil, 2, false), ep(2), lateSuperseded},
		"still the last lease":    {held(tenant, &me, 2, false), ep(2), lateCurrent},
	} {
		if got := decideLate(tc.cmd, tenant, me, tc.epoch); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}
}
