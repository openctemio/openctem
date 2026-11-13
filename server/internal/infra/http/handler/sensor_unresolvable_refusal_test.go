package handler

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// resolutionByTenant is a tenant-scoped resolution state: a name is
// not_resolving only in the tenant that holds it.
type resolutionByTenant map[shared.ID]map[string]bool

func (r resolutionByTenant) RecordFailedNames(context.Context, shared.ID, []string, time.Time, string) error {
	return nil
}

func (r resolutionByTenant) NotResolving(_ context.Context, tenantID shared.ID, names []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, n := range names {
		if r[tenantID][n] {
			out[n] = true
		}
	}
	return out, nil
}

func TestParseRefusedSummary(t *testing.T) {
	entries, total, ok := scanrun.ParseRefusedSummary(`21 target(s) refused: "pop.pti.com.vn" (denied_by_policy), "Portal.pti.com.vn." (unresolvable), and 19 more`)
	if !ok || total != 21 || len(entries) != 2 || entries[0].Target != "pop.pti.com.vn" || entries[1].Target != "portal.pti.com.vn" ||
		entries[1].Reason != "unresolvable" {
		t.Fatalf("%+v %d %v", entries, total, ok)
	}
	for _, bad := range []string{
		"", "nothing", `3 target(s) refused: "a" (unresolvable)`, // count does not add up
		`2 target(s) refused: "a" (unresolvable), garbage`, `0 target(s) refused: `,
	} {
		if _, _, ok := scanrun.ParseRefusedSummary(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
}

// A task refused under the sensor's local policy whose every target does
// not resolve completes with per-target skips: it is not re-queued to this
// sensor or another. A sensor that predates the unresolvable reason says
// denied_by_policy for such a name; the platform's own resolution state of
// the command's tenant settles it.
func TestUnresolvableRefusalResult(t *testing.T) {
	sensor := shared.NewID()
	tenantA, tenantB := shared.NewID(), shared.NewID()
	cmd := runningCommandOf(t, sensor)
	cmd.TenantID = tenantA
	states := resolutionByTenant{tenantA: {"pop.pti.example": true, "portal.pti.example": true}}
	ctx := context.Background()

	const allDenied = `2 target(s) refused: "pop.pti.example" (denied_by_policy), "portal.pti.example" (denied_by_policy)`
	res, ok := unresolvableRefusalResult(ctx, cmd, tenantA.String(), sensor.String(), allDenied, states)
	if !ok {
		t.Fatal("names the platform knows do not resolve must complete as skips")
	}
	var got struct {
		Metadata struct {
			Refused []struct{ Target, Reason string } `json:"refused_targets"`
			Total   int                               `json:"refused_targets_total"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(res, &got); err != nil || got.Metadata.Total != 2 || len(got.Metadata.Refused) != 2 || got.Metadata.Refused[0].Reason != "unresolvable" {
		t.Fatalf("result %s err %v", res, err)
	}
	if !scanrun.IsSynthesizedUnresolvable(res) {
		t.Fatal("the completion is not marked synthesized")
	}

	for name, tc := range map[string]struct {
		detail string
		states resolutionRecorder
		tenant string
		mutate func(*commanddom.Command)
	}{
		"sensor says unresolvable": {`2 target(s) refused: "a.example" (unresolvable), "b.example" (unresolvable)`, nil, tenantA.String(), nil},
	} {
		c := runningCommandOf(t, sensor)
		c.TenantID = tenantA
		if tc.mutate != nil {
			tc.mutate(c)
		}
		if _, ok := unresolvableRefusalResult(ctx, c, tc.tenant, sensor.String(), tc.detail, tc.states); !ok {
			t.Errorf("%s: not converted", name)
		}
	}

	for name, tc := range map[string]struct {
		detail string
		states resolutionRecorder
		tenant shared.ID
	}{
		// Another tenant's resolution state says nothing about this one's names.
		"state of another tenant": {allDenied, resolutionByTenant{tenantB: {"pop.pti.example": true, "portal.pti.example": true}}, tenantA},
		"no state":                {allDenied, nil, tenantA},
		"one name resolves":       {allDenied, resolutionByTenant{tenantA: {"pop.pti.example": true}}, tenantA},
		"denied for a rule, not a dead name": {`2 target(s) refused: "10.0.0.1" (denied_by_policy), "pop.pti.example" (unresolvable)`,
			resolutionByTenant{tenantA: {"10.0.0.1": false}}, tenantA},
		"listed fewer than refused": {`5 target(s) refused: "pop.pti.example" (unresolvable), and 3 more`, nil, tenantA},
	} {
		c := runningCommandOf(t, sensor)
		c.TenantID = tc.tenant
		if _, ok := unresolvableRefusalResult(ctx, c, tc.tenant.String(), sensor.String(), tc.detail, tc.states); ok {
			t.Errorf("%s: converted", name)
		}
	}

	// A command of another tenant than the one the call names is never converted.
	other := runningCommandOf(t, sensor)
	other.TenantID = tenantB
	if _, ok := unresolvableRefusalResult(ctx, other, tenantA.String(), sensor.String(), allDenied, states); ok {
		t.Error("converted a command of another tenant")
	}
	// Not held by the reporting sensor.
	if _, ok := unresolvableRefusalResult(ctx, cmd, tenantA.String(), shared.NewID().String(), allDenied, states); ok {
		t.Error("converted for a sensor that does not hold the command")
	}
}
