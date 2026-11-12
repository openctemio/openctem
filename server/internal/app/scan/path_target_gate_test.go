package scan

import (
	"context"
	"reflect"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The claim-time re-check takes every repository out of a job the catalog
// places on a network stage, by tool or by capability; a code job keeps
// them, and a job the catalog cannot place was decided when it was built.
func TestResolveDispatchTargets_PathTargetsOnlyForCodeJobs(t *testing.T) {
	targets := []string{"github.com/acme/app", "git@gitlab.com:acme/app", "app.example.com"}
	run := func(job scopedom.JobShape) *DispatchTargets {
		t.Helper()
		svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: &constraintGate{}, logger: logger.NewNop()}
		got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
			TenantID: shared.NewID(), Targets: targets, Job: &job,
			AllowNonNetworkTargets: true, SkipZoneRouting: true, Path: "claim_recheck",
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, job := range []scopedom.JobShape{
		{Tool: "httpx"}, {Tool: "nuclei"}, {Tool: "naabu"}, {Tool: "subfinder"},
		{Capability: "probe.http@1"}, {Tool: "tenant-tool", Capability: "vuln.templates@1"},
	} {
		got := run(job)
		if !reflect.DeepEqual(got.Allowed, []string{"app.example.com"}) || len(got.Refused) != 2 {
			t.Errorf("%+v: allowed %v refused %+v", job, got.Allowed, got.Refused)
			continue
		}
		for _, r := range got.Refused {
			if r.Reason != stage.ReasonPathTarget || r.Code != scopedom.RefusalInvalidTarget {
				t.Errorf("%+v: refusal %+v", job, r)
			}
		}
	}
	for _, job := range []scopedom.JobShape{{Tool: "semgrep"}, {Capability: "secrets.code@1"}, {Tool: "tenant-tool"}} {
		if got := run(job); len(got.Allowed) != 3 || len(got.Refused) != 0 {
			t.Errorf("%+v: allowed %v refused %+v, want every target kept", job, got.Allowed, got.Refused)
		}
	}
}
