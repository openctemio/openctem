package scan

import (
	"context"
	"errors"
	"reflect"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// constraintGate refuses the targets it lists for the job's tool.
type constraintGate struct {
	stubGate
	refuse map[string]string
	saw    *scopedom.JobShape
}

func (g *constraintGate) ConstraintRefused(_ context.Context, _ shared.ID, targets []string, _ scopedom.Tier, job scopedom.JobShape) (map[string]string, error) {
	g.saw = &job
	out := map[string]string{}
	for _, t := range targets {
		if r, ok := g.refuse[t]; ok {
			out[t] = r
		}
	}
	return out, nil
}

// The gate refuses (constrained) a target the job may not probe within its
// entries' port or path limit; the claim re-check passes the job.
func TestResolveDispatchTargets_Constrained(t *testing.T) {
	g := &constraintGate{refuse: map[string]string{"api.example.com": scopedom.ConstrainedPortsOutside}}
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: g, logger: logger.NewNop()}
	job := scopedom.JobShape{Tool: "naabu", Ports: "1-65535"}
	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
		TenantID: shared.NewID(), Targets: []string{"api.example.com", "app.example.com"}, Job: &job,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Allowed, []string{"app.example.com"}) || len(got.Refused) != 1 ||
		got.Refused[0].Code != scopedom.RefusalConstrained || g.saw == nil || g.saw.Tool != "naabu" {
		t.Fatalf("allowed %v refused %+v saw %+v", got.Allowed, got.Refused, g.saw)
	}

	// Without a job (trigger-time paths that check per step) nothing is
	// asked; a passive dispatch is never limited.
	g.saw = nil
	if got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
		TenantID: shared.NewID(), Targets: []string{"api.example.com"}, Job: &job, PassiveOnly: true,
	}); err != nil || len(got.Allowed) != 1 || g.saw != nil {
		t.Fatalf("passive: %+v %v", got, err)
	}
}

// A gate that cannot check the limits fails closed.
func TestResolveDispatchTargets_ConstrainedFailsClosed(t *testing.T) {
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: &stubGate{}, logger: logger.NewNop()}
	job := scopedom.JobShape{Tool: "httpx"}
	_, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
		TenantID: shared.NewID(), Targets: []string{"api.example.com"}, Job: &job,
	})
	if !errors.Is(err, ErrDispatchGateUnavailable) {
		t.Fatalf("err = %v, want the gate unavailable", err)
	}
}
