package scan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scope/ipset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A job carries the exclusions near its range pieces, so the sensor can cut
// its ranges around them again; the pieces themselves never hold them.
func TestJobExclusions_TouchingThePieces(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{tenant: {
		approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, "198.51.100.7"),
		approvedExclusion(t, tenant, scopedom.ExclusionTypeIPRange, "198.51.100.250-198.51.101.3"),
		approvedExclusion(t, tenant, scopedom.ExclusionTypeCIDR, "203.0.113.0/24"), // far from the job
		approvedExclusion(t, tenant, scopedom.ExclusionTypeDomain, "example.com"),  // not an address
	}}}, nil)
	ctx := context.Background()
	got, err := svc.ResolveDispatchTargets(ctx, triggerInput(tenant, "198.51.100.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	excl, err := svc.JobExclusions(ctx, tenant, got.Allowed)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"198.51.100.7/32", "198.51.100.250/31", "198.51.100.252/30"}; !reflect.DeepEqual(excl, want) {
		t.Fatalf("job exclusions = %v, want %v", excl, want)
	}
	// Each piece is outside every exclusion the job carries.
	for _, p := range got.Allowed {
		for _, x := range excl {
			if rangeOverlaps(t, p, x) {
				t.Fatalf("piece %s overlaps exclusion %s", p, x)
			}
		}
	}
}

func rangeOverlaps(t *testing.T, a, b string) bool {
	t.Helper()
	ra, ok1 := ipset.Parse(a)
	rb, ok2 := ipset.Parse(b)
	if !ok1 || !ok2 {
		t.Fatalf("unreadable %q or %q", a, b)
	}
	return !(ra.Hi.Less(rb.Lo) || rb.Hi.Less(ra.Lo))
}

// Jobs without a range carry nothing; names are not cut by the sensor.
func TestJobExclusions_NoRangeNoExclusions(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{tenant: {
		approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, "198.51.100.7"),
	}}}, nil)
	excl, err := svc.JobExclusions(context.Background(), tenant, []string{"198.51.100.8", "app.example.com", "https://198.51.100.9/"})
	if err != nil || excl != nil {
		t.Fatalf("exclusions = %v, err %v", excl, err)
	}
}

// Another tenant's exclusions never travel with a job.
func TestJobExclusions_CrossTenant(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{
		tenantB: {approvedExclusion(t, tenantB, scopedom.ExclusionTypeIPAddress, "198.51.100.7")},
	}}, nil)
	excl, err := svc.JobExclusions(context.Background(), tenantA, []string{"198.51.100.0/25"})
	if err != nil || excl != nil {
		t.Fatalf("tenant A carries %v (err %v); tenant B's exclusion must not", excl, err)
	}
	excl, err = svc.JobExclusions(context.Background(), tenantB, []string{"198.51.100.128/25"})
	if err != nil || !reflect.DeepEqual(excl, []string{"198.51.100.7/32"}) {
		t.Fatalf("tenant B carries %v (err %v), want its exclusion in the same /24", excl, err)
	}
}

// A lookup failure refuses the job (fail closed); too many exclusions is
// RANGE_TOO_FRAGMENTED, never a silently shortened list.
func TestJobExclusions_FailClosed(t *testing.T) {
	svc := splitGate(&tenantExclusionRepo{err: errors.New("db down")}, nil)
	if _, err := svc.JobExclusions(context.Background(), shared.NewID(), []string{"198.51.100.0/24"}); err == nil {
		t.Fatal("a failed exclusion lookup must refuse the job")
	}
	tenant := shared.NewID()
	ex := make([]*scopedom.Exclusion, 0, MaxJobExclusions+1)
	for i := 0; i <= MaxJobExclusions; i++ {
		ex = append(ex, approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress,
			fmt.Sprintf("198.51.%d.%d", (2*i+1)/256, (2*i+1)%256)))
	}
	svc = splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{tenant: ex}}, nil)
	targets := make([]string, 0, 64)
	for i := 0; i < 64; i++ {
		targets = append(targets, fmt.Sprintf("198.51.%d.0/24", i))
	}
	_, err := svc.JobExclusions(context.Background(), tenant, targets)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != CodeRangeTooFragmented {
		t.Fatalf("err = %v, want %s", err, CodeRangeTooFragmented)
	}
}
