package postgres

// The address set the scan target gate cuts ranges with (RFC-088) comes from
// the tenant's own stored, active exclusions through the real repository:
// never another tenant's, never a pending one.

import (
	"context"
	"net/netip"
	"testing"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestScopeExcludedAddressSet_DB(t *testing.T) {
	db := openScopeApproversDB(t)
	ctx := context.Background()
	tenant := newApproverSeed(t, db).tenant
	other := newApproverSeed(t, db).tenant
	exclusions := NewScopeExclusionRepository(&DB{DB: db})

	add := func(owner shared.ID, typ scope.ExclusionType, pattern string, approve bool) {
		t.Helper()
		x, err := scope.NewExclusion(owner, typ, pattern, "test", nil, "")
		if err != nil {
			t.Fatal(err)
		}
		if approve {
			if err := x.Approve("approver"); err != nil {
				t.Fatal(err)
			}
		}
		if err := exclusions.Create(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	add(tenant, scope.ExclusionTypeIPAddress, "198.51.100.7", true)
	add(tenant, scope.ExclusionTypeCIDR, "2001:db8::80/121", true)
	add(tenant, scope.ExclusionTypeIPRange, "203.0.113.10-203.0.113.20", false) // pending
	add(other, scope.ExclusionTypeCIDR, "198.51.100.0/25", true)

	svc := scopeapp.NewService(nil, exclusions, nil, logger.NewNop())
	mine, err := svc.ExcludedAddressSet(ctx, tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := svc.ExcludedAddressSet(ctx, other.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		addr         string
		mine, theirs bool
	}{
		{"198.51.100.7", true, true},
		{"198.51.100.8", false, true},
		{"198.51.100.200", false, false},
		{"2001:db8::90", true, false},
		{"203.0.113.15", false, false},
	} {
		a := netip.MustParseAddr(c.addr)
		if mine.Contains(a) != c.mine || theirs.Contains(a) != c.theirs {
			t.Errorf("%s: tenant %v (want %v), other tenant %v (want %v)", c.addr, mine.Contains(a), c.mine, theirs.Contains(a), c.theirs)
		}
	}
}
