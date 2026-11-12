package scim

import (
	"context"
	"errors"
	"testing"

	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type groupLinksGate map[shared.ID]bool

func (g groupLinksGate) Allowed(_ context.Context, id shared.ID, f string) (bool, error) {
	if f != limits.FeatureSSOGroupLinks {
		return false, errors.New("unexpected feature " + f)
	}
	return g[id], nil
}

// research/232 D16: group to role links need sso.group_links in the plan;
// nothing is written when it is missing.
func TestGroupLinksFeatureDeniedRefusesMapping(t *testing.T) {
	f := newGroupFixture(t)
	owner := f.member(tenantdom.RoleOwner)
	f.svc.SetFeatureGate(groupLinksGate{})
	err := f.setMappings(owner, map[string]string{"engineers": "member"})
	var fd *limits.ErrFeatureDenied
	if !errors.As(err, &fd) || fd.Feature != limits.FeatureSSOGroupLinks {
		t.Fatalf("got %v, want the sso.group_links refusal", err)
	}
	if got, _ := f.repo.GetRoleMappings(context.Background(), f.tenant); len(got) != 0 {
		t.Fatalf("nothing may be stored, got %v", got)
	}
	f.svc.SetFeatureGate(groupLinksGate{f.tenant: true})
	if err := f.setMappings(owner, map[string]string{"engineers": "member"}); err != nil {
		t.Fatalf("a plan with group links must save: %v", err)
	}
}
