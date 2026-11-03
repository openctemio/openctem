package entitlement

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fixedGrants struct {
	grants map[limits.GrantKey]limits.Grant
	err    error
	seen   []shared.ID
}

func (f *fixedGrants) Grants(_ context.Context, tenantID shared.ID) (map[limits.GrantKey]limits.Grant, error) {
	f.seen = append(f.seen, tenantID)
	return f.grants, f.err
}

func grantOf(st limits.GrantStatus) map[limits.GrantKey]limits.Grant {
	return map[limits.GrantKey]limits.Grant{limits.GrantAIWorker: {Key: limits.GrantAIWorker, Status: st}}
}

func TestAddonStates(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	cases := []struct {
		name        string
		sources     []limits.GrantSource
		key         limits.GrantKey
		want        limits.GrantStatus
		unavailable bool
		code        string
	}{
		{"no source: Community, nothing granted", nil, limits.GrantAIWorker, limits.GrantNone, false, limits.CodeAddonNotLicensed},
		{"active", []limits.GrantSource{&fixedGrants{grants: grantOf(limits.GrantActive)}}, limits.GrantAIWorker, limits.GrantActive, false, ""},
		{"expiring still grants", []limits.GrantSource{&fixedGrants{grants: grantOf(limits.GrantExpiring)}}, limits.GrantAIWorker, limits.GrantExpiring, false, ""},
		{"grace still grants", []limits.GrantSource{&fixedGrants{grants: grantOf(limits.GrantGrace)}}, limits.GrantAIWorker, limits.GrantGrace, false, ""},
		{"expired", []limits.GrantSource{&fixedGrants{grants: grantOf(limits.GrantExpired)}}, limits.GrantAIWorker, limits.GrantExpired, false, limits.CodeAddonLicenseExpired},
		{"other key not granted", []limits.GrantSource{&fixedGrants{grants: grantOf(limits.GrantActive)}}, limits.GrantAssetCollector, limits.GrantNone, false, limits.CodeAddonNotLicensed},
		{"unregistered key never granted", []limits.GrantSource{&fixedGrants{grants: map[limits.GrantKey]limits.Grant{"x": {Key: "x", Status: limits.GrantActive}}}}, "x", limits.GrantNone, false, limits.CodeAddonNotLicensed},
		{"source error fails closed", []limits.GrantSource{&fixedGrants{err: errors.New("db down")}}, limits.GrantAIWorker, limits.GrantNone, true, limits.CodeAddonNotLicensed},
		{"best of two sources", []limits.GrantSource{&fixedGrants{grants: grantOf(limits.GrantExpired)}, &fixedGrants{grants: grantOf(limits.GrantActive)}}, limits.GrantAIWorker, limits.GrantActive, false, ""},
		{"one failing source, one answering", []limits.GrantSource{&fixedGrants{err: errors.New("down")}, &fixedGrants{grants: grantOf(limits.GrantGrace)}}, limits.GrantAIWorker, limits.GrantGrace, false, ""},
		{"a mislabelled grant is ignored", []limits.GrantSource{&fixedGrants{grants: map[limits.GrantKey]limits.Grant{limits.GrantAIWorker: {Key: limits.GrantAssetCollector, Status: limits.GrantActive}}}}, limits.GrantAIWorker, limits.GrantNone, false, limits.CodeAddonNotLicensed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewService(&memRepo{}, nil, nil)
			svc.SetGrantSources(tc.sources...)
			st := svc.Addon(ctx, tenant, tc.key)
			if st.Status != tc.want || st.Unavailable != tc.unavailable {
				t.Fatalf("got %s unavailable=%v, want %s unavailable=%v", st.Status, st.Unavailable, tc.want, tc.unavailable)
			}
			err := svc.RequireAddon(ctx, tenant, tc.key)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("RequireAddon: %v", err)
				}
				return
			}
			var gr *limits.ErrGrantRequired
			if !errors.As(err, &gr) || gr.Code() != tc.code || gr.Unavailable != tc.unavailable {
				t.Fatalf("RequireAddon = %v, want code %s", err, tc.code)
			}
		})
	}
}

// Grants never touch Community: with every grant expired or failing, every
// feature that is not a grant key stays allowed.
func TestGrantsNeverDenyCommunityFeatures(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	all := map[limits.GrantKey]limits.Grant{}
	for _, k := range limits.GrantKeys() {
		all[k] = limits.Grant{Key: k, Status: limits.GrantExpired}
	}
	svc := NewService(&memRepo{}, nil, nil)
	svc.SetGrantSources(&fixedGrants{grants: all}, &fixedGrants{err: errors.New("down")})
	for _, f := range limits.Features() {
		ok, err := svc.Allowed(ctx, tenant, f)
		if err != nil || !ok {
			t.Errorf("feature %q allowed=%v err=%v with every grant expired", f, ok, err)
		}
	}
}
