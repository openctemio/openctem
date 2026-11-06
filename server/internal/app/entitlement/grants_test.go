package entitlement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/limits"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

const testKey limits.GrantKey = "test_extra"

type fixedProvider struct {
	grant     limits.Grant
	err       error
	notices   []limits.Notice
	noticeErr error
	seen      []shared.ID
}

func (f *fixedProvider) Grant(_ context.Context, tenantID shared.ID, _ limits.GrantKey) (limits.Grant, error) {
	f.seen = append(f.seen, tenantID)
	return f.grant, f.err
}

func (f *fixedProvider) Notices(context.Context) ([]limits.Notice, error) {
	return f.notices, f.noticeErr
}

func provider(st limits.GrantStatus) *fixedProvider {
	return &fixedProvider{grant: limits.Grant{Key: testKey, Status: st}}
}

func TestAddonStates(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	cases := []struct {
		name        string
		p           limits.GrantProvider
		key         limits.GrantKey
		want        limits.GrantStatus
		unavailable bool
		code        string
	}{
		{"no provider: Community, nothing granted", nil, testKey, limits.GrantNone, false, limits.CodeAddonNotLicensed},
		{"active", provider(limits.GrantActive), testKey, limits.GrantActive, false, ""},
		{"expiring still grants", provider(limits.GrantExpiring), testKey, limits.GrantExpiring, false, ""},
		{"grace still grants", provider(limits.GrantGrace), testKey, limits.GrantGrace, false, ""},
		{"expired", provider(limits.GrantExpired), testKey, limits.GrantExpired, false, limits.CodeAddonLicenseExpired},
		{"none", provider(limits.GrantNone), testKey, limits.GrantNone, false, limits.CodeAddonNotLicensed},
		{"unknown status is none", provider("bogus"), testKey, limits.GrantNone, false, limits.CodeAddonNotLicensed},
		{"answer for another key is ignored", provider(limits.GrantActive), "other_extra", limits.GrantNone, false, limits.CodeAddonNotLicensed},
		{"empty key never granted", provider(limits.GrantActive), "", limits.GrantNone, false, limits.CodeAddonNotLicensed},
		{"provider error fails closed", &fixedProvider{err: errors.New("db down"), grant: limits.Grant{Key: testKey, Status: limits.GrantActive}}, testKey, limits.GrantNone, true, limits.CodeAddonNotLicensed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewService(&memRepo{}, nil, nil)
			svc.SetGrantProvider(tc.p)
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
			if !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("RequireAddon error is not ErrForbidden: %v", err)
			}
		})
	}
}

// The provider is asked for the caller's organization, never another.
func TestAddonAsksForTheCallersOrganization(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	p := provider(limits.GrantActive)
	svc := NewService(&memRepo{}, nil, nil)
	svc.SetGrantProvider(p)
	svc.Addon(context.Background(), a, testKey)
	svc.Addon(context.Background(), b, testKey)
	if len(p.seen) != 2 || p.seen[0] != a || p.seen[1] != b {
		t.Fatalf("provider asked for %v, want [%s %s]", p.seen, a, b)
	}
}

func TestNotices(t *testing.T) {
	ctx := context.Background()
	svc := NewService(&memRepo{}, nil, nil)
	if n := svc.Notices(ctx); n != nil {
		t.Fatalf("Community notices = %v, want none", n)
	}
	want := []limits.Notice{{Code: "LICENSE_EXPIRING", Level: limits.NoticeWarning, Until: time.Now()}}
	svc.SetGrantProvider(&fixedProvider{notices: want})
	if n := svc.Notices(ctx); len(n) != 1 || n[0].Code != "LICENSE_EXPIRING" {
		t.Fatalf("notices = %v", n)
	}
	svc.SetGrantProvider(&fixedProvider{noticeErr: errors.New("down")})
	if n := svc.Notices(ctx); n != nil {
		t.Fatalf("notices on error = %v, want none", n)
	}
}

// Grants never touch Community: with a provider that expires or fails every
// grant, every feature that is not a grant stays allowed.
func TestGrantsNeverDenyCommunityFeatures(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	for _, p := range []limits.GrantProvider{provider(limits.GrantExpired), &fixedProvider{err: errors.New("down")}} {
		svc := NewService(&memRepo{}, nil, nil)
		svc.SetGrantProvider(p)
		for _, f := range limits.Features() {
			ok, err := svc.Allowed(ctx, tenant, f)
			if err != nil || !ok {
				t.Errorf("feature %q allowed=%v err=%v with every grant off", f, ok, err)
			}
		}
	}
}
