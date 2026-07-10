package exposure

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// fakeKeyResolver records how a keyed campaign resolves progress + findings by
// its remediation-group key, so tests can assert the keyed path is taken (and
// the generic filter path is NOT).
type fakeKeyResolver struct {
	total, resolved int64
	countCalls      int
	resolveCalls    int
	gotKey          string
	n               int
}

func (f *fakeKeyResolver) CountByKey(_ context.Context, _ shared.ID, key string) (int64, int64, error) {
	f.countCalls++
	f.gotKey = key
	return f.total, f.resolved, nil
}

func (f *fakeKeyResolver) ResolveGroupByKey(_ context.Context, _ string, key string, _ CampaignResolveInput) (int, error) {
	f.resolveCalls++
	f.gotKey = key
	return f.n, nil
}

// A campaign scoped to a remediation-group key must compute its progress from
// the side-table (CountByKey), NOT from the generic finding counter — the two
// disagree because the key filter isn't expressible as a plain FindingFilter.
func TestCreateCampaign_KeyedUsesSideTableCount(t *testing.T) {
	repo := newFakeCampaignRepo()
	genericCounter := &fakeCounter{total: 999, resolved: 999} // must NOT be consulted
	svc := newService(repo, genericCounter)
	kr := &fakeKeyResolver{total: 12, resolved: 5}
	svc.SetKeyResolver(kr)

	c, err := svc.CreateCampaign(context.Background(), CreateRemediationCampaignInput{
		TenantID:      shared.NewID().String(),
		Name:          "Upgrade openssl",
		FindingFilter: map[string]any{"remediation_key": "sol:abc123"},
	})
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if kr.countCalls == 0 {
		t.Fatal("expected the side-table CountByKey to be used for a keyed campaign")
	}
	if kr.gotKey != "sol:abc123" {
		t.Errorf("wrong key passed to CountByKey: %q", kr.gotKey)
	}
	if genericCounter.calls != 0 {
		t.Errorf("generic finding counter must NOT run for a keyed campaign (ran %d times)", genericCounter.calls)
	}
	if c.FindingCount() != 12 || c.ResolvedCount() != 5 {
		t.Errorf("keyed progress wrong: got %d/%d, want 12/5", c.ResolvedCount(), c.FindingCount())
	}
}

// A keyed campaign resolves via the key path (bounded to the group's findings),
// and must NEVER fall through to the generic filter resolver — that would map an
// unknown remediation_key to a tenant-only filter and close the whole tenant.
func TestResolveCampaignFindings_KeyedRoutesToKeyResolver(t *testing.T) {
	repo := newFakeCampaignRepo()
	svc := newService(repo, nil)
	generic := &fakeResolver{n: 500} // the tenant-wide blast radius; must stay untouched
	svc.SetFindingResolver(generic)
	kr := &fakeKeyResolver{n: 7}
	svc.SetKeyResolver(kr)

	tid := shared.NewID()
	c, err := svc.CreateCampaign(context.Background(), CreateRemediationCampaignInput{
		TenantID:      tid.String(),
		Name:          "Patch family",
		FindingFilter: map[string]any{"remediation_key": "sol:deadbeef"},
	})
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}

	n, err := svc.ResolveCampaignFindings(context.Background(), tid.String(), c.ID().String(), CampaignResolveInput{Status: "resolved"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if n != 7 {
		t.Errorf("expected 7 resolved via key path, got %d", n)
	}
	if kr.resolveCalls != 1 || kr.gotKey != "sol:deadbeef" {
		t.Errorf("keyed resolve not routed correctly: calls=%d key=%q", kr.resolveCalls, kr.gotKey)
	}
	if generic.called {
		t.Fatal("SAFETY: generic tenant-wide resolver must NOT run for a keyed campaign")
	}
}

// If a campaign is keyed but no key resolver is wired, resolve must fail closed —
// it must never silently fall through to the tenant-wide generic path.
func TestResolveCampaignFindings_KeyedButNoKeyResolver_FailsClosed(t *testing.T) {
	repo := newFakeCampaignRepo()
	svc := newService(repo, nil)
	generic := &fakeResolver{n: 500}
	svc.SetFindingResolver(generic)
	// deliberately no SetKeyResolver

	tid := shared.NewID()
	c, err := svc.CreateCampaign(context.Background(), CreateRemediationCampaignInput{
		TenantID:      tid.String(),
		Name:          "Keyed no resolver",
		FindingFilter: map[string]any{"remediation_key": "sca:pkg:npm/lodash"},
	})
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}

	_, err = svc.ResolveCampaignFindings(context.Background(), tid.String(), c.ID().String(), CampaignResolveInput{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation when keyed campaign has no key resolver, got %v", err)
	}
	if generic.called {
		t.Fatal("SAFETY: generic tenant-wide resolver must NOT run when the keyed path is unavailable")
	}
}

func TestCampaignRemediationKey(t *testing.T) {
	cases := []struct {
		raw  map[string]any
		want string
	}{
		{nil, ""},
		{map[string]any{"severity": "high"}, ""},
		{map[string]any{"remediation_key": "sol:abc"}, "sol:abc"},
		{map[string]any{"remediation_key": ""}, ""},
		{map[string]any{"remediation_key": 123}, ""}, // non-string ignored
	}
	for _, tc := range cases {
		if got := campaignRemediationKey(tc.raw); got != tc.want {
			t.Errorf("campaignRemediationKey(%v) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}
