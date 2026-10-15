package exposure

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type fakeResolver struct {
	n         int
	called    bool
	gotFilter vulnerability.FindingFilter
	gotStatus string
}

func (f *fakeResolver) ResolveOpenByFilter(_ context.Context, _ string, filter vulnerability.FindingFilter, in CampaignResolveInput) (*CampaignResolveResult, error) {
	f.called = true
	f.gotFilter = filter
	f.gotStatus = in.Status
	return &CampaignResolveResult{Updated: f.n}, nil
}

// fixClaim is a valid campaign "mark fixed" request.
func fixClaim() CampaignResolveInput {
	return CampaignResolveInput{Resolution: "patched", HasFixApplyPermission: true}
}

// Without a resolver wired, a (non-keyed) campaign's resolve is unavailable —
// ErrValidation, not a silent no-op. The campaign must exist first, since the
// service loads it to decide keyed-vs-generic before checking the resolver.
func TestResolveCampaignFindings_NoResolver(t *testing.T) {
	s := newService(newFakeCampaignRepo(), nil)
	tid := shared.NewID()
	c, err := s.CreateCampaign(context.Background(), CreateRemediationCampaignInput{
		TenantID:      tid.String(),
		Name:          "No resolver",
		FindingFilter: map[string]any{"severity": "high"},
	}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}
	_, err = s.ResolveCampaignFindings(context.Background(), tid.String(), c.ID().String(), fixClaim())
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation when resolver unwired, got %v", err)
	}
}

// Resolve loads the campaign, converts its filter, and delegates to the resolver.
func TestResolveCampaignFindings_DelegatesWithFilter(t *testing.T) {
	repo := newFakeCampaignRepo()
	s := newService(repo, nil)
	res := &fakeResolver{n: 5}
	s.SetFindingResolver(res)

	tid := shared.NewID()
	c, err := s.CreateCampaign(context.Background(), CreateRemediationCampaignInput{
		TenantID:      tid.String(),
		Name:          "Fix all high",
		FindingFilter: map[string]any{"severity": "high"},
	}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}

	out, err := s.ResolveCampaignFindings(context.Background(), tid.String(), c.ID().String(), fixClaim())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if out.Updated != 5 {
		t.Errorf("expected 5 marked fixed, got %d", out.Updated)
	}
	if !res.called {
		t.Fatal("expected the resolver to be called")
	}
	if res.gotStatus != "fix_applied" {
		t.Errorf("status = %q, want fix_applied", res.gotStatus)
	}
	// The campaign's tenant + severity filter must be converted onto the finding filter.
	if res.gotFilter.TenantID == nil || *res.gotFilter.TenantID != tid {
		t.Error("tenant not pinned on the converted filter")
	}
	if len(res.gotFilter.Severities) != 1 || res.gotFilter.Severities[0] != vulnerability.SeverityHigh {
		t.Errorf("severity filter not converted: %+v", res.gotFilter.Severities)
	}
}

// A campaign resolve never closes findings, and a fix claim needs
// findings:fix_apply and a note: all refused before the resolver runs.
func TestResolveCampaignFindings_RefusesCloseAndClaimWithoutRules(t *testing.T) {
	s := newService(newFakeCampaignRepo(), nil)
	res := &fakeResolver{n: 5}
	s.SetFindingResolver(res)
	tid := shared.NewID()
	c, err := s.CreateCampaign(context.Background(), CreateRemediationCampaignInput{
		TenantID: tid.String(), Name: "Fix all high", FindingFilter: map[string]any{"severity": "high"},
	}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}
	for name, tc := range map[string]struct {
		in   CampaignResolveInput
		want error
	}{
		"resolved":     {CampaignResolveInput{Status: "resolved", Resolution: "x", HasFixApplyPermission: true, HasVerifyPermission: true}, shared.ErrValidation},
		"no fix_apply": {CampaignResolveInput{Resolution: "x"}, shared.ErrForbidden},
		"no note":      {CampaignResolveInput{HasFixApplyPermission: true}, shared.ErrValidation},
		"blank note":   {CampaignResolveInput{Resolution: "  ", HasFixApplyPermission: true}, shared.ErrValidation},
	} {
		if _, err := s.ResolveCampaignFindings(context.Background(), tid.String(), c.ID().String(), tc.in); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	if res.called {
		t.Fatal("the resolver ran for a refused request")
	}
}
