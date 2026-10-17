package exposure

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
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

// activate moves a test campaign to active: only an active or validating
// campaign marks findings fixed.
func activate(t *testing.T, s *RemediationCampaignService, tid shared.ID, c *remediation.Campaign) {
	t.Helper()
	if _, err := s.UpdateCampaignStatus(context.Background(), tid.String(), c.ID().String(), "active", auditapp.AuditContext{}); err != nil {
		t.Fatalf("activate: %v", err)
	}
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
		FindingFilter: map[string]any{"severity": "high", "tool_name": "trivy"},
	}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}
	activate(t, s, tid, c)
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
		FindingFilter: map[string]any{"severity": "high", "tool_name": "trivy"},
	}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}

	activate(t, s, tid, c)
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
		TenantID: tid.String(), Name: "Fix all high", FindingFilter: map[string]any{"severity": "high", "tool_name": "trivy"},
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

// Only an active or validating campaign marks findings fixed; a draft,
// paused, completed or canceled one is refused before the resolver runs.
func TestResolveCampaignFindings_OnlyActiveOrValidating(t *testing.T) {
	s := newService(newFakeCampaignRepo(), nil)
	res := &fakeResolver{n: 1}
	s.SetFindingResolver(res)
	tid := shared.NewID()
	c, err := s.CreateCampaign(context.Background(), CreateRemediationCampaignInput{
		TenantID: tid.String(), Name: "Draft", FindingFilter: map[string]any{"severity": "high", "tool_name": "trivy"},
	}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}
	if _, err := s.ResolveCampaignFindings(context.Background(), tid.String(), c.ID().String(), fixClaim()); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("draft resolve: err = %v, want a validation error", err)
	}
	activate(t, s, tid, c)
	if _, err := s.UpdateCampaignStatus(context.Background(), tid.String(), c.ID().String(), "paused", auditapp.AuditContext{}); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if _, err := s.ResolveCampaignFindings(context.Background(), tid.String(), c.ID().String(), fixClaim()); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("paused resolve: err = %v, want a validation error", err)
	}
	if res.called {
		t.Fatal("the resolver ran for a campaign that is not being worked on")
	}
}
