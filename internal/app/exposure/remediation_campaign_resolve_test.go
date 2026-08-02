package exposure

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

type fakeResolver struct {
	n         int
	called    bool
	gotFilter vulnerability.FindingFilter
	gotStatus string
}

func (f *fakeResolver) ResolveOpenByFilter(_ context.Context, _ string, filter vulnerability.FindingFilter, in CampaignResolveInput) (int, error) {
	f.called = true
	f.gotFilter = filter
	f.gotStatus = in.Status
	return f.n, nil
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
	})
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}
	_, err = s.ResolveCampaignFindings(context.Background(), tid.String(), c.ID().String(), CampaignResolveInput{})
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
	})
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}

	n, err := s.ResolveCampaignFindings(context.Background(), tid.String(), c.ID().String(), CampaignResolveInput{Status: "resolved"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 resolved, got %d", n)
	}
	if !res.called {
		t.Fatal("expected the resolver to be called")
	}
	if res.gotStatus != "resolved" {
		t.Errorf("status not passed through: %q", res.gotStatus)
	}
	// The campaign's tenant + severity filter must be converted onto the finding filter.
	if res.gotFilter.TenantID == nil || *res.gotFilter.TenantID != tid {
		t.Error("tenant not pinned on the converted filter")
	}
	if len(res.gotFilter.Severities) != 1 || res.gotFilter.Severities[0] != vulnerability.SeverityHigh {
		t.Errorf("severity filter not converted: %+v", res.gotFilter.Severities)
	}
}
