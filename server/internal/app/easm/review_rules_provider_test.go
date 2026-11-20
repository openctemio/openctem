package easm

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/scope"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// previewOnlyScope answers PreviewTarget with a fixed refusal, so a test
// can tell whether the rule reached the scope service.
type previewOnlyScope struct {
	RuleScope
	asked int
}

var errPreviewReached = errors.New("preview reached the scope service")

func (p *previewOnlyScope) PreviewTarget(context.Context, scope.CreateTargetInput) (*scope.TargetPreview, error) {
	p.asked++
	return nil, errPreviewReached
}

type noCoverage struct{ ReviewCoverage }

// A review rule never adds an entry on a provider's shared addresses
// (research/531 D14): an address or range wholly inside a published shared
// range is refused before the scope service is asked; anything else goes on
// to the usual preview.
func TestRulePreview_ProviderSharedRangeRefused(t *testing.T) {
	var p netip.Prefix
	for _, q := range edgeaddr.Default().SharedFrontEndPrefixes() {
		if q.Addr().Is4() && q.Bits() <= 28 {
			p = q
			break
		}
	}
	if !p.IsValid() {
		t.Fatal("no shared IPv4 prefix in the dataset")
	}
	inner := netip.PrefixFrom(p.Addr(), p.Bits()+1).Masked()
	f := newGateFixture(t)
	sc := &previewOnlyScope{}
	svc := NewRuleService(&ReviewService{}, &ScopeJoin{}, sc, f, noCoverage{}, scopedom.Guardrails{})

	for _, tc := range []struct {
		typ, pattern string
	}{
		{"cidr", inner.String()},
		{"ip_address", p.Addr().Next().String()},
	} {
		out, err := svc.Preview(context.Background(), shared.NewID(), RuleActionInput{Action: RuleAcceptRule, TargetType: tc.typ,
			Pattern: tc.pattern, Reason: "test"})
		if err != nil {
			t.Fatal(err)
		}
		if out.Allowed || out.Refusal == nil || out.Refusal.Code != RuleRefusalProviderShared {
			t.Fatalf("%s %s: %+v", tc.typ, tc.pattern, out)
		}
	}
	if sc.asked != 0 {
		t.Fatal("a shared range reached the scope service")
	}
	// A documentation range is not a provider's: the usual preview runs.
	out, err := svc.Preview(context.Background(), shared.NewID(), RuleActionInput{Action: RuleAcceptRule, TargetType: "cidr",
		Pattern: "198.51.100.0/24", Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if sc.asked != 1 || out.Refusal == nil || out.Refusal.Code == RuleRefusalProviderShared {
		t.Fatalf("documentation range: asked %d, %+v", sc.asked, out)
	}
}
