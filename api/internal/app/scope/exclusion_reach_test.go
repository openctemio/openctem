package scope

import (
	"context"
	"errors"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeDS struct{ ds *shared.DataScope }

func (f fakeDS) Resolve(context.Context, shared.ID) (*shared.DataScope, error) { return f.ds, nil }

// Everything matches in the database when nothing is scoped: one visible
// and one total match, so the reach check itself passes.
type fakeMatches struct{}

func (fakeMatches) ExclusionMatches(_ context.Context, _ shared.ID, _ *shared.DataScope, items []BulkExclusionItem) ([]ExclusionMatch, error) {
	out := make([]ExclusionMatch, len(items))
	for i := range items {
		out[i] = ExclusionMatch{Matched: 1}
	}
	return out, nil
}

func TestCheckClosingRuleNeedsFullAccess(t *testing.T) {
	limited := &shared.DataScope{Unrestricted: false}
	full := &shared.DataScope{Unrestricted: true}
	cases := []struct {
		name    string
		ds      *shared.DataScope
		kind    scopedom.ExclusionKind
		typ     scopedom.ExclusionType
		pattern string
		perm    bool
		refused bool
	}{
		{"limited, exact host", limited, scopedom.ExclusionKindNotOurs, scopedom.ExclusionTypeSubdomain, "x.example.com", true, false},
		{"limited, exact ip", limited, scopedom.ExclusionKindRetired, scopedom.ExclusionTypeIPAddress, "203.0.113.7", true, false},
		{"limited, wildcard", limited, scopedom.ExclusionKindNotOurs, scopedom.ExclusionTypeDomain, "*.example.com", true, true},
		{"limited, cidr as ip_address", limited, scopedom.ExclusionKindRetired, scopedom.ExclusionTypeIPAddress, "203.0.113.0/28", true, true},
		{"limited, cidr type", limited, scopedom.ExclusionKindRetired, scopedom.ExclusionTypeCIDR, "203.0.113.0/28", true, true},
		{"limited, range", limited, scopedom.ExclusionKindRetired, scopedom.ExclusionTypeIPRange, "203.0.113.1-203.0.113.9", true, true},
		{"limited, wildcard url", limited, scopedom.ExclusionKindNotOurs, scopedom.ExclusionTypeURL, "https://a.example.com/*", true, true},
		{"limited, wildcard do_not_scan", limited, scopedom.ExclusionKindDoNotScan, scopedom.ExclusionTypeDomain, "*.example.com", true, false},
		{"limited, wildcard temporary", limited, scopedom.ExclusionKindNotOurs, scopedom.ExclusionTypeDomain, "*.example.com", false, false},
		{"full access, wildcard", full, scopedom.ExclusionKindNotOurs, scopedom.ExclusionTypeDomain, "*.example.com", true, false},
		{"full access, cidr", full, scopedom.ExclusionKindRetired, scopedom.ExclusionTypeCIDR, "203.0.113.0/28", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Service{dataScope: fakeDS{c.ds}, exclusionMatches: fakeMatches{}}
			err := s.checkClosingReach(context.Background(), shared.NewID(), c.kind, c.typ, c.pattern, c.perm)
			if c.refused {
				if !errors.Is(err, ErrClosingRuleNeedsFullAccess) {
					t.Fatalf("err = %v, want ErrClosingRuleNeedsFullAccess", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
