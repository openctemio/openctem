package dashboard

import (
	"testing"

	domain "github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func homeDash(kind domain.Kind, def, orgDef bool) *domain.Dashboard {
	return domain.Reconstruct(domain.Stored{ID: shared.NewID(), Kind: kind, Name: "d", IsDefault: def, IsOrgDefault: orgDef})
}

func orgOf(ds ...*domain.Dashboard) []OrgDashboard {
	out := make([]OrgDashboard, 0, len(ds))
	for _, d := range ds {
		out = append(out, OrgDashboard{Dashboard: d})
	}
	return out
}

func refOf(d *domain.Dashboard) *Ref { return &Ref{Kind: d.Kind(), ID: d.ID().String()} }

// The landing rules are the ones the web used to apply (web landing.ts):
// the remembered choice while it exists, the person's default, the
// organization default or first organization dashboard, the first own one.
func TestPickLanding(t *testing.T) {
	p1, p2 := homeDash(domain.KindPersonal, false, false), homeDash(domain.KindPersonal, true, false)
	o1, o2 := homeDash(domain.KindOrganization, false, false), homeDash(domain.KindOrganization, false, true)
	foreign := &Ref{Kind: domain.KindPersonal, ID: shared.NewID().String()}
	// A personal id offered as an organization choice (and the reverse) is not in that list.
	crossed := &Ref{Kind: domain.KindOrganization, ID: p1.ID().String()}

	cases := []struct {
		name     string
		personal []*domain.Dashboard
		org      []OrgDashboard
		saved    *Ref
		want     *Ref
	}{
		{"nothing at all", nil, nil, nil, nil},
		{"saved personal wins", []*domain.Dashboard{p1, p2}, orgOf(o1, o2), refOf(p1), refOf(p1)},
		{"saved organization wins", []*domain.Dashboard{p1, p2}, orgOf(o1, o2), refOf(o1), refOf(o1)},
		{"foreign choice is ignored", []*domain.Dashboard{p1, p2}, orgOf(o1, o2), foreign, refOf(p2)},
		{"choice of the wrong kind is ignored", []*domain.Dashboard{p1}, orgOf(o1), crossed, refOf(o1)},
		{"personal default beats organization default", []*domain.Dashboard{p1, p2}, orgOf(o1, o2), nil, refOf(p2)},
		{"organization default when no personal default", []*domain.Dashboard{p1}, orgOf(o1, o2), nil, refOf(o2)},
		{"first organization dashboard when no default", []*domain.Dashboard{p1}, orgOf(o1), nil, refOf(o1)},
		{"first personal dashboard last", []*domain.Dashboard{p1}, nil, nil, refOf(p1)},
		{"organization choice without organization list", []*domain.Dashboard{p1}, nil, refOf(o1), refOf(p1)},
	}
	for _, c := range cases {
		got := PickLanding(c.personal, c.org, c.saved)
		switch {
		case got == nil && c.want == nil:
		case got == nil || c.want == nil || *got != *c.want:
			t.Errorf("%s: landing %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestParseRef(t *testing.T) {
	id := shared.NewID().String()
	if r := ParseRef("personal:" + id); r == nil || r.Kind != domain.KindPersonal || r.ID != id {
		t.Errorf("personal ref = %+v", r)
	}
	if r := ParseRef("organization:" + id); r == nil || r.Kind != domain.KindOrganization || r.ID != id {
		t.Errorf("organization ref = %+v", r)
	}
	for _, bad := range []string{"", "personal", "personal:", "team:" + id, ":" + id, id} {
		if r := ParseRef(bad); r != nil {
			t.Errorf("ParseRef(%q) = %+v, want nil", bad, r)
		}
	}
}
