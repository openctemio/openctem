package dashboard

import (
	"context"
	"strings"

	domain "github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// Ref names one dashboard the way the dashboard home does: its kind and id.
type Ref struct {
	Kind domain.Kind `json:"kind" enums:"personal,organization"`
	ID   string      `json:"id"`
}

// ParseRef reads a remembered choice ("personal:<id>" or "organization:<id>").
// Anything else is no choice at all.
func ParseRef(raw string) *Ref {
	kind, id, ok := strings.Cut(raw, ":")
	if !ok || id == "" {
		return nil
	}
	switch domain.Kind(kind) {
	case domain.KindPersonal:
		return &Ref{Kind: domain.KindPersonal, ID: id}
	case domain.KindOrganization:
		return &Ref{Kind: domain.KindOrganization, ID: id}
	}
	return nil
}

// Home is what the dashboard home opens with: the person's own dashboards,
// the organization dashboards they may read (nil without
// dashboards:org:view or :manage), and the one to open.
type Home struct {
	Personal     []*domain.Dashboard
	Organization []OrgDashboard // nil when the caller cannot read organization dashboards
	Landing      *Ref           // nil when there is no dashboard at all
}

// Home lists both sets with the services' own rules (the personal list is
// self-scoped, the organization list applies the permission and each
// dashboard's audience) and picks the landing dashboard. A remembered choice
// that is not in either list (deleted, someone else's, outside the audience)
// is ignored without a word, so it can tell nothing about what exists.
func (s *Service) Home(ctx context.Context, c Caller, choice *Ref) (*Home, error) {
	if err := c.requireUser(); err != nil {
		return nil, err
	}
	personal, err := s.List(ctx, c.TenantID.String(), c.UserID.String())
	if err != nil {
		return nil, err
	}
	h := &Home{Personal: personal}
	if c.has(permission.DashboardsOrgView) || c.has(permission.DashboardsOrgManage) {
		org, err := s.ListOrg(ctx, c)
		if err != nil {
			return nil, err
		}
		if org == nil {
			org = []OrgDashboard{}
		}
		h.Organization = org
	}
	h.Landing = PickLanding(personal, h.Organization, choice)
	return h, nil
}

// PickLanding decides which dashboard the home opens: the one the viewer
// last chose while it still exists, else their own default, else the
// organization default (or the first organization dashboard), else their
// first own dashboard.
func PickLanding(personal []*domain.Dashboard, organization []OrgDashboard, saved *Ref) *Ref {
	if saved != nil {
		switch saved.Kind {
		case domain.KindPersonal:
			for _, d := range personal {
				if d.ID().String() == saved.ID {
					return saved
				}
			}
		case domain.KindOrganization:
			for _, d := range organization {
				if d.ID().String() == saved.ID {
					return saved
				}
			}
		}
	}
	for _, d := range personal {
		if d.IsDefault() {
			return &Ref{Kind: domain.KindPersonal, ID: d.ID().String()}
		}
	}
	var org *OrgDashboard
	for i := range organization {
		if organization[i].IsOrgDefault() {
			org = &organization[i]
			break
		}
	}
	if org == nil && len(organization) > 0 {
		org = &organization[0]
	}
	if org != nil {
		return &Ref{Kind: domain.KindOrganization, ID: org.ID().String()}
	}
	if len(personal) > 0 {
		return &Ref{Kind: domain.KindPersonal, ID: personal[0].ID().String()}
	}
	return nil
}
