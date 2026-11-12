package dashboard

import (
	"context"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	domain "github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// FlowPanelResult is the outcome of offering the exposure flow panel.
type FlowPanelResult struct {
	// Added is true only when this call put the panel on the layout.
	Added bool
	// WidgetID is the config id of the added panel (empty when not added).
	WidgetID  string
	Dashboard *domain.Dashboard
}

// AddFlowPanel offers the exposure flow panel on one of the caller's personal
// dashboards, once (docs/architecture/dashboards.md, "Exposure flow panel").
// Another user's or another organization's dashboard is not found.
func (s *Service) AddFlowPanel(ctx context.Context, c Caller, id string) (*FlowPanelResult, error) {
	d, err := s.ownedPersonal(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return s.addFlowPanel(ctx, c, d)
}

// AddOrgFlowPanel offers the panel on an organization dashboard
// (dashboards:org:manage).
func (s *Service) AddOrgFlowPanel(ctx context.Context, c Caller, id string) (*FlowPanelResult, error) {
	d, err := s.managedOrg(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return s.addFlowPanel(ctx, c, d)
}

// UndoFlowPanel removes the panel added to a personal dashboard. The offer
// stays recorded, so the panel is never added again.
func (s *Service) UndoFlowPanel(ctx context.Context, c Caller, id, widgetID string) (*domain.Dashboard, error) {
	d, err := s.ownedPersonal(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return s.undoFlowPanel(ctx, c, d, widgetID)
}

// UndoOrgFlowPanel is UndoFlowPanel for an organization dashboard.
func (s *Service) UndoOrgFlowPanel(ctx context.Context, c Caller, id, widgetID string) (*domain.Dashboard, error) {
	d, err := s.managedOrg(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return s.undoFlowPanel(ctx, c, d, widgetID)
}

func (s *Service) ownedPersonal(ctx context.Context, c Caller, id string) (*domain.Dashboard, error) {
	if err := c.requireUser(); err != nil {
		return nil, err
	}
	dID, err := parseID(id)
	if err != nil {
		return nil, err
	}
	return s.repo.GetByID(ctx, c.TenantID, c.UserID, dID)
}

// reload re-reads d by its kind after another writer won the race.
func (s *Service) reload(ctx context.Context, c Caller, d *domain.Dashboard) (*domain.Dashboard, error) {
	if d.Kind() == domain.KindOrganization {
		return s.repo.GetOrg(ctx, c.TenantID, d.ID())
	}
	return s.repo.GetByID(ctx, c.TenantID, c.UserID, d.ID())
}

func (s *Service) addFlowPanel(ctx context.Context, c Caller, d *domain.Dashboard) (*FlowPanelResult, error) {
	if d.FlowPanelAt() != nil {
		return &FlowPanelResult{Dashboard: d}, nil
	}
	now := s.now().UTC()
	// A layout that already has the flow, or none at all (deliberately empty),
	// is only marked as offered.
	if d.HasFlowWidget() || len(d.Widgets()) == 0 {
		if _, err := s.repo.MarkFlowPanel(ctx, d, now); err != nil {
			return nil, err
		}
		cur, err := s.reload(ctx, c, d)
		if err != nil {
			return nil, err
		}
		return &FlowPanelResult{Dashboard: cur}, nil
	}
	widgetID, err := d.PrependFlowPanel()
	if err != nil {
		return nil, err
	}
	d.MarkFlowPanelOffered(now)
	won, err := s.repo.AddFlowPanel(ctx, d, now)
	if err != nil {
		return nil, err
	}
	if !won {
		// Someone else offered it first: report what is stored now.
		cur, err := s.reload(ctx, c, d)
		if err != nil {
			return nil, err
		}
		return &FlowPanelResult{Dashboard: cur}, nil
	}
	s.logAudit(ctx, c, s.flowEvent(auditdom.ActionDashboardFlowPanelAdded, d, "Exposure flow panel added to the dashboard", widgetID))
	return &FlowPanelResult{Added: true, WidgetID: widgetID, Dashboard: d}, nil
}

func (s *Service) undoFlowPanel(ctx context.Context, c Caller, d *domain.Dashboard, widgetID string) (*domain.Dashboard, error) {
	if err := d.RemoveFlowWidget(widgetID); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, d); err != nil {
		return nil, err
	}
	s.logAudit(ctx, c, s.flowEvent(auditdom.ActionDashboardFlowPanelUndone, d, "Exposure flow panel removed from the dashboard", widgetID))
	return s.reload(ctx, c, d)
}

func (s *Service) flowEvent(action auditdom.Action, d *domain.Dashboard, msg, widgetID string) auditapp.AuditEvent {
	return auditapp.NewSuccessEvent(action, auditdom.ResourceTypeDashboard, d.ID().String()).
		WithResourceName(d.Name()).
		WithMessage(msg).
		WithMetadata("kind", string(d.Kind())).
		WithMetadata("widget_id", widgetID)
}
