package cirun

import (
	"context"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AdminLister lists a tenant's active owners and administrators.
type AdminLister interface {
	ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
}

// InAppNotifier delivers an in-app notification to one user.
type InAppNotifier interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// AdminAlert is a CI security event every administrator of the tenant must
// see: in-app for each active owner and administrator, and on the tenant's
// notification channels that subscribe to EventType.
type AdminAlert struct {
	EventType   string
	Title       string
	Body        string
	Severity    string
	URL         string
	Aggregate   string
	AggregateID *shared.ID
	Metadata    map[string]any
}

// breakGlassAlert is a break-glass event (created or used): high severity,
// on the ci.break_glass channel event.
func breakGlassAlert(a AdminAlert) AdminAlert {
	a.EventType, a.Severity = string(integration.EventTypeCIBreakGlass), notificationdom.SeverityHigh
	return a
}

// AdminAlerter sends AdminAlerts. Best effort: the action it reports already
// happened and is audited.
type AdminAlerter interface {
	AlertAdmins(ctx context.Context, tenantID shared.ID, a AdminAlert)
}

// AdminAlerts is the AdminAlerter over the member list, the in-app
// notifications and the notification outbox. Any of them may be nil.
type AdminAlerts struct {
	admins AdminLister
	inApp  InAppNotifier
	outbox Notifier
	log    *logger.Logger
}

// NewAdminAlerts creates the alerter.
func NewAdminAlerts(admins AdminLister, inApp InAppNotifier, ob Notifier, log *logger.Logger) *AdminAlerts {
	if log == nil {
		log = logger.NewNop()
	}
	return &AdminAlerts{admins: admins, inApp: inApp, outbox: ob, log: log.With("component", "ci-admin-alerts")}
}

// AlertAdmins notifies every active owner and administrator in-app and
// enqueues the event for the tenant's channels.
func (n *AdminAlerts) AlertAdmins(ctx context.Context, tenantID shared.ID, a AdminAlert) {
	if n.admins != nil && n.inApp != nil {
		ids, err := n.admins.ActiveAdminIDs(ctx, tenantID)
		if err != nil {
			n.log.Warn("ci admin alert: list administrators", "error", logger.SanitizeError(err))
		}
		for _, id := range ids {
			uid := id
			if err := n.inApp.Notify(ctx, notificationdom.NotificationParams{
				TenantID: tenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
				NotificationType: notificationdom.TypeCISecurity, Title: a.Title, Body: a.Body,
				Severity: a.Severity, ResourceType: a.Aggregate, ResourceID: a.AggregateID, URL: a.URL,
			}); err != nil {
				n.log.Warn("ci admin alert: in-app notification", "error", logger.SanitizeError(err))
			}
		}
	}
	if n.outbox != nil {
		var aggID *uuid.UUID
		if a.AggregateID != nil {
			if id, err := uuid.Parse(a.AggregateID.String()); err == nil {
				aggID = &id
			}
		}
		if err := n.outbox.Enqueue(ctx, outbox.EnqueueParams{TenantID: tenantID, EventType: a.EventType,
			AggregateType: a.Aggregate, AggregateID: aggID, Title: a.Title, Body: a.Body, Severity: a.Severity,
			URL: a.URL, Metadata: a.Metadata}); err != nil {
			n.log.Warn("ci admin alert: enqueue", "event_type", a.EventType, "error", logger.SanitizeError(err))
		}
	}
}
