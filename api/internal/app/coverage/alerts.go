package coverage

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/internal/metrics"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Gap detection runs at most this often per tenant, and one alert of a kind
// and capability is sent at most once per AlertEvery.
const (
	DetectEvery = 15 * time.Minute
	AlertEvery  = 20 * time.Hour
)

// AdminDirectory lists a tenant's active administrators.
type AdminDirectory interface {
	ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
}

// InAppNotifier creates in-app notifications.
type InAppNotifier interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// Enqueuer is the outbox (integrations: Slack, email, webhooks).
type Enqueuer interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

type alerting struct {
	health covdom.HealthReader
	admins AdminDirectory
	inApp  InAppNotifier
	outbox Enqueuer
	last   map[shared.ID]time.Time
	gaps   map[string]int // capability -> gap pairs, this pass
}

// EnableAlerts wires gap detection. Any sink may be nil (skipped).
func (s *Service) EnableAlerts(health covdom.HealthReader, admins AdminDirectory, inApp InAppNotifier, o Enqueuer) {
	s.alerts = &alerting{health: health, admins: admins, inApp: inApp, outbox: o, last: map[shared.ID]time.Time{}}
}

func (s *Service) cadences() map[string]time.Duration {
	out := map[string]time.Duration{}
	for _, r := range s.rules {
		if _, ok := out[r.Capability]; !ok {
			out[r.Capability] = r.Every
		}
	}
	return out
}

// detect reads the tenant's coverage health and raises its alerts. It
// returns the alerts it sent.
func (s *Service) detect(ctx context.Context, tenantID shared.ID) (int, error) {
	a := s.alerts
	if a == nil || a.health == nil {
		return 0, nil
	}
	if last, ok := a.last[tenantID]; ok && s.now().Sub(last) < DetectEvery {
		return 0, nil
	}
	a.last[tenantID] = s.now()
	health, err := a.health.Health(ctx, tenantID, s.cadences())
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, h := range health {
		if a.gaps != nil {
			a.gaps[h.Capability] += h.Gaps
		}
		for _, kind := range h.Alerts() {
			key := tenantID.String() + ":" + h.Capability + ":" + kind
			ok, err := a.health.ClaimAlert(ctx, key, AlertEvery)
			if err != nil {
				return sent, err
			}
			if !ok {
				continue
			}
			metrics.AssetCoverageAlertsTotal.WithLabelValues(kind, h.Capability).Inc()
			s.sendAlert(ctx, tenantID, h, kind)
			sent++
		}
	}
	return sent, nil
}

// describeAlert is the alert's title and body. Server-generated English: it
// reaches integrations and in-app notifications verbatim.
func describeAlert(h covdom.CapabilityHealth, kind string) (title, body string) {
	switch kind {
	case covdom.AlertOutputDrop:
		return "Coverage: " + h.Capability + " produces nothing",
			fmt.Sprintf("In the last 24 hours %s ran on %d assets that should have produced output and produced none. The tool may be broken or blocked.", h.Capability, h.NoOutput)
	case covdom.AlertFailing:
		return "Coverage: " + h.Capability + " keeps failing",
			fmt.Sprintf("%s failed %d or more times in a row on %d assets.", h.Capability, covdom.FailingStreak, h.Failing)
	default:
		return "Coverage gap: " + h.Capability,
			fmt.Sprintf("%d of %d assets that need %s have not had it for more than twice its cadence (or never).", h.Gaps, h.Applicable, h.Capability)
	}
}

func (s *Service) sendAlert(ctx context.Context, tenantID shared.ID, h covdom.CapabilityHealth, kind string) {
	a := s.alerts
	title, body := describeAlert(h, kind)
	const url = "/assets"
	if a.outbox != nil {
		if err := a.outbox.Enqueue(ctx, outbox.EnqueueParams{
			TenantID: tenantID, EventType: string(integration.EventTypeCoverageGap), AggregateType: "asset",
			Title: title, Body: body, Severity: "medium", URL: url,
			Metadata: map[string]any{"capability": h.Capability, "kind": kind, "gaps": h.Gaps,
				"applicable": h.Applicable, "failing": h.Failing, "no_output": h.NoOutput},
		}); err != nil {
			s.logger.Warn("coverage alert not enqueued", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
	}
	if a.inApp == nil || a.admins == nil {
		return
	}
	ids, err := a.admins.ActiveAdminIDs(ctx, tenantID)
	if err != nil {
		s.logger.Warn("coverage alert: list admins", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return
	}
	for _, id := range ids {
		uid := id
		if err := a.inApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: tenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
			NotificationType: notificationdom.TypeCoverageGap, Severity: notificationdom.SeverityMedium,
			Title: title, Body: body, ResourceType: "asset", URL: url,
		}); err != nil {
			s.logger.Warn("coverage alert: notify admin", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
	}
}
