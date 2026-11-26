package coverage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/internal/app/outbox"
	"github.com/openctemio/openctem/server/internal/metrics"
	covdom "github.com/openctemio/openctem/server/pkg/domain/coverage"
	"github.com/openctemio/openctem/server/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Gap detection runs at most this often per tenant. Alerts are sent on
// change (covdom.PlanAlerts), never on a timer.
const DetectEvery = 15 * time.Minute

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

func cadences(rules []covdom.Rule) map[string]time.Duration {
	out := map[string]time.Duration{}
	for _, r := range rules {
		if _, ok := out[r.Capability]; !ok {
			out[r.Capability] = r.Every
		}
	}
	return out
}

// detect reads the tenant's coverage health and sends the alerts whose
// condition appeared or got clearly worse (covdom.PlanAlerts), with the action
// that fixes it; several changes in one pass go out as one digest. It
// returns the alert conditions it sent.
func (s *Service) detect(ctx context.Context, tenantID shared.ID, rules []covdom.Rule) (int, error) {
	a := s.alerts
	if a == nil || a.health == nil {
		return 0, nil
	}
	if last, ok := a.last[tenantID]; ok && s.now().Sub(last) < DetectEvery {
		return 0, nil
	}
	a.last[tenantID] = s.now()
	health, err := a.health.Health(ctx, tenantID, cadences(rules))
	if err != nil {
		return 0, err
	}
	for _, h := range health {
		if a.gaps != nil {
			a.gaps[h.Capability] += h.Gaps
		}
	}
	states, err := a.health.AlertStates(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	send, store := covdom.PlanAlerts(states, covdom.Conditions(health), s.now())
	// Record first: a send that fails is logged, never repeated every pass.
	if err := a.health.SaveAlertStates(ctx, tenantID, store); err != nil {
		return 0, err
	}
	if len(send) == 0 {
		return 0, nil
	}
	for _, c := range send {
		metrics.AssetCoverageAlertsTotal.WithLabelValues(c.Kind, c.Capability).Inc()
	}
	s.sendAlert(ctx, tenantID, send)
	return len(send), nil
}

// describeCondition is one condition's sentence. Server-generated English:
// it reaches integrations and in-app notifications verbatim, with counts
// and capability names only (never a host name).
func describeCondition(c covdom.AlertCondition) (title, body string) {
	switch c.Kind {
	case covdom.AlertReadiness:
		return "Coverage paused: " + c.Capability,
			fmt.Sprintf("%s is paused on %d assets: %s.", c.Capability, c.Count, covdom.ReadinessText(c.Reason))
	case covdom.AlertOutputDrop:
		return "Coverage: " + c.Capability + " produces nothing",
			fmt.Sprintf("In the last 24 hours %s ran on %d assets that should have produced output and produced none. The tool may be broken or blocked.", c.Capability, c.Count)
	case covdom.AlertFailing:
		return "Coverage: " + c.Capability + " keeps failing",
			fmt.Sprintf("%s failed %d or more times in a row on %d assets.", c.Capability, covdom.FailingStreak, c.Count)
	case covdom.AlertUnreachable:
		return "Coverage: " + c.Capability + " targets unreachable",
			fmt.Sprintf("%d assets did not answer %s from your sensors; they are checked again on a widening schedule.", c.Count, c.Capability)
	default:
		return "Coverage gap: " + c.Capability,
			fmt.Sprintf("%d assets that need %s have not had it for more than twice its cadence (or never).", c.Count, c.Capability)
	}
}

// describeAlert is the message of one or several changed conditions: one
// condition with its action, or a digest with one line per condition. msg is
// the same text as a code and values for the web (conditionMessage).
func describeAlert(send []covdom.AlertCondition) (title, body, url string, msg *notificationdom.Message) {
	if len(send) == 1 {
		title, body = describeCondition(send[0])
		act := covdom.ActionFor(send[0])
		return title, body + " " + act.Text, act.URL, conditionMessage(send[0])
	}
	lines := make([]string, 0, len(send))
	items := make([]*notificationdom.Message, 0, len(send))
	url = covdom.ActionFor(send[0]).URL
	for _, c := range send {
		_, b := describeCondition(c)
		act := covdom.ActionFor(c)
		lines = append(lines, "- "+b+" "+act.Text)
		items = append(items, conditionMessage(c))
		if act.URL != url {
			url = "/assets"
		}
	}
	return fmt.Sprintf("Coverage: %d changes", len(send)), strings.Join(lines, "\n"), url,
		notificationdom.Lines("coverage.digest", items, "count", len(send))
}

// conditionMessage is one condition as a message code (coverage.<kind>) with
// the capability key, the asset count, the readiness reason and the action
// as values; the web words each in the reader's language.
func conditionMessage(c covdom.AlertCondition) *notificationdom.Message {
	kind := c.Kind
	switch kind {
	case covdom.AlertReadiness, covdom.AlertOutputDrop, covdom.AlertFailing, covdom.AlertUnreachable:
	default:
		kind = covdom.AlertGap
	}
	m := notificationdom.Msg("coverage."+kind, "capability", c.Capability, "count", c.Count,
		"action", notificationdom.Msg(alertActionCode(c)))
	switch kind {
	case covdom.AlertReadiness:
		m.Params["readiness"] = notificationdom.Msg("coverage.readiness." + safeCodeSegment(c.Reason))
	case covdom.AlertFailing:
		m.Params["streak"] = covdom.FailingStreak
	}
	return m
}

// alertActionCode names the action covdom.ActionFor words for a condition.
func alertActionCode(c covdom.AlertCondition) string {
	switch c.Kind {
	case covdom.AlertUnreachable:
		return "coverage.action.unreachable"
	case covdom.AlertReadiness:
		return "coverage.action." + safeCodeSegment(c.Reason)
	default:
		return "coverage.action.open_assets"
	}
}

// safeCodeSegment keeps a reason usable as one code segment (lower-case
// letters, digits and underscores); anything else becomes "other", which the
// web words generically.
func safeCodeSegment(v string) string {
	if v == "" {
		return "other"
	}
	for _, r := range v {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return "other"
		}
	}
	return v
}

func (s *Service) sendAlert(ctx context.Context, tenantID shared.ID, send []covdom.AlertCondition) {
	a := s.alerts
	title, body, url, msg := describeAlert(send)
	if a.outbox != nil {
		conds := make([]map[string]any, 0, len(send))
		for _, c := range send {
			conds = append(conds, map[string]any{"capability": c.Capability, "kind": c.Kind, "reason": c.Reason, "count": c.Count})
		}
		meta := map[string]any{"conditions": conds}
		if len(send) == 1 {
			meta["capability"], meta["kind"], meta["reason"], meta["count"] = send[0].Capability, send[0].Kind, send[0].Reason, send[0].Count
		}
		if err := a.outbox.Enqueue(ctx, outbox.EnqueueParams{
			TenantID: tenantID, EventType: string(integration.EventTypeCoverageGap), AggregateType: "asset",
			Title: title, Body: body, Severity: "medium", URL: url, Metadata: meta,
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
			Title: title, Body: body, Message: msg, ResourceType: "asset", URL: url,
		}); err != nil {
			s.logger.Warn("coverage alert: notify admin", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
	}
}
