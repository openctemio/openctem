package threatalert

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/threatalert"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Console paths of the alerts.
const (
	alertsPath = "/emerging-threats"
	// maxDeliveryAssets bounds the asset ids an outbox entry carries for
	// the delivery resolver (private program routing).
	maxDeliveryAssets = 200
)

func alertPath(id shared.ID) string { return alertsPath + "/" + id.String() }

// flush sends the organization's pending immediate alerts: held during
// quiet hours unless at or above the override score, one bundle when the
// window ends, at most MaxImmediatePerHour messages an hour and one "N more"
// message for the rest (at most one an hour; until then they wait).
func (p *Planner) flush(ctx context.Context, rs *runState, tenantID shared.ID) (int, error) {
	pol := p.policyOf(ctx, rs, tenantID)
	if !pol.active {
		return 0, nil
	}
	pending, err := p.store.PendingImmediate(ctx, tenantID)
	if err != nil || len(pending) == 0 {
		return 0, err
	}
	now := p.now()
	local := now.In(pol.loc)
	var send []*threatalert.Alert
	var hold []shared.ID
	if pol.settings.InQuietHours(local.Hour()) {
		for _, a := range pending {
			if a.ETS >= pol.settings.QuietOverride {
				send = append(send, a)
			} else if !a.Held {
				hold = append(hold, a.ID)
			}
		}
		if err := p.store.SetHeld(ctx, tenantID, hold); err != nil {
			return 0, err
		}
	} else {
		send = pending
		held := 0
		for _, a := range pending {
			if a.Held {
				held++
			}
		}
		if held > 0 && len(pending) > 1 {
			// The end of quiet hours: everything held goes as one bundle.
			p.sendSummary(ctx, pol, tenantID, pending, true)
			return 1, p.store.MarkNotified(ctx, tenantID, ids(pending), threatalert.LevelImmediate, true, now)
		}
	}
	if len(send) == 0 {
		return 0, nil
	}
	sentLastHour, err := p.store.ImmediateSentSince(ctx, tenantID, now.Add(-time.Hour))
	if err != nil {
		return 0, err
	}
	room := max(0, MaxImmediatePerHour-sentLastHour)
	individual := send[:min(room, len(send))]
	rest := send[len(individual):]
	for _, a := range individual {
		p.sendImmediate(ctx, pol, a)
	}
	if err := p.store.MarkNotified(ctx, tenantID, ids(individual), threatalert.LevelImmediate, true, now); err != nil {
		return len(individual), err
	}
	sent := len(individual)
	if len(rest) == 0 {
		return sent, nil
	}
	state, err := p.store.TenantState(ctx, tenantID)
	if err != nil {
		return sent, err
	}
	if state.LastFoldAt != nil && now.Sub(*state.LastFoldAt) < time.Hour {
		return sent, nil // the rest waits for the next hour
	}
	p.sendSummary(ctx, pol, tenantID, rest, false)
	state.LastFoldAt = &now
	if err := p.store.SaveTenantState(ctx, state); err != nil {
		return sent, err
	}
	return sent + 1, p.store.MarkNotified(ctx, tenantID, ids(rest), threatalert.LevelImmediate, false, now)
}

func ids(as []*threatalert.Alert) []shared.ID {
	out := make([]shared.ID, 0, len(as))
	for _, a := range as {
		out = append(out, a.ID)
	}
	return out
}

// whyNow is the alert's reason in one line (public facts).
func whyNow(a *threatalert.Alert) string {
	var parts []string
	if a.InKEV {
		s := "in the CISA KEV catalog"
		if a.KEVRansomware {
			s += " (known ransomware use)"
		}
		parts = append(parts, s)
	}
	if a.EPSS != nil && *a.EPSS >= 0.1 {
		parts = append(parts, fmt.Sprintf("EPSS %.2f", *a.EPSS))
	}
	if a.Severity != "" {
		parts = append(parts, "severity "+a.Severity)
	}
	if len(parts) == 0 {
		return "newly published"
	}
	return strings.Join(parts, " · ")
}

// affects is the alert's reach in one line: counts, and names only when
// the organization turned them on.
func (p *Planner) affects(ctx context.Context, pol *policy, a *threatalert.Alert) string {
	s := fmt.Sprintf("%d confirmed, %d possibly affected (version unknown), %d internet-facing", a.Confirmed, a.Possible, a.InternetFacing)
	if !pol.settings.AssetNamesInMessages {
		return s
	}
	assets, err := p.store.AffectedAssets(ctx, a.TenantID, a.VulnID)
	if err != nil || len(assets) == 0 {
		return s
	}
	names := make([]string, 0, tenant.MaxEmergingAssetNames)
	for _, x := range assets {
		if len(names) == tenant.MaxEmergingAssetNames {
			break
		}
		if n := threatalert.PlainText(x.Name, 80); n != "" {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return s
	}
	return s + ". Assets: " + strings.Join(names, ", ")
}

func deliveryAssets(ctx context.Context, p *Planner, a *threatalert.Alert) []map[string]any {
	assets, err := p.store.AffectedAssets(ctx, a.TenantID, a.VulnID)
	if err != nil {
		return nil
	}
	out := make([]map[string]any, 0, min(len(assets), maxDeliveryAssets))
	for _, x := range assets {
		if len(out) == maxDeliveryAssets {
			break
		}
		out = append(out, map[string]any{"id": x.AssetID.String()})
	}
	return out
}

func (p *Planner) sendImmediate(ctx context.Context, pol *policy, a *threatalert.Alert) {
	title := "[Urgent] " + a.Title
	body := "Why now: " + whyNow(a) + "\nAffects you: " + p.affects(ctx, pol, a) +
		fmt.Sprintf("\nEmerging threat score: %d", a.ETS)
	if a.Tier == threatalert.TierPossible {
		body += "\nThe version is unknown on these assets: confirm before you patch."
	}
	if p.outbox != nil {
		params := outbox.EnqueueParams{
			TenantID: a.TenantID, EventType: string(integration.EventTypeEmergingThreat), AggregateType: "emerging_threat",
			Title: title, Body: body, Severity: "critical", URL: alertPath(a.ID),
			Metadata: map[string]any{"schema": "emerging_threat.v1", "vuln_id": a.VulnID, "level": string(a.Level),
				"tier": string(a.Tier), "ets": a.ETS, "in_kev": a.InKEV, "confirmed": a.Confirmed, "possible": a.Possible,
				"internet_facing": a.InternetFacing, "assets": deliveryAssets(ctx, p, a)},
		}
		if u, err := uuid.Parse(a.ID.String()); err == nil {
			params.AggregateID = &u
		}
		if err := p.outbox.Enqueue(ctx, params); err != nil {
			p.logger.Warn("emerging threat not enqueued", "tenant_id", a.TenantID.String(), "error", logger.SanitizeError(err))
		}
	}
	p.notifyAdmins(ctx, a.TenantID, notificationdom.TypeEmergingThreat, notificationdom.SeverityCritical, title,
		"Why now: "+whyNow(a)+". Affects you: "+fmt.Sprintf("%d confirmed, %d possibly affected, %d internet-facing.", a.Confirmed, a.Possible, a.InternetFacing),
		alertPath(a.ID))
}

// sendSummary sends one message for several urgent alerts: the hourly
// overflow, or what quiet hours held.
func (p *Planner) sendSummary(ctx context.Context, pol *policy, tenantID shared.ID, alerts []*threatalert.Alert, quiet bool) {
	_ = pol
	title := fmt.Sprintf("[Urgent] %d more emerging threats affect your assets", len(alerts))
	if quiet {
		title = fmt.Sprintf("[Urgent] %d emerging threats held during quiet hours", len(alerts))
	}
	lines := make([]string, 0, 10)
	for i, a := range alerts {
		if i == 10 {
			lines = append(lines, fmt.Sprintf("and %d more", len(alerts)-10))
			break
		}
		lines = append(lines, fmt.Sprintf("%s (score %d, %d confirmed, %d possibly affected)", threatalert.PlainText(a.VulnID, 64), a.ETS, a.Confirmed, a.Possible))
	}
	body := strings.Join(lines, "\n")
	url := alertsPath + "?level=immediate"
	if p.outbox != nil {
		if err := p.outbox.Enqueue(ctx, outbox.EnqueueParams{
			TenantID: tenantID, EventType: string(integration.EventTypeEmergingThreat), AggregateType: "emerging_threat",
			Title: title, Body: body, Severity: "critical", URL: url,
			Metadata: map[string]any{"schema": "emerging_threat.v1", "summary": true, "alerts": len(alerts)},
		}); err != nil {
			p.logger.Warn("emerging threat summary not enqueued", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
	}
	p.notifyAdmins(ctx, tenantID, notificationdom.TypeEmergingThreat, notificationdom.SeverityCritical, title, body, url)
}

func (p *Planner) notifyAdmins(ctx context.Context, tenantID shared.ID, kind, severity, title, body, url string) {
	if p.inApp == nil || p.admins == nil {
		return
	}
	admins, err := p.admins.ActiveAdminIDs(ctx, tenantID)
	if err != nil {
		p.logger.Warn("emerging threat: list admins", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return
	}
	for _, id := range admins {
		uid := id
		if err := p.inApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: tenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
			NotificationType: kind, Severity: severity, Title: title, Body: body, ResourceType: "emerging_threat", URL: url,
		}); err != nil {
			p.logger.Warn("emerging threat: notify admin", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
	}
}

// digests sends each organization's daily digest at its local digest hour,
// once a day, when something changed (or the baseline is due).
func (p *Planner) digests(ctx context.Context, rs *runState) (int, error) {
	tenants, err := p.store.DigestTenants(ctx)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, id := range tenants {
		ok, err := p.digest(ctx, rs, id)
		if err != nil {
			p.logger.Warn("emerging threat digest not sent", "tenant_id", id.String(), "error", err)
			continue
		}
		if ok {
			sent++
		}
	}
	return sent, nil
}

func (p *Planner) digest(ctx context.Context, rs *runState, tenantID shared.ID) (bool, error) {
	pol := p.policyOf(ctx, rs, tenantID)
	if !pol.active {
		return false, nil
	}
	now := p.now()
	local := now.In(pol.loc)
	today := local.Format(time.DateOnly)
	state, err := p.store.TenantState(ctx, tenantID)
	if err != nil {
		return false, err
	}
	if state.LastDigestOn == today || local.Hour() < *pol.settings.DigestHour {
		return false, nil
	}
	since := now.Add(-24 * time.Hour)
	if state.LastDigestAt != nil {
		since = *state.LastDigestAt
	}
	d, err := p.store.DigestSummary(ctx, tenantID, since, nil)
	if err != nil {
		return false, err
	}
	baseline := state.BaselineDigestDue
	if !d.Empty() || baseline {
		title, body := digestText(d, baseline)
		if p.outbox != nil {
			if err := p.outbox.Enqueue(ctx, outbox.EnqueueParams{
				TenantID: tenantID, EventType: string(integration.EventTypeEmergingThreatDigest), AggregateType: "emerging_threat",
				Title: title, Body: body, Severity: "info", URL: alertsPath,
				Metadata: map[string]any{"schema": "emerging_threat_digest.v1", "immediate": d.Immediate, "digest": d.Digest,
					"listed": d.Listed, "resolved": d.Resolved, "kev": d.KEV, "baseline": baseline},
			}); err != nil {
				p.logger.Warn("emerging threat digest not enqueued", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
			}
		}
		p.notifyAdmins(ctx, tenantID, notificationdom.TypeEmergingThreatDigest, notificationdom.SeverityLow, title, body, alertsPath)
		p.mailDigests(ctx, tenantID, local, since, baseline)
	}
	if err := p.store.ClearDigest(ctx, tenantID); err != nil {
		return false, err
	}
	state.LastDigestOn, state.LastDigestAt, state.BaselineDigestDue = today, &now, false
	return !d.Empty() || baseline, p.store.SaveTenantState(ctx, state)
}

// digestText is the digest's title and body: counts and vulnerability ids,
// no asset names (the digest reaches external channels).
func digestText(d threatalert.Digest, baseline bool) (string, string) {
	if baseline {
		title := fmt.Sprintf("Emerging threats: %d actively exploited vulnerabilities affect your assets today", d.Exploited)
		return title, title + ". From now on you are told only about new ones. Open the list to see them."
	}
	title := fmt.Sprintf("Emerging threats: %d urgent, %d new to review", d.Immediate, d.Digest)
	var b strings.Builder
	fmt.Fprintf(&b, "Since the last digest: %d urgent, %d to review, %d listed only, %d resolved. %d are in the CISA KEV catalog.",
		d.Immediate, d.Digest, d.Listed, d.Resolved, d.KEV)
	if len(d.Top) > 0 {
		b.WriteString("\nTop by score:")
		for _, it := range d.Top {
			fmt.Fprintf(&b, "\n%s (score %d, %d confirmed, %d possibly affected, %d internet-facing)",
				threatalert.PlainText(it.VulnID, 64), it.ETS, it.Confirmed, it.Possible, it.InternetFacing)
		}
	}
	return title, b.String()
}

// mailDigests e-mails each member who asked for the digest, counted within
// their data scope; weekly members get it on Mondays, covering seven days.
func (p *Planner) mailDigests(ctx context.Context, tenantID shared.ID, local time.Time, since time.Time, baseline bool) {
	if p.mail == nil {
		return
	}
	recipients, err := p.store.DigestRecipients(ctx, tenantID)
	if err != nil {
		p.logger.Warn("emerging threat digest: recipients", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return
	}
	for _, rc := range recipients {
		if rc.Muted {
			continue
		}
		from := since
		if rc.Frequency == "weekly" {
			if local.Weekday() != time.Monday {
				continue
			}
			from = p.now().Add(-7 * 24 * time.Hour)
		}
		var scope *shared.DataScope
		if p.scopes != nil {
			s, err := p.scopes.ForUser(ctx, tenantID, rc.UserID)
			if err != nil {
				continue // fail closed: no scope, no mail
			}
			scope = s
		}
		d, err := p.store.DigestSummary(ctx, tenantID, from, scope)
		if err != nil || (d.Empty() && !baseline) || (baseline && d.Exploited == 0 && d.Empty()) {
			continue
		}
		title, _ := digestText(d, baseline)
		p.mail.SendEmergingThreatMail(ctx, tenantID.String(), []string{rc.Email}, "[Emerging threats] "+title, p.digestMail(d, baseline))
	}
}

func (p *Planner) digestMail(d threatalert.Digest, baseline bool) string {
	link := html.EscapeString(p.webBase + alertsPath)
	var b strings.Builder
	if baseline {
		fmt.Fprintf(&b, "<p>%d actively exploited vulnerabilities affect assets you can see today. From now on you are told only about new ones.</p>", d.Exploited)
	} else {
		fmt.Fprintf(&b, "<p>Since the last digest: %d urgent, %d to review, %d listed only, %d resolved; %d in the CISA KEV catalog.</p>",
			d.Immediate, d.Digest, d.Listed, d.Resolved, d.KEV)
	}
	if len(d.Top) > 0 {
		b.WriteString("<ul>")
		for _, it := range d.Top {
			fmt.Fprintf(&b, "<li>%s: score %d, %d confirmed, %d possibly affected, %d internet-facing</li>",
				html.EscapeString(threatalert.PlainText(it.Title, 200)), it.ETS, it.Confirmed, it.Possible, it.InternetFacing)
		}
		b.WriteString("</ul>")
	}
	fmt.Fprintf(&b, `<p>Open the list: <a href="%s">%s</a> (sign-in required). To stop this e-mail, set the e-mail digest to none or mute "Emerging threats daily digest" in your notification settings.</p>`, link, link)
	return b.String()
}
