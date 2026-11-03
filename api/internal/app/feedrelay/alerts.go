package feedrelay

import (
	"context"
	"errors"
	"fmt"
	"html"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	dom "github.com/openctemio/openctem/api/pkg/domain/feedrelay"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Alerts: in relay mode the platform has no other way to receive its feeds
// (it never falls back to direct by itself), so the platform administrators
// are told, through the existing admin channel (e-mail and the alert
// webhook), when
//   - no designated relay sensor has been seen for AlertRelayOffline,
//   - a feed's applied release is older than its alert age,
//   - a cycle failed verification (verify_failed, pin_mismatch,
//     rollback_refused) or the job signer refused a round.
//
// One alert per condition: the open alerts are stored (platform setting
// AlertsKey), so a restart or a lease move does not mail again; a condition
// that clears is closed with a "resolved" notice. Alerts carry codes, times
// and feed names only, never upstream text beyond the signer's sanitized
// reason.

// AlertsKey is the platform_settings key of the open alerts (written by the
// feed-relay controller, never by a person).
const AlertsKey = "feed_relay.alerts"

// AlertRelayOffline: relay mode with no designated sensor seen for this
// long alerts.
const AlertRelayOffline = time.Hour

// alertEvery bounds how often the conditions are read.
const alertEvery = time.Minute

// alertAge is how old a feed's applied release may get before the
// administrators are told. The vulnerability feed carries EPSS, which is
// stale after 48 hours; the release feed is issued per release, so its age
// says nothing (its failures and the relay going offline still alert).
var alertAge = map[string]time.Duration{dom.FeedVulnFeed: 48 * time.Hour}

// alertCodes are the round failures that alert at once.
var alertCodes = []string{dom.CodeVerifyFailed, dom.CodePinMismatch, dom.CodeRollbackRefused, dom.CodeSignerRefused}

// Alert conditions (the first part of an alert key).
const (
	AlertConditionOffline = "relay_offline"
	AlertConditionStale   = "feed_stale"
	AlertConditionFailed  = "round_failed"
)

// Notifier tells the platform administrators (systemstatus.Notifier: the
// e-mail and the alert webhook).
type Notifier interface {
	NotifyAdmins(ctx context.Context, subject, htmlBody string) error
}

// OpenAlert is one open alert.
type OpenAlert struct {
	Since time.Time `json:"since"`
}

// alertState is the stored set of open alerts by key.
type alertState struct {
	Open map[string]OpenAlert `json:"open"`
}

// alert is one condition that holds now.
type alert struct {
	key      string
	critical bool
	subject  string
	body     string // HTML, escaped
}

// SetNotifier wires the administrators' channel (nil: log only).
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

// OpenAlerts returns the open alerts by key.
func (s *Service) OpenAlerts(ctx context.Context) (map[string]OpenAlert, error) {
	st, _, err := s.alerts.Fresh(ctx)
	if err != nil {
		return nil, err
	}
	return st.Open, nil
}

// watch opens and resolves the alerts (on the controller's tick, at most
// every alertEvery). The new state is stored before anything is sent, so a
// failed write never mails twice.
func (s *Service) watch(ctx context.Context, now time.Time) {
	if !s.lastWatch.IsZero() && now.Sub(s.lastWatch) < alertEvery {
		return
	}
	s.lastWatch = now
	holding, direct, err := s.conditions(ctx, now)
	if err != nil {
		s.logger.Warn("feed relay: read alert conditions", "error", err)
		return
	}
	st, meta, err := s.alerts.Fresh(ctx)
	if err != nil {
		s.logger.Warn("feed relay: read open alerts", "error", err)
		return
	}
	next := alertState{Open: map[string]OpenAlert{}}
	opened := make([]alert, 0, len(holding))
	resolved := make([]string, 0, len(st.Open))
	for _, a := range holding {
		if prev, ok := st.Open[a.key]; ok {
			next.Open[a.key] = prev
			continue
		}
		next.Open[a.key] = OpenAlert{Since: now.UTC()}
		opened = append(opened, a)
	}
	for key := range st.Open {
		if _, ok := next.Open[key]; !ok {
			resolved = append(resolved, key)
		}
	}
	if len(opened) == 0 && len(resolved) == 0 {
		return
	}
	version := 0
	if meta.Stored {
		version = meta.Version
	}
	if _, err := s.alerts.Put(ctx, next, version, shared.ID{}); err != nil {
		if !errors.Is(err, platformsetting.ErrVersionConflict) {
			s.logger.Warn("feed relay: store open alerts", "error", err)
		}
		return
	}
	slices.Sort(resolved)
	for _, a := range opened {
		s.send(ctx, a.key, a.critical, a.subject, a.body)
	}
	for _, key := range resolved {
		why := "The condition has cleared."
		if direct {
			why = "The platform now receives its feeds directly, so the relay no longer applies."
		}
		s.send(ctx, key, false, resolvedPrefix+alertTitle(key),
			"<p>"+html.EscapeString(why)+"</p>"+consoleHint)
	}
}

const (
	consoleHint    = "<p>Open System &gt; Threat intelligence in the platform console for the full status.</p>"
	resolvedPrefix = "Feed relay: resolved: "
)

func (s *Service) send(ctx context.Context, key string, critical bool, subject, body string) {
	level := "warning"
	if critical {
		level = "critical"
	}
	s.logger.Warn("feed relay alert", "alert", "feed_relay_"+strings.SplitN(key, ":", 2)[0], "key", key, "level", level)
	if s.notifier == nil {
		return
	}
	if !strings.HasPrefix(subject, resolvedPrefix) {
		subject = "[" + strings.ToUpper(level) + "] " + subject
	}
	if err := s.notifier.NotifyAdmins(ctx, subject, body); err != nil {
		s.logger.Warn("feed relay: alert not delivered", "key", key)
	}
}

// alertTitle names an alert key in a "resolved" notice.
func alertTitle(key string) string {
	parts := strings.Split(key, ":")
	switch parts[0] {
	case AlertConditionOffline:
		return "no relay sensor online"
	case AlertConditionStale:
		if len(parts) > 1 {
			return parts[1] + " is out of date"
		}
	case AlertConditionFailed:
		if len(parts) > 2 {
			return parts[1] + " round failed (" + parts[2] + ")"
		}
	}
	return key
}

// conditions lists the alerts that hold now. direct reports that the
// platform is not in relay mode (nothing holds).
func (s *Service) conditions(ctx context.Context, now time.Time) ([]alert, bool, error) {
	st, err := s.Status(ctx)
	if err != nil {
		return nil, false, err
	}
	if st.Settings.Mode != ModeRelay {
		return nil, true, nil
	}
	since := st.Settings.UpdatedAt // grace after the mode or the relays changed
	out := make([]alert, 0, 1+2*len(st.Feeds))
	var lastSeen time.Time
	for _, rs := range st.Sensors {
		if rs.CanRelay && rs.Sensor != nil && rs.Sensor.LastSeenAt != nil && rs.Sensor.LastSeenAt.After(lastSeen) {
			lastSeen = *rs.Sensor.LastSeenAt
		}
	}
	seen := !lastSeen.IsZero() && now.Sub(lastSeen) < AlertRelayOffline
	if !seen && now.Sub(since) >= AlertRelayOffline {
		out = append(out, offlineAlert(st, lastSeen))
	}
	for _, fs := range st.Feeds {
		if a, ok := staleAlert(fs, since, now); ok {
			out = append(out, a)
		}
		failed, err := s.repo.LatestFailed(ctx, fs.Feed)
		if err != nil {
			return nil, false, err
		}
		if failed == nil || !slices.Contains(alertCodes, failed.ErrorCode) ||
			(fs.LastImport != nil && !failed.CreatedAt.After(fs.LastImport.CreatedAt)) {
			continue
		}
		detail := ""
		if failed.ErrorDetail != "" {
			detail = " (" + failed.ErrorDetail + ")"
		}
		out = append(out, alert{key: AlertConditionFailed + ":" + fs.Feed + ":" + failed.ErrorCode,
			critical: failed.ErrorCode != dom.CodeSignerRefused,
			subject:  "Feed relay: " + fs.Feed + " round failed: " + failed.ErrorCode,
			body: "<p>" + html.EscapeString(fs.Feed+": "+reasonText(failed.ErrorCode)+detail) + "</p>" +
				"<p>Nothing was applied: the platform keeps the data it has.</p>" + consoleHint})
	}
	return out, false, nil
}

func offlineAlert(st Status, lastSeen time.Time) alert {
	what := fmt.Sprintf("None of the %d designated relay sensors has been seen", len(st.Sensors))
	if !lastSeen.IsZero() {
		what += " since " + lastSeen.UTC().Format(time.RFC3339)
	} else {
		what += " in the last hour"
	}
	if len(st.Sensors) == 0 {
		what = "No relay sensor is designated"
		if st.Settings.Bootstrap {
			what = "The bundled sensor has not enrolled as the relay yet"
		}
	}
	return alert{key: AlertConditionOffline, critical: true,
		subject: "Feed relay: no relay sensor online",
		body: "<p>" + html.EscapeString(what) + ". The platform is in relay mode and receives no feed updates " +
			"(vulnerability data, KEV, EPSS, release notices) until a relay sensor is back.</p>" +
			"<p>Fix: start or reconnect a designated relay sensor, or designate another platform sensor that reports feed.relay@1. " +
			"If no sensor can reach the feeds, a super administrator can switch feed delivery to direct, or load an offline feed bundle. " +
			"The platform never does either by itself.</p>" +
			consoleHint}
}

func staleAlert(fs FeedStatus, since, now time.Time) (alert, bool) {
	limit, ok := alertAge[fs.Feed]
	if !ok {
		return alert{}, false
	}
	ref := since
	if fs.Freshness.PublishedAt != nil {
		ref = *fs.Freshness.PublishedAt
	}
	if now.Sub(ref) < limit {
		return alert{}, false
	}
	age := "no release has been applied"
	if fs.Freshness.PublishedAt != nil {
		age = fmt.Sprintf("the applied release is %d hours old", int(now.Sub(ref).Hours()))
	}
	return alert{key: AlertConditionStale + ":" + fs.Feed,
		subject: "Feed relay: " + fs.Feed + " is out of date",
		body: "<p>" + html.EscapeString(fmt.Sprintf("%s: %s (alert after %d hours).", fs.Feed, age, int(limit.Hours()))) + "</p>" +
			"<p>" + html.EscapeString(reasonText(fs.StaleReason)) + "</p>" + consoleHint}, true
}

// reasonText is the plain sentence of a stale reason, with the fix.
func reasonText(code string) string {
	switch code {
	case "":
		return "The relay is working; the feed publisher may not have issued a new release."
	case dom.CodeNoRelayDesignated:
		return "No relay sensor is designated: designate one in the console."
	case dom.CodeRelayOffline:
		return "No designated relay sensor is online: start or reconnect one."
	case dom.CodeSignerRefused:
		return "The job signer refused to sign the round: add the feed origin to SIGNER_FEED_ORIGINS or correct the feed address."
	case dom.CodeSensorRefused:
		return "The relay sensor refused the round (signature or origin rule on the sensor): check its SENSOR_FEED_RELAY_ORIGINS and the signer key it trusts."
	case dom.CodeUpstreamMissing:
		return "The relay could not find a file at the feed origin: check the feed address."
	case dom.CodePinMismatch:
		return "A relayed file did not match its pinned digest: the files may have been altered on the way. Check the relay sensor's network path."
	case dom.CodeVerifyFailed:
		return "The relayed files did not verify against the pinned feed keys: possible tampering. Check the relay sensor and the feed origin."
	case dom.CodeRollbackRefused:
		return "The relay delivered an older release than the one applied: possible replay. Check the relay sensor and the feed origin."
	case dom.CodeSpoolFull:
		return "The relay spool is full."
	}
	return "The last relay cycle failed (" + code + ")."
}

// newAlertStore is the store of the open alerts.
func newAlertStore(settings platformsetting.Repository) *consolesetting.Store[alertState] {
	return consolesetting.NewStore[alertState](settings, AlertsKey)
}
