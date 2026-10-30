package coverage

import (
	"context"
	"fmt"
	"html"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Platform-side failures (docs/rfcs/RFC-093-asset-coverage.md, "Platform-side
// failures"): a pair whose check did not run (no task carried it, the run
// stalled, the task, tool, sensor network or proxy failed) is the operator's
// concern, never the organization's "keeps failing" alert. Every settled one
// is counted in a metric; the fleet-wide count of pairs failing that way 3
// times in a row is a gauge and goes to the platform administrators' alert
// channel (e-mail and the alert webhook) when it appears or gets clearly
// worse. Counts only: no tenant, asset or target leaves the platform.

// OperatorNotifier tells the platform administrators (systemstatus.Notifier:
// the e-mail and the alert webhook).
type OperatorNotifier interface {
	NotifyAdmins(ctx context.Context, subject, htmlBody string) error
}

type operatorAlerts struct {
	reader   covdom.PlatformFailureReader
	notifier OperatorNotifier
	mu       sync.Mutex
	lastRead time.Time
	sent     map[string]operatorSent // capability -> last send
}

type operatorSent struct {
	pairs int
	at    time.Time
}

// EnableOperatorAlerts wires the platform-side failure signal. notifier may
// be nil (metric and log only).
func (s *Service) EnableOperatorAlerts(reader covdom.PlatformFailureReader, notifier OperatorNotifier) {
	if reader == nil {
		return
	}
	s.operator = &operatorAlerts{reader: reader, notifier: notifier, sent: map[string]operatorSent{}}
}

// countPlatformFailures counts the platform-side pairs of a settled run.
func countPlatformFailures(capability string, failed []covdom.FailedPair) {
	for _, f := range failed {
		if covdom.IsPlatformSide(f.Outcome) {
			metrics.AssetCoveragePlatformFailuresTotal.WithLabelValues(capability, covdom.PlatformOutcomeLabel(f.Outcome)).Inc()
		}
	}
}

// operatorPass reads the fleet-wide platform failures at most every
// DetectEvery, sets the gauge and alerts the administrators per capability
// when its count appears or gets clearly worse (the organization alerts'
// rule: at least double and AlertMinRise more than last sent, at most once
// per AlertRenotifyAfter). A capability back to zero is re-armed.
func (s *Service) operatorPass(ctx context.Context) {
	o := s.operator
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := s.now()
	if !o.lastRead.IsZero() && now.Sub(o.lastRead) < DetectEvery {
		return
	}
	o.lastRead = now
	counts, err := o.reader.PlatformFailures(ctx)
	if err != nil {
		s.logger.Warn("coverage platform failures not read", "error", logger.SanitizeError(err))
		return
	}
	metrics.AssetCoveragePlatformFailingPairs.Reset()
	byCap := map[string][]covdom.PlatformFailureCount{}
	for _, c := range counts {
		metrics.AssetCoveragePlatformFailingPairs.WithLabelValues(c.Capability, c.Outcome).Set(float64(c.Pairs))
		byCap[c.Capability] = append(byCap[c.Capability], c)
	}
	for capability := range o.sent {
		if _, ok := byCap[capability]; !ok {
			delete(o.sent, capability)
		}
	}
	caps := make([]string, 0, len(byCap))
	for c := range byCap {
		caps = append(caps, c)
	}
	sort.Strings(caps)
	for _, capability := range caps {
		list := byCap[capability]
		pairs := 0
		for _, c := range list {
			pairs += c.Pairs
		}
		prev, had := o.sent[capability]
		if had && !operatorWorse(prev, pairs, now) {
			continue
		}
		o.sent[capability] = operatorSent{pairs: pairs, at: now}
		subject, body := operatorMessage(capability, list, pairs)
		s.logger.Warn("coverage cannot run on the platform side", "alert", "coverage_platform_failures",
			"capability", capability, "pairs", pairs)
		if o.notifier == nil {
			continue
		}
		if err := o.notifier.NotifyAdmins(ctx, subject, body); err != nil {
			s.logger.Warn("coverage platform failure alert not sent", "capability", capability, "error", logger.SanitizeError(err))
		}
	}
}

// operatorWorse reports whether a capability's count got clearly worse
// since it was last sent.
func operatorWorse(prev operatorSent, pairs int, now time.Time) bool {
	return pairs >= 2*prev.pairs && pairs-prev.pairs >= covdom.AlertMinRise && now.Sub(prev.at) >= covdom.AlertRenotifyAfter
}

// operatorMessage is the administrators' alert of one capability.
func operatorMessage(capability string, list []covdom.PlatformFailureCount, pairs int) (string, string) {
	tenants := 0
	parts := make([]string, 0, len(list))
	for _, c := range list {
		tenants = max(tenants, c.Tenants)
		parts = append(parts, fmt.Sprintf("<li>%s: %d</li>", html.EscapeString(c.Outcome), c.Pairs))
	}
	subject := fmt.Sprintf("[WARNING] Coverage %s cannot run on %d assets (platform side)", capability, pairs)
	body := fmt.Sprintf("<p>Automatic coverage of <strong>%s</strong> failed %d or more times in a row on the platform "+
		"or sensor side for %d assets (at least %d organizations). The check did not run, so this says nothing about "+
		"the assets, and the organizations are not told their assets are failing.</p><ul>%s</ul>"+
		"<p>Check the sensor fleet, proxy health and scan runs in the platform console.</p>",
		html.EscapeString(capability), covdom.PlatformFailingStreak, pairs, tenants, strings.Join(parts, ""))
	return subject, body
}
