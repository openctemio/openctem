// Package feedwatch makes a stale vulnerability corpus impossible to miss, in
// every feed mode (direct and relay).
//
// A controller checks every CheckEvery:
//   - each enabled feed (vulnerability bundle, KEV, EPSS): the age of the
//     data it holds against the feed's limit (feedstatus.StaleAfter), and
//     whether its imports fail (a refused bundle at once, other failures
//     after two runs);
//   - the corpus itself: the age of the newest published CVE record, and the
//     number of CVEs published in the last 24 hours against the daily
//     average of the 30 days before, which catches an import that "succeeds"
//     on old data.
//
// What holds is stored in one platform setting (StateKey), so a restart or a
// lease move does not alert twice. The platform administrators get one
// message when conditions open and one when they clear (e-mail and the alert
// webhook). Every signed-in user sees a banner while vulnerability data is
// older than its limit (Banner); the banner cannot be dismissed while the
// condition lasts.
//
// The watch reads only platform-wide data (feed status rows and the CVE
// corpus); it holds no organization data, and the banner says only whether
// the platform's data is current and since when.
//
// Design: server/docs/architecture/intelligence-feeds.md, "Freshness".
package feedwatch

import (
	"context"
	"errors"
	"fmt"
	"html"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/internal/app/consolesetting"
	"github.com/openctemio/openctem/server/internal/app/feedstatus"
	"github.com/openctemio/openctem/server/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/threatintel"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// StateKey is the platform_settings key of the watch state (written by the
// controller only).
const StateKey = "feed_freshness.state"

// CheckEvery is the controller interval.
const CheckEvery = 10 * time.Minute

// Limits.
const (
	// NewestRecordStaleAfter: the newest published CVE record may be this
	// old. About 280 CVEs are published a day, so a gap this long means the
	// corpus stopped moving even if every import "succeeds".
	NewestRecordStaleAfter = 12 * time.Hour
	// VolumeFloor: the CVEs published in the last 24 hours may not fall
	// under this share of the daily average of the 30 days before.
	VolumeFloor = 0.3
	// VolumeMinBaseline: the volume check runs only on a corpus that holds at
	// least this many CVEs a day on average (a partial or test corpus does
	// not alert).
	VolumeMinBaseline = 50.0
	// NeverLoadedGrace: a feed that never held data alerts once the watch
	// has run this long (the first import of a new install).
	NeverLoadedGrace = 2 * time.Hour
	// CheckStaleAfter: a stored state older than this means the watch is not
	// running, which the banner reports as unknown freshness.
	CheckStaleAfter = 3 * CheckEvery
	// minFailingAfter: a failing feed (other than a refused bundle) alerts
	// after two runs, and never before this.
	minFailingAfter = 30 * time.Minute
)

// Condition codes.
const (
	CodeDataStale       = "data_stale"
	CodeImportFailing   = "import_failing"
	CodeImportRefused   = "import_refused"
	CodeNewestRecordOld = "newest_record_old"
	CodeVolumeLow       = "volume_low"
	// CodeCheckNotRunning is reported by the banner only: the watch itself
	// has not run for CheckStaleAfter.
	CodeCheckNotRunning = "check_not_running"
)

// Condition is one problem that holds.
type Condition struct {
	Key    string `json:"key"`
	Code   string `json:"code"`
	Source string `json:"source,omitempty"`
	// Banner: the condition means vulnerability data is out of date, so
	// every signed-in user is told.
	Banner bool `json:"banner"`
	// AsOf is the date of the data the condition is about (nil: never
	// loaded or not a data age).
	AsOf *time.Time `json:"as_of,omitempty"`
	// Since is when the watch first saw the condition.
	Since time.Time `json:"since"`
	// Detail is a plain sentence for the administrators (never shown to
	// organization users).
	Detail string `json:"detail"`
}

// State is what the watch stores.
type State struct {
	FirstCheckedAt time.Time   `json:"first_checked_at"`
	CheckedAt      time.Time   `json:"checked_at"`
	DataAsOf       *time.Time  `json:"data_as_of,omitempty"`
	NewestRecordAt *time.Time  `json:"newest_record_at,omitempty"`
	Open           []Condition `json:"open"`
}

// CorpusStats is what the corpus checks read.
type CorpusStats struct {
	// NewestPublished is the newest publication date in the corpus that is
	// not in the future (nil: empty corpus).
	NewestPublished *time.Time
	// Published24h is the number of CVEs published in the 24 hours before
	// now; PublishedPrior30d in the 30 days before those.
	Published24h      int
	PublishedPrior30d int
}

// Feeds lists the feed views (*threat.IntelService).
type Feeds interface {
	FeedViews(ctx context.Context) ([]feedstatus.View, error)
}

// Corpus reads the corpus statistics (*postgres.CVECorpusRepository).
type Corpus interface {
	FreshnessStats(ctx context.Context, now time.Time) (CorpusStats, error)
}

// Notifier tells the platform administrators (e-mail and the alert webhook).
type Notifier interface {
	NotifyAdmins(ctx context.Context, subject, htmlBody string) error
}

// Service runs the checks and answers the banner.
type Service struct {
	feeds    Feeds
	corpus   Corpus
	notifier Notifier
	store    *consolesetting.Store[State]
	logger   *logger.Logger
	now      func() time.Time
}

// New creates the service. corpus and notifier may be nil.
func New(feeds Feeds, corpus Corpus, settings platformsetting.Repository, log *logger.Logger) *Service {
	return &Service{feeds: feeds, corpus: corpus, store: consolesetting.NewStore[State](settings, StateKey),
		logger: log, now: time.Now}
}

// SetNotifier wires the administrators' channel (nil: log only).
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) {
	s.now = now
	s.store.SetClock(now)
}

// Name, Interval, Exclusive and Reconcile make the service a controller.
func (s *Service) Name() string { return "feed-freshness" }

// Interval is CheckEvery.
func (s *Service) Interval() time.Duration { return CheckEvery }

// Exclusive: one replica checks and alerts.
func (s *Service) Exclusive() bool { return true }

// Reconcile runs one check. It returns the number of open conditions.
func (s *Service) Reconcile(ctx context.Context) (int, error) {
	n, err := s.Check(ctx)
	return n, err
}

// Check evaluates the conditions, stores them and tells the administrators
// about the ones that opened or cleared.
func (s *Service) Check(ctx context.Context) (int, error) {
	now := s.now().UTC()
	views, err := s.feeds.FeedViews(ctx)
	if err != nil {
		return 0, fmt.Errorf("feed freshness: read feeds: %w", err)
	}
	prev, meta, err := s.store.Fresh(ctx)
	if err != nil {
		return 0, fmt.Errorf("feed freshness: read state: %w", err)
	}
	first := prev.FirstCheckedAt
	if first.IsZero() {
		first = now
	}
	var stats *CorpusStats
	if s.corpus != nil && corpusLoaded(views) {
		st, cerr := s.corpus.FreshnessStats(ctx, now)
		if cerr != nil {
			s.logger.Warn("feed freshness: corpus statistics not read", "error", cerr)
		} else {
			stats = &st
		}
	}
	holding := Evaluate(views, stats, first, now)

	next := State{FirstCheckedAt: first, CheckedAt: now, Open: make([]Condition, 0, len(holding))}
	if v, ok := findView(views, feedstatus.SourceVulnfeed); ok {
		next.DataAsOf = v.DataAsOf
	}
	if stats != nil {
		next.NewestRecordAt = stats.NewestPublished
	}
	was := map[string]Condition{}
	for _, c := range prev.Open {
		was[c.Key] = c
	}
	var opened []Condition
	for _, c := range holding {
		if p, ok := was[c.Key]; ok {
			c.Since = p.Since
		} else {
			opened = append(opened, c)
		}
		next.Open = append(next.Open, c)
	}
	var resolved []Condition
	for _, c := range prev.Open {
		if !slices.ContainsFunc(next.Open, func(x Condition) bool { return x.Key == c.Key }) {
			resolved = append(resolved, c)
		}
	}
	version := 0
	if meta.Stored {
		version = meta.Version
	}
	// Stored before anything is sent: a failed write never alerts twice.
	if _, err := s.store.Put(ctx, next, version, shared.ID{}); err != nil {
		if errors.Is(err, platformsetting.ErrVersionConflict) {
			return len(next.Open), nil // another replica checked meanwhile
		}
		return len(next.Open), fmt.Errorf("feed freshness: store state: %w", err)
	}
	for _, c := range opened {
		s.logger.Warn("feed freshness alert", "alert", c.Key, "code", c.Code, "source", c.Source)
	}
	for _, c := range resolved {
		s.logger.Info("feed freshness alert resolved", "alert", c.Key)
	}
	s.send(ctx, opened, resolved, next.Open)
	return len(next.Open), nil
}

// Evaluate lists the conditions that hold now. stats is nil when the corpus
// checks do not apply (no applied bundle, or the statistics failed). first
// is when the watch first ran.
func Evaluate(views []feedstatus.View, stats *CorpusStats, first, now time.Time) []Condition {
	var out []Condition
	for _, v := range views {
		if !v.Enabled {
			continue // switched off by an administrator: nothing to expect
		}
		limit := feedstatus.StaleAfter(v.Source)
		if limit == 0 {
			continue
		}
		ref := v.LastSuccessAt
		if v.Source == feedstatus.SourceVulnfeed {
			ref = v.DataAsOf
		}
		switch {
		case ref == nil && now.Sub(first) >= NeverLoadedGrace:
			out = append(out, Condition{Key: CodeDataStale + ":" + v.Source, Code: CodeDataStale, Source: v.Source,
				Banner: true, Since: now,
				Detail: fmt.Sprintf("%s: no data has been loaded yet (limit %s).", feedName(v.Source), hours(limit))})
		case ref != nil && now.Sub(*ref) > limit:
			at := *ref
			out = append(out, Condition{Key: CodeDataStale + ":" + v.Source, Code: CodeDataStale, Source: v.Source,
				Banner: true, AsOf: &at, Since: now,
				Detail: fmt.Sprintf("%s: the data is %s old (limit %s).", feedName(v.Source), hours(now.Sub(at)), hours(limit))})
		}
		switch {
		case v.State == feedstatus.StateRefused:
			out = append(out, Condition{Key: CodeImportRefused + ":" + v.Source, Code: CodeImportRefused, Source: v.Source,
				Since: now, Detail: fmt.Sprintf("%s: the last import was refused (%s). Nothing was applied; the platform keeps the data it has.",
					feedName(v.Source), codeOr(v.ErrorCode))})
		case v.State == feedstatus.StateFailing || v.State == feedstatus.StateStale && v.LastSyncStatus == threatintel.SyncStateFailed.String():
			if v.FailingSince != nil && now.Sub(*v.FailingSince) >= failingAfter(v) {
				out = append(out, Condition{Key: CodeImportFailing + ":" + v.Source, Code: CodeImportFailing, Source: v.Source,
					Since: now, Detail: fmt.Sprintf("%s: imports have failed since %s (%s).",
						feedName(v.Source), v.FailingSince.UTC().Format(time.RFC3339), codeOr(v.ErrorCode))})
			}
		}
	}
	if stats == nil {
		return out
	}
	if stats.NewestPublished != nil && now.Sub(*stats.NewestPublished) > NewestRecordStaleAfter {
		at := *stats.NewestPublished
		out = append(out, Condition{Key: CodeNewestRecordOld, Code: CodeNewestRecordOld, Banner: true, AsOf: &at, Since: now,
			Detail: fmt.Sprintf("The newest CVE record in the corpus was published %s ago (limit %s): new vulnerabilities are not arriving.",
				hours(now.Sub(at)), hours(NewestRecordStaleAfter))})
	}
	baseline := float64(stats.PublishedPrior30d) / 30
	if baseline >= VolumeMinBaseline && float64(stats.Published24h) < VolumeFloor*baseline {
		out = append(out, Condition{Key: CodeVolumeLow, Code: CodeVolumeLow, Since: now,
			Detail: fmt.Sprintf("Only %d CVEs were published in the last 24 hours against a daily average of %.0f over the 30 days before: the corpus may be missing records.",
				stats.Published24h, baseline)})
	}
	return out
}

// failingAfter: two runs of the feed, at least minFailingAfter.
func failingAfter(v feedstatus.View) time.Duration {
	return max(2*v.Interval, minFailingAfter)
}

// corpusLoaded: the vulnerability bundle feed is on and applied a bundle,
// so the corpus checks mean something.
func corpusLoaded(views []feedstatus.View) bool {
	v, ok := findView(views, feedstatus.SourceVulnfeed)
	return ok && v.Enabled && v.Bundle != nil && v.Bundle.AppliedSequence > 0
}

func findView(views []feedstatus.View, source string) (feedstatus.View, bool) {
	for _, v := range views {
		if v.Source == source {
			return v, true
		}
	}
	return feedstatus.View{}, false
}

// Banner is what every signed-in user's console shows.
type Banner struct {
	// Stale: vulnerability data is older than its limit (or the watch is
	// not running), so new vulnerabilities may be missing.
	Stale bool
	// Codes are the banner conditions that hold (stable codes, sorted).
	Codes []string
	// StaleSince is the oldest data date among the banner conditions (nil:
	// never loaded, or unknown).
	StaleSince *time.Time
	// DataAsOf is when the vulnerability data held was published (the
	// applied bundle), for "data as of" lines.
	DataAsOf *time.Time
	// CheckedAt is when the watch last ran (nil: never).
	CheckedAt *time.Time
}

// Banner answers from the stored state (cached briefly; no feed or corpus
// query per request).
func (s *Service) Banner(ctx context.Context) (Banner, error) {
	st, meta, err := s.store.Get(ctx)
	if err != nil {
		return Banner{}, err
	}
	if !meta.Stored || st.CheckedAt.IsZero() {
		return Banner{}, nil // the watch has not run yet
	}
	checked := st.CheckedAt
	b := Banner{DataAsOf: st.DataAsOf, CheckedAt: &checked}
	codes := map[string]bool{}
	for _, c := range st.Open {
		if !c.Banner {
			continue
		}
		codes[c.Code] = true
		if c.AsOf != nil && (b.StaleSince == nil || c.AsOf.Before(*b.StaleSince)) {
			at := *c.AsOf
			b.StaleSince = &at
		}
	}
	if s.now().Sub(st.CheckedAt) > CheckStaleAfter {
		codes[CodeCheckNotRunning] = true
	}
	for c := range codes {
		b.Codes = append(b.Codes, c)
	}
	slices.Sort(b.Codes)
	b.Stale = len(b.Codes) > 0
	return b, nil
}

// Open lists the open conditions (platform administrators only: the
// details name feeds, error codes and dates).
func (s *Service) Open(ctx context.Context) ([]Condition, error) {
	st, _, err := s.store.Get(ctx)
	if err != nil {
		return nil, err
	}
	return st.Open, nil
}

// send writes one message for what opened and one for what cleared.
func (s *Service) send(ctx context.Context, opened, resolved, open []Condition) {
	if s.notifier == nil || (len(opened) == 0 && len(resolved) == 0) {
		return
	}
	if len(opened) > 0 {
		level, subject := "WARNING", "Threat intelligence feed problem"
		if slices.ContainsFunc(opened, func(c Condition) bool { return c.Banner || c.Code == CodeImportRefused }) {
			level, subject = "CRITICAL", "Vulnerability data is out of date or not updating"
		}
		var b strings.Builder
		b.WriteString("<p>New:</p><ul>")
		for _, c := range opened {
			b.WriteString("<li>" + html.EscapeString(c.Detail) + "</li>")
		}
		b.WriteString("</ul>")
		if len(open) > len(opened) {
			b.WriteString("<p>Still open:</p><ul>")
			for _, c := range open {
				if !slices.ContainsFunc(opened, func(x Condition) bool { return x.Key == c.Key }) {
					b.WriteString("<li>" + html.EscapeString(c.Detail) + "</li>")
				}
			}
			b.WriteString("</ul>")
		}
		b.WriteString("<p>While vulnerability data is out of date every user sees a banner, and new vulnerabilities may not be matched or alerted.</p>" + consoleHint)
		s.deliver(ctx, "["+level+"] "+subject, b.String())
	}
	if len(resolved) > 0 {
		var b strings.Builder
		b.WriteString("<p>Cleared:</p><ul>")
		for _, c := range resolved {
			b.WriteString("<li>" + html.EscapeString(c.Detail) + "</li>")
		}
		b.WriteString("</ul>" + consoleHint)
		s.deliver(ctx, "Threat intelligence feeds: resolved", b.String())
	}
}

const consoleHint = "<p>Open System &gt; Threat intelligence in the platform console for the full status.</p>"

func (s *Service) deliver(ctx context.Context, subject, body string) {
	if err := s.notifier.NotifyAdmins(ctx, subject, body); err != nil {
		s.logger.Warn("feed freshness alert not delivered", "subject", subject)
	}
}

func feedName(source string) string {
	switch source {
	case feedstatus.SourceVulnfeed:
		return "Vulnerability bundle feed"
	case feedstatus.SourceKEV:
		return "CISA KEV"
	case feedstatus.SourceEPSS:
		return "EPSS"
	}
	return source
}

func codeOr(code string) string {
	if code == "" {
		return feedstatus.CodeFailed
	}
	return code
}

// hours renders a duration as whole hours (minutes under one hour).
func hours(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	return fmt.Sprintf("%d hours", int(d.Hours()))
}
