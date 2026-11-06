// Package consolesetting holds the shared mechanics of a platform setting
// that moved from an environment variable into the platform console:
//
//   - a typed value stored in platform_settings, read through a short cache,
//     so a change made on one replica applies on every replica within
//     CacheTTL, without a restart;
//   - compare-and-swap writes (a stale form is refused, never merged);
//   - the record of a change: an admin audit row that carries the reason and
//     never a secret, and a notice to every active administrator.
//
// Each setting keeps its own package for its rules (validation, the
// environment lock or ceiling, what "test" means); this package only removes
// the repetition.
//
// Design: docs/rfcs/RFC-079-console-platform-settings.md.
package consolesetting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CacheTTL bounds how long a replica serves a value it read.
const CacheTTL = 15 * time.Second

// MaxReasonRunes bounds the reason of a guarded change.
const MaxReasonRunes = 500

// ErrReasonRequired refuses a guarded change without a usable reason.
var ErrReasonRequired = errors.New("a reason is required (1-500 characters, one paragraph)")

// CheckReason trims the reason of a guarded change and checks it: present,
// at most MaxReasonRunes, no control characters (it is shown in e-mails and
// the audit log).
func CheckReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || utf8.RuneCountInString(reason) > MaxReasonRunes {
		return "", ErrReasonRequired
	}
	for _, r := range reason {
		if unicode.IsControl(r) {
			return "", ErrReasonRequired
		}
	}
	return reason, nil
}

// Meta describes the stored row: nothing stored is the zero value.
type Meta struct {
	Stored    bool
	Version   int
	Source    string
	UpdatedAt time.Time
	UpdatedBy *shared.ID
}

// Store is one typed setting.
type Store[T any] struct {
	key  string
	repo platformsetting.Repository
	now  func() time.Time

	mu       sync.Mutex
	loaded   bool
	val      T
	meta     Meta
	cachedAt time.Time
}

// NewStore creates the store of key. repo may be nil: every read then
// reports nothing stored and every write fails.
func NewStore[T any](repo platformsetting.Repository, key string) *Store[T] {
	return &Store[T]{key: key, repo: repo, now: time.Now}
}

// Key is the platform_settings key.
func (s *Store[T]) Key() string { return s.key }

// SetClock replaces the clock (tests).
func (s *Store[T]) SetClock(now func() time.Time) { s.now = now }

// Get returns the stored value (cached for CacheTTL). Nothing stored is the
// zero value with Meta.Stored false.
func (s *Store[T]) Get(ctx context.Context) (T, Meta, error) {
	s.mu.Lock()
	if s.loaded && s.now().Sub(s.cachedAt) < CacheTTL {
		v, m := s.val, s.meta
		s.mu.Unlock()
		return v, m, nil
	}
	s.mu.Unlock()
	return s.Fresh(ctx)
}

// Fresh reads the stored value, bypassing the cache.
func (s *Store[T]) Fresh(ctx context.Context) (T, Meta, error) {
	var zero T
	if s.repo == nil {
		return zero, Meta{}, nil
	}
	row, err := s.repo.Get(ctx, s.key)
	if errors.Is(err, platformsetting.ErrNotFound) {
		s.remember(zero, Meta{})
		return zero, Meta{}, nil
	}
	if err != nil {
		return zero, Meta{}, err
	}
	var v T
	if err := json.Unmarshal(row.Value, &v); err != nil {
		return zero, Meta{}, fmt.Errorf("decode %s: %w", s.key, err)
	}
	m := Meta{Stored: true, Version: row.Version, Source: row.Source, UpdatedAt: row.UpdatedAt, UpdatedBy: row.UpdatedBy}
	s.remember(v, m)
	return v, m, nil
}

func (s *Store[T]) remember(v T, m Meta) {
	s.mu.Lock()
	s.loaded, s.val, s.meta, s.cachedAt = true, v, m, s.now()
	s.mu.Unlock()
}

// Put stores v when the stored version is expectedVersion (0: nothing
// stored). A stale version is platformsetting.ErrVersionConflict.
func (s *Store[T]) Put(ctx context.Context, v T, expectedVersion int, by shared.ID) (Meta, error) {
	if s.repo == nil {
		return Meta{}, errors.New("console setting store is not configured")
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return Meta{}, err
	}
	now := s.now().UTC()
	var m Meta
	if expectedVersion == 0 {
		created, err := s.repo.CreateIfAbsent(ctx, s.key, platformsetting.State{
			Value: raw, Version: 1, Source: platformsetting.SourceConsole, UpdatedBy: &by, UpdatedAt: now,
		})
		if err != nil {
			return Meta{}, err
		}
		if !created {
			return Meta{}, platformsetting.ErrVersionConflict
		}
		m = Meta{Stored: true, Version: 1, Source: platformsetting.SourceConsole, UpdatedAt: now, UpdatedBy: &by}
	} else {
		st, err := s.repo.Update(ctx, s.key, raw, expectedVersion, by, now)
		if err != nil {
			return Meta{}, err
		}
		m = Meta{Stored: true, Version: st.Version, Source: platformsetting.SourceConsole, UpdatedAt: now, UpdatedBy: &by}
	}
	s.remember(v, m)
	return m, nil
}

// Notifier tells every active platform administrator (e-mail, and the alert
// webhook when one is set). It must not block on slow delivery.
type Notifier interface {
	NotifyAdmins(ctx context.Context, subject, htmlBody string) error
}

// Change is one change to record.
type Change struct {
	// Action is the admin audit action, e.g. platform.captcha_changed.
	Action string
	// Key is the platform_settings key (the audit resource).
	Key string
	// Title names the setting in the notice ("CAPTCHA keys").
	Title string
	// Method and Path are the request that made the change.
	Method, Path string
	// Reason is the administrator's reason (guarded settings).
	Reason string
	// Details are the old and new values. Never a secret: a secret is
	// recorded as "<name>_changed": true.
	Details map[string]any
	// Critical marks a guarded (class C) change; others are high.
	Critical bool
	// Notify sends the notice to every administrator.
	Notify bool
}

// Recorder writes the audit row and the notice of a change.
type Recorder struct {
	audit    admin.AuditLogRepository
	notifier Notifier
	appName  string
	log      *logger.Logger
}

// NewRecorder creates a recorder. audit and notifier may be nil (tests).
func NewRecorder(audit admin.AuditLogRepository, notifier Notifier, appName string, log *logger.Logger) *Recorder {
	if log == nil {
		log = logger.NewNop()
	}
	return &Recorder{audit: audit, notifier: notifier, appName: appName, log: log.With("component", "console_setting")}
}

// SetNotifier wires the administrator notice after construction.
func (r *Recorder) SetNotifier(n Notifier) {
	if r != nil {
		r.notifier = n
	}
}

// Record writes the change. Failures are logged, never returned: the change
// is already stored, and the WARN line is the alert of last resort.
func (r *Recorder) Record(ctx context.Context, actor *admin.AdminUser, ch Change, ip, userAgent string) {
	if r == nil || actor == nil {
		return
	}
	r.log.Warn("platform setting changed", "alert", "platform_setting_changed", "key", ch.Key,
		"action", ch.Action, "admin_id", actor.ID().String())
	if r.audit != nil {
		body := map[string]any{}
		for k, v := range ch.Details {
			body[k] = v
		}
		if ch.Reason != "" {
			body["reason"] = ch.Reason
		}
		b := admin.NewAuditLogBuilder(actor, ch.Action).
			Resource("platform_setting", nil, ch.Key).
			Context(ip, userAgent).
			Request(ch.Method, ch.Path, body)
		if ch.Critical {
			b = b.Critical()
		} else {
			b = b.High()
		}
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := r.audit.Create(actx, b.Build()); err != nil {
			r.log.Error("write admin audit for a platform setting change", "key", ch.Key, "error", err)
		}
	}
	if ch.Notify && r.notifier != nil {
		name := r.appName
		if name == "" {
			name = "OpenCTEM"
		}
		who := strings.NewReplacer("\r", "", "\n", "").Replace(actor.Email())
		subject := fmt.Sprintf("%s changed by %s", ch.Title, who)
		reason := ch.Reason
		if reason == "" {
			reason = "-"
		}
		body := fmt.Sprintf(`<p><strong>%s</strong> changed the platform setting <strong>%s</strong> on %s.</p>
<ul><li>Reason: %s</li><li>Time: %s</li><li>IP address: %s</li></ul>
<p>If this change was not expected, review it in the admin console (Security &gt; Admin activity).</p>`,
			html.EscapeString(who), html.EscapeString(ch.Title), html.EscapeString(name),
			html.EscapeString(reason), html.EscapeString(time.Now().UTC().Format(time.RFC1123)), html.EscapeString(ip))
		nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := r.notifier.NotifyAdmins(nctx, subject, body); err != nil {
			r.log.Warn("notify administrators of a platform setting change", "key", ch.Key, "error", err)
		}
	}
}
