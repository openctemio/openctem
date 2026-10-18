// Package platformalert is the platform's alert webhook: an HTTPS address,
// set by a platform administrator in the console (Settings > Alerts), that
// receives the alerts the API raises for administrators (low disk space,
// stale backups, expiring certificates, console setting changes) next to
// the e-mail. A chat or paging tool connects to it.
//
// Host probes that must work while the API is down stay with the
// installer's monitoring; this is the API's own channel.
//
// Security:
//   - The address and the signing secret are encrypted with
//     APP_ENCRYPTION_KEY and write-only (an incoming-webhook address is a
//     credential). Reads return the host name only.
//   - Every request goes through the SSRF-guarded client (pkg/httpsec):
//     internal, loopback and metadata addresses are refused at dial time,
//     unless the operator allowed private egress on the server.
//   - Redirecting or silencing alerts hides incidents, so a change needs a
//     super admin, a fresh confirmation, a reason, a critical audit row and
//     a notice to every administrator (sent to the old and new address).
//   - With a secret, each delivery carries X-OpenCTEM-Timestamp and
//     X-OpenCTEM-Signature: sha256=HMAC(secret, timestamp + "." + body).
//
// Design: docs/rfcs/RFC-079-console-platform-settings.md.
package platformalert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SettingKey is the platform_settings key.
const SettingKey = "alerts.webhook"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.alert_webhook_changed"

// Delivery headers.
const (
	HeaderTimestamp = "X-OpenCTEM-Timestamp"
	HeaderSignature = "X-OpenCTEM-Signature"
)

// deliveryTimeout bounds one delivery.
const deliveryTimeout = 10 * time.Second

// Errors of the service.
var (
	ErrInvalid       = fmt.Errorf("%w: invalid alert webhook", shared.ErrValidation)
	ErrNoActor       = errors.New("an alert webhook change needs an administrator")
	ErrNotConfigured = errors.New("no alert webhook is set")
	// ErrDelivery: the receiver could not be reached or refused the alert.
	ErrDelivery = errors.New("the alert could not be delivered")
)

type stored struct {
	Enabled         bool   `json:"enabled"`
	URLEncrypted    string `json:"url_encrypted,omitempty"`
	URLHost         string `json:"url_host,omitempty"`
	SecretEncrypted string `json:"secret_encrypted,omitempty"`
}

// Settings is what an administrator sees: never the address or the secret.
type Settings struct {
	Enabled   bool
	URLSet    bool
	URLHost   string
	SecretSet bool
	Version   int
	UpdatedAt time.Time
	UpdatedBy *shared.ID
}

// Input is a change. URL and Secret: nil keeps the stored value, "" removes
// it, any other value replaces it.
type Input struct {
	Enabled bool
	URL     *string
	Secret  *string
	Reason  string
}

// Message is one alert.
type Message struct {
	Type    string `json:"type"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
	SentAt  string `json:"sent_at"`
}

// Service reads and changes the webhook and delivers alerts to it.
type Service struct {
	store     *consolesetting.Store[stored]
	encryptor crypto.Encryptor
	recorder  *consolesetting.Recorder
	client    *http.Client
	validate  func(string) error
	now       func() time.Time
	log       *logger.Logger
}

// NewService creates the service.
func NewService(repo platformsetting.Repository, encryptor crypto.Encryptor, recorder *consolesetting.Recorder, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{
		store: consolesetting.NewStore[stored](repo, SettingKey), encryptor: encryptor, recorder: recorder,
		client: httpsec.SafeHTTPClient(deliveryTimeout),
		validate: func(raw string) error {
			_, err := httpsec.ValidateURL(raw)
			return err
		},
		now: time.Now, log: log.With("service", "platform_alert"),
	}
}

// SetHTTPClient replaces the delivery client and the address check (tests:
// a local receiver the SSRF guard would refuse).
func (s *Service) SetHTTPClient(c *http.Client, validate func(string) error) {
	s.client, s.validate = c, validate
}

// Get returns the settings without the address or the secret.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	st, m, err := s.store.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	return Settings{Enabled: st.Enabled, URLSet: st.URLEncrypted != "", URLHost: st.URLHost,
		SecretSet: st.SecretEncrypted != "", Version: m.Version, UpdatedAt: m.UpdatedAt, UpdatedBy: m.UpdatedBy}, nil
}

// checkURL refuses anything but a plain https address with a host, no
// credentials in it.
func (s *Service) checkURL(raw string) (string, error) {
	if len(raw) > 2048 {
		return "", fmt.Errorf("%w: the address is too long", ErrInvalid)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("%w: use an https:// address with a host name, without credentials", ErrInvalid)
	}
	if err := s.validate(raw); err != nil {
		// Never echo the address: it is a credential.
		return "", fmt.Errorf("%w: the address is not allowed (internal or unresolvable host)", ErrInvalid)
	}
	return strings.ToLower(u.Hostname()), nil
}

// secretRE: a printable secret without spaces.
var secretRE = regexp.MustCompile(`^[\x21-\x7e]{16,256}$`)

// Update replaces the webhook. The caller checked the actor's role and a
// fresh confirmation. expectedVersion is the version read (0: nothing
// stored). The notice of the change goes out after it is stored, so it
// reaches the new address too; the previous address gets it first.
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, in Input, expectedVersion int, ip, userAgent string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	reason, err := consolesetting.CheckReason(in.Reason)
	if err != nil {
		return Settings{}, err
	}
	prev, _, err := s.store.Fresh(ctx)
	if err != nil {
		return Settings{}, err
	}
	next := prev
	next.Enabled = in.Enabled
	urlChanged, secretChanged := false, false
	if in.URL != nil {
		urlChanged = true
		next.URLEncrypted, next.URLHost = "", ""
		if v := strings.TrimSpace(*in.URL); v != "" {
			host, err := s.checkURL(v)
			if err != nil {
				return Settings{}, err
			}
			enc, err := s.encryptor.EncryptString(v)
			if err != nil {
				return Settings{}, fmt.Errorf("encrypt alert webhook address: %w", err)
			}
			next.URLEncrypted, next.URLHost = enc, host
		}
	}
	if in.Secret != nil {
		secretChanged = true
		next.SecretEncrypted = ""
		if v := strings.TrimSpace(*in.Secret); v != "" {
			if !secretRE.MatchString(v) {
				return Settings{}, fmt.Errorf("%w: the signing secret must be 16-256 printable characters without spaces", ErrInvalid)
			}
			enc, err := s.encryptor.EncryptString(v)
			if err != nil {
				return Settings{}, fmt.Errorf("encrypt alert webhook secret: %w", err)
			}
			next.SecretEncrypted = enc
		}
	}
	if next.Enabled && next.URLEncrypted == "" {
		return Settings{}, fmt.Errorf("%w: set an address to turn the webhook on", ErrInvalid)
	}
	// Tell the previous receiver before it stops getting alerts.
	if prev.Enabled && prev.URLEncrypted != "" && (urlChanged || !next.Enabled) {
		s.deliverStored(ctx, prev, Message{Type: "openctem.alert",
			Subject: "Alert webhook changed by " + actor.Email(),
			Text:    "This address no longer receives the platform's alerts. Reason: " + reason})
	}
	if _, err := s.store.Put(ctx, next, expectedVersion, actor.ID()); err != nil {
		return Settings{}, err
	}
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionChanged, Key: SettingKey, Title: "Alert webhook",
		Method: "PUT", Path: "/api/v1/admin/settings/alerts", Reason: reason,
		Details: map[string]any{
			"previous_enabled": prev.Enabled, "enabled": next.Enabled,
			"previous_host": prev.URLHost, "host": next.URLHost,
			// Never the values: only that they changed.
			"url_changed": urlChanged, "secret_changed": secretChanged,
		},
		Critical: true, Notify: true,
	}, ip, userAgent)
	return s.Get(ctx)
}

// NotifyAdmins delivers an alert to the webhook when one is on (the
// systemstatus and consolesetting notifier). It returns at once; delivery
// runs in the background with its own timeout.
func (s *Service) NotifyAdmins(ctx context.Context, subject, htmlBody string) error {
	st, _, err := s.store.Get(ctx)
	if err != nil {
		return fmt.Errorf("read alert webhook: %w", err)
	}
	if !st.Enabled || st.URLEncrypted == "" {
		return nil
	}
	msg := Message{Type: "openctem.alert", Subject: subject, Text: textOf(htmlBody)}
	go s.deliverStored(context.WithoutCancel(ctx), st, msg)
	return nil
}

// SendTest delivers a test alert to the stored webhook and reports the
// outcome. The receiver's answer is not returned (it could echo anything);
// the status code is logged.
func (s *Service) SendTest(ctx context.Context, actor *admin.AdminUser) error {
	if actor == nil {
		return ErrNoActor
	}
	st, _, err := s.store.Fresh(ctx)
	if err != nil {
		return err
	}
	if st.URLEncrypted == "" {
		return ErrNotConfigured
	}
	return s.deliverStoredErr(ctx, st, Message{Type: "openctem.alert.test",
		Subject: "Test alert", Text: "A test alert sent by " + actor.Email() + " from the platform console."})
}

func (s *Service) deliverStored(ctx context.Context, st stored, msg Message) {
	if err := s.deliverStoredErr(ctx, st, msg); err != nil {
		s.log.Warn("alert webhook delivery failed", "alert", "alert_webhook_failed", "host", st.URLHost, "error", err)
	}
}

func (s *Service) deliverStoredErr(ctx context.Context, st stored, msg Message) error {
	target, err := s.encryptor.DecryptString(st.URLEncrypted)
	if err != nil {
		return fmt.Errorf("alert webhook address does not decrypt (was APP_ENCRYPTION_KEY rotated without rekey?): %w", ErrDelivery)
	}
	secret := ""
	if st.SecretEncrypted != "" {
		if secret, err = s.encryptor.DecryptString(st.SecretEncrypted); err != nil {
			// Never send unsigned when a secret is set.
			return fmt.Errorf("alert webhook secret does not decrypt: %w", ErrDelivery)
		}
	}
	return s.deliver(ctx, target, secret, msg)
}

func (s *Service) deliver(ctx context.Context, target, secret string, msg Message) error {
	now := s.now().UTC()
	msg.SentAt = now.Format(time.RFC3339)
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, deliveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return ErrDelivery
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OpenCTEM-Alerts/1")
	if secret != "" {
		ts := strconv.FormatInt(now.Unix(), 10)
		req.Header.Set(HeaderTimestamp, ts)
		req.Header.Set(HeaderSignature, "sha256="+Sign(secret, ts, body))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		// The transport error can contain the address; keep it out.
		return fmt.Errorf("%w: receiver unreachable", ErrDelivery)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: receiver answered HTTP %d", ErrDelivery, resp.StatusCode)
	}
	return nil
}

// Sign is the delivery signature: hex HMAC-SHA256 of timestamp + "." + body.
func Sign(secret, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(timestamp))
	m.Write([]byte("."))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

var tagRE = regexp.MustCompile(`<[^>]*>`)

// textOf turns an alert's HTML body into plain text.
func textOf(htmlBody string) string {
	t := strings.NewReplacer("</p>", "\n", "</li>", "\n", "<br>", "\n").Replace(htmlBody)
	t = html.UnescapeString(tagRE.ReplaceAllString(t, ""))
	lines := strings.Split(t, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
