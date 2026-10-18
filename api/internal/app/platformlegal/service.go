// Package platformlegal is the operator's legal information (links to the
// terms and privacy policy, the built-in legal pages' values, the
// security.txt contact), set by a platform administrator in the admin
// console (Settings > Legal) instead of LEGAL_* / SECURITY_* environment
// variables of the web console. Nothing in it is secret: the web console reads
// it through a public endpoint to render the sign-in notice, the legal pages
// and /.well-known/security.txt.
//
// Design: docs/rfcs/RFC-079-console-platform-settings.md.
package platformlegal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SettingKey is the platform_settings key.
const SettingKey = "legal"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.legal_settings_changed"

const cacheTTL = 15 * time.Second

// Errors of the service.
var (
	ErrNoActor = errors.New("legal settings change needs an administrator")
	ErrInvalid = errors.New("invalid legal settings")
)

// Settings is the operator's legal information. Empty fields mean the web
// console's defaults (OpenCTEM contacts, marked placeholders).
type Settings struct {
	TermsURL           string `json:"terms_url"`
	PrivacyURL         string `json:"privacy_url"`
	PagesEnabled       bool   `json:"pages_enabled"`
	OrganizationName   string `json:"organization_name"`
	ServiceName        string `json:"service_name"`
	ContactEmail       string `json:"contact_email"`
	WebsiteURL         string `json:"website_url"`
	DocsURL            string `json:"docs_url"`
	Address            string `json:"address"`
	Jurisdiction       string `json:"jurisdiction"`
	EffectiveDate      string `json:"effective_date"`
	SecurityContact    string `json:"security_contact"`
	SecurityPolicyURL  string `json:"security_policy_url"`
	SecurityTxtDisable bool   `json:"security_txt_disabled"`
}

// State is the stored settings with their version.
type State struct {
	Settings  Settings
	Version   int
	UpdatedAt time.Time
}

func trim(s *Settings) {
	for _, p := range []*string{&s.TermsURL, &s.PrivacyURL, &s.OrganizationName, &s.ServiceName, &s.ContactEmail,
		&s.WebsiteURL, &s.DocsURL, &s.Address, &s.Jurisdiction, &s.EffectiveDate, &s.SecurityContact, &s.SecurityPolicyURL} {
		*p = strings.TrimSpace(*p)
	}
}

func httpsURL(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && len(v) <= 2048
}

func emailAddr(v string) bool {
	a, err := mail.ParseAddress(v)
	return err == nil && a.Name == "" && len(v) <= 254
}

// Validate checks every field: links are https URLs (a link the sign-in page
// shows must not be javascript: or plain http), addresses are bare e-mail
// addresses, the security contact is an address or an https URL, and text is
// one line of bounded length.
func (s Settings) Validate() error {
	for name, v := range map[string]string{"terms_url": s.TermsURL, "privacy_url": s.PrivacyURL, "website_url": s.WebsiteURL,
		"docs_url": s.DocsURL, "security_policy_url": s.SecurityPolicyURL} {
		if v != "" && !httpsURL(v) {
			return fmt.Errorf("%w: %s must be an https URL", ErrInvalid, name)
		}
	}
	if s.ContactEmail != "" && !emailAddr(s.ContactEmail) {
		return fmt.Errorf("%w: contact_email must be an e-mail address", ErrInvalid)
	}
	if s.SecurityContact != "" && !emailAddr(s.SecurityContact) && !httpsURL(s.SecurityContact) {
		return fmt.Errorf("%w: security_contact must be an e-mail address or an https URL", ErrInvalid)
	}
	for name, v := range map[string]string{"organization_name": s.OrganizationName, "service_name": s.ServiceName,
		"address": s.Address, "jurisdiction": s.Jurisdiction, "effective_date": s.EffectiveDate} {
		if len(v) > 300 || strings.ContainsAny(v, "\r\n<>") {
			return fmt.Errorf("%w: %s must be one line of at most 300 characters, without < or >", ErrInvalid, name)
		}
	}
	return nil
}

// Service reads and changes the legal settings.
type Service struct {
	repo  platformsetting.Repository
	audit admin.AuditLogRepository
	log   *logger.Logger
	now   func() time.Time

	mu       sync.Mutex
	cached   *State
	cachedAt time.Time
}

// NewService creates the service. audit may be nil (tests).
func NewService(repo platformsetting.Repository, audit admin.AuditLogRepository, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, audit: audit, log: log.With("service", "platform_legal"), now: time.Now}
}

// Get returns the stored settings (cached); nothing stored is the zero value.
func (s *Service) Get(ctx context.Context) (State, error) {
	s.mu.Lock()
	if s.cached != nil && s.now().Sub(s.cachedAt) < cacheTTL {
		st := *s.cached
		s.mu.Unlock()
		return st, nil
	}
	s.mu.Unlock()
	row, err := s.repo.Get(ctx, SettingKey)
	var st State
	switch {
	case errors.Is(err, platformsetting.ErrNotFound):
	case err != nil:
		return State{}, err
	default:
		if err := json.Unmarshal(row.Value, &st.Settings); err != nil {
			return State{}, fmt.Errorf("decode legal settings: %w", err)
		}
		st.Version, st.UpdatedAt = row.Version, row.UpdatedAt
	}
	s.mu.Lock()
	s.cached, s.cachedAt = &st, s.now()
	s.mu.Unlock()
	return st, nil
}

// Update replaces the settings. The caller has checked the actor's role and a
// fresh authenticator code. Audited (critical) with the values.
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, in Settings, expectedVersion int, ip, userAgent string) (State, error) {
	if actor == nil {
		return State{}, ErrNoActor
	}
	trim(&in)
	if err := in.Validate(); err != nil {
		return State{}, err
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return State{}, err
	}
	now := s.now().UTC()
	var next State
	if expectedVersion == 0 {
		by := actor.ID()
		created, err := s.repo.CreateIfAbsent(ctx, SettingKey, platformsetting.State{Value: raw, Source: platformsetting.SourceConsole, UpdatedBy: &by, UpdatedAt: now})
		if err != nil {
			return State{}, err
		}
		if !created {
			return State{}, platformsetting.ErrVersionConflict
		}
		next = State{Settings: in, Version: 1, UpdatedAt: now}
	} else {
		row, err := s.repo.Update(ctx, SettingKey, raw, expectedVersion, actor.ID(), now)
		if err != nil {
			return State{}, err
		}
		next = State{Settings: in, Version: row.Version, UpdatedAt: now}
	}
	s.mu.Lock()
	s.cached, s.cachedAt = &next, s.now()
	s.mu.Unlock()

	s.log.Warn("legal settings changed", "admin_id", actor.ID().String(), "version", next.Version)
	if s.audit != nil {
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		body["version"] = next.Version
		entry := admin.NewAuditLogBuilder(actor, ActionChanged).
			Resource("platform_setting", nil, SettingKey).
			Context(ip, userAgent).
			Request("PUT", "/api/v1/admin/settings/legal", body).
			Critical().
			Build()
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := s.audit.Create(actx, entry); err != nil {
			s.log.Error("write admin audit for legal settings change", "error", err)
		}
	}
	return next, nil
}
