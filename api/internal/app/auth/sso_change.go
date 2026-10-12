package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	identityproviderdom "github.com/openctemio/openctem/api/pkg/domain/identityprovider"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SSO changes from the platform admin console wait for an owner (RFC-022,
// owner decision 2026-10-02).
//
// The organization's SAML configuration and OIDC identity providers decide who
// can sign in to it. A platform administrator who could change them directly
// could install their own IdP signing certificate (or OIDC client) and sign in
// as any member. So a SAML config or identity-provider create/update submitted
// from the admin console is stored as a pending change, the organization's
// owners are told, and nothing changes until one of them approves it.
//
// Bootstrap: an organization with no owner yet (the administrator is still
// setting it up) has nobody to approve, so a change to it applies directly.
// Once the organization has an owner, every later change waits, including
// while all its owners are suspended: a suspended owner still owns the
// organization (RFC-022 revision 7), and applying directly then would let an
// administrator suspend the owners and install their own identity provider.
// The change waits for an owner restored or recovered.
//
// Deleting a SAML config or an identity provider still applies directly: it
// removes a way in rather than adding one.

// SSOChangeOwners answers who owns an organization.
type SSOChangeOwners interface {
	OwnerPresence(ctx context.Context, tenantID shared.ID) (tenantdom.OwnerPresence, error)
	ListActiveOwners(ctx context.Context, tenantID shared.ID) ([]ssochange.OwnerContact, error)
	IsActiveOwner(ctx context.Context, tenantID, userID shared.ID) (bool, error)
}

// SSOChangeInAppNotifier delivers an in-app notification.
type SSOChangeInAppNotifier interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// SSOChangeMailer emails an owner about a change that waits for them.
type SSOChangeMailer interface {
	NotifySSOChangePending(ctx context.Context, ownerEmail, ownerName, orgName, summary string)
}

// SSOChangeRequester is the platform administrator submitting a change.
type SSOChangeRequester struct {
	AdminID shared.ID
	Email   string
}

// SSOChangeResult is the outcome of a submission: either applied directly
// (organization without an owner) or stored as a pending change.
type SSOChangeResult struct {
	Applied bool
	Change  *ssochange.Change
}

// SSOChangeService stores, lists and decides pending SSO changes.
type SSOChangeService struct {
	repo    ssochange.Repository
	saml    *SAMLService
	sso     *SSOService
	owners  SSOChangeOwners
	tenants tenantdom.Repository
	inApp   SSOChangeInAppNotifier
	mailer  SSOChangeMailer
	domains DomainJITStore
	ttl     time.Duration
	now     func() time.Time
	logger  *logger.Logger
}

// NewSSOChangeService wires the service.
func NewSSOChangeService(repo ssochange.Repository, saml *SAMLService, sso *SSOService, owners SSOChangeOwners, tenants tenantdom.Repository, log *logger.Logger) *SSOChangeService {
	return &SSOChangeService{
		repo: repo, saml: saml, sso: sso, owners: owners, tenants: tenants,
		ttl: ssochange.DefaultTTL, now: time.Now, logger: log.With("service", "sso_change"),
	}
}

// SetNotificationService delivers the in-app notification to the owners.
func (s *SSOChangeService) SetNotificationService(n SSOChangeInAppNotifier) { s.inApp = n }

// SetMailer emails the owners (system SMTP).
func (s *SSOChangeService) SetMailer(m SSOChangeMailer) { s.mailer = m }

// --- payloads (what the owner sees; never a secret) ---

// SAMLChangePayload is a proposed SAML configuration.
type SAMLChangePayload struct {
	IDPEntityID    string   `json:"idp_entity_id"`
	IDPSSOURL      string   `json:"idp_sso_url"`
	IDPCertificate string   `json:"idp_certificate"`
	AllowedDomains []string `json:"allowed_domains"`
	DefaultRole    string   `json:"default_role"`
	AutoProvision  bool     `json:"auto_provision"`
	Enabled        bool     `json:"enabled"`
}

// IdPCreatePayload is a proposed new OIDC identity provider.
type IdPCreatePayload struct {
	Provider         string   `json:"provider"`
	DisplayName      string   `json:"display_name"`
	ClientID         string   `json:"client_id"`
	ClientSecretSet  bool     `json:"client_secret_set"`
	IssuerURL        string   `json:"issuer_url,omitempty"`
	TenantIdentifier string   `json:"tenant_identifier,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	AllowedDomains   []string `json:"allowed_domains,omitempty"`
	AutoProvision    bool     `json:"auto_provision"`
	DefaultRole      string   `json:"default_role,omitempty"`
}

// IdPUpdatePayload is a proposed change to an OIDC identity provider; only the
// set fields change.
type IdPUpdatePayload struct {
	DisplayName         *string  `json:"display_name,omitempty"`
	ClientID            *string  `json:"client_id,omitempty"`
	ClientSecretChanged bool     `json:"client_secret_changed"`
	IssuerURL           *string  `json:"issuer_url,omitempty"`
	TenantIdentifier    *string  `json:"tenant_identifier,omitempty"`
	Scopes              []string `json:"scopes,omitempty"`
	AllowedDomains      []string `json:"allowed_domains,omitempty"`
	AutoProvision       *bool    `json:"auto_provision,omitempty"`
	DefaultRole         *string  `json:"default_role,omitempty"`
	IsActive            *bool    `json:"is_active,omitempty"`
	// TargetProvider and TargetName identify the provider being changed in
	// the change summary (read at proposal time; the name is the one the
	// change sets when it renames the provider).
	TargetProvider string `json:"target_provider,omitempty"`
	TargetName     string `json:"target_name,omitempty"`
}

// --- submission ---

// needsApproval reports whether the organization has an owner who must
// approve the change. Without one (bootstrap) the change applies directly.
func (s *SSOChangeService) needsApproval(ctx context.Context, tenantID shared.ID) (bool, error) {
	presence, err := s.owners.OwnerPresence(ctx, tenantID)
	if err != nil {
		return false, fmt.Errorf("check organization owner: %w", err)
	}
	return presence.Any, nil
}

// SubmitSAML proposes the organization's SAML configuration.
func (s *SSOChangeService) SubmitSAML(ctx context.Context, tenantID shared.ID, in SAMLConfigInput, by SSOChangeRequester) (*SSOChangeResult, error) {
	// Validate now, so the administrator learns about a bad certificate
	// instead of the owner at approval time.
	if _, err := s.saml.BuildConfig(ctx, tenantID, in); err != nil {
		return nil, err
	}
	pending, err := s.needsApproval(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !pending {
		if _, err := s.saml.UpsertConfig(ctx, tenantID, in); err != nil {
			return nil, err
		}
		return &SSOChangeResult{Applied: true}, nil
	}
	payload := SAMLChangePayload(in)
	return s.store(ctx, tenantID, ssochange.KindSAMLConfig, "", payload, "", by)
}

// SubmitCreateProvider proposes a new OIDC identity provider.
func (s *SSOChangeService) SubmitCreateProvider(ctx context.Context, in CreateProviderInput, by SSOChangeRequester) (*SSOChangeResult, error) {
	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid organization id", shared.ErrValidation)
	}
	if _, err := s.sso.BuildProvider(in); err != nil {
		return nil, err
	}
	if existing, err := s.sso.ipRepo.GetByTenantAndProvider(ctx, in.TenantID, providerOf(in.Provider)); err == nil && existing != nil {
		return nil, errIdPAlreadyExists
	}
	pending, err := s.needsApproval(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !pending {
		if _, err := s.sso.CreateProvider(ctx, in); err != nil {
			return nil, err
		}
		return &SSOChangeResult{Applied: true}, nil
	}
	secret, err := s.sso.encryptor.EncryptString(in.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("encrypt client secret: %w", err)
	}
	payload := IdPCreatePayload{
		Provider: in.Provider, DisplayName: in.DisplayName, ClientID: in.ClientID,
		ClientSecretSet: in.ClientSecret != "", IssuerURL: in.IssuerURL, TenantIdentifier: in.TenantIdentifier,
		Scopes: in.Scopes, AllowedDomains: in.AllowedDomains, AutoProvision: in.AutoProvision, DefaultRole: in.DefaultRole,
	}
	return s.store(ctx, tenantID, ssochange.KindIdPCreate, "", payload, secret, by)
}

// SubmitUpdateProvider proposes a change to an OIDC identity provider.
func (s *SSOChangeService) SubmitUpdateProvider(ctx context.Context, in UpdateProviderInput, by SSOChangeRequester) (*SSOChangeResult, error) {
	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid organization id", shared.ErrValidation)
	}
	if _, err := shared.IDFromString(in.ID); err != nil {
		return nil, errIdPNotFound
	}
	// Validates the fields and that the provider exists in this organization.
	target, err := s.sso.BuildProviderUpdate(ctx, in)
	if err != nil {
		return nil, err
	}
	pending, err := s.needsApproval(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !pending {
		if _, err := s.sso.UpdateProvider(ctx, in); err != nil {
			return nil, err
		}
		return &SSOChangeResult{Applied: true}, nil
	}
	var secret string
	if in.ClientSecret != nil && *in.ClientSecret != "" {
		if secret, err = s.sso.encryptor.EncryptString(*in.ClientSecret); err != nil {
			return nil, fmt.Errorf("encrypt client secret: %w", err)
		}
	}
	payload := IdPUpdatePayload{
		DisplayName: in.DisplayName, ClientID: in.ClientID, ClientSecretChanged: secret != "",
		IssuerURL: in.IssuerURL, TenantIdentifier: in.TenantIdentifier, Scopes: in.Scopes,
		AllowedDomains: in.AllowedDomains, AutoProvision: in.AutoProvision, DefaultRole: in.DefaultRole,
		IsActive:       in.IsActive,
		TargetProvider: string(target.Provider()), TargetName: target.DisplayName(),
	}
	return s.store(ctx, tenantID, ssochange.KindIdPUpdate, in.ID, payload, secret, by)
}

func (s *SSOChangeService) store(ctx context.Context, tenantID shared.ID, kind ssochange.Kind, target string, payload any, secret string, by SSOChangeRequester) (*SSOChangeResult, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal sso change: %w", err)
	}
	now := s.now().UTC()
	c := &ssochange.Change{
		ID:               shared.NewID(),
		TenantID:         tenantID,
		Kind:             kind,
		TargetID:         target,
		Payload:          raw,
		SecretEncrypted:  secret,
		Status:           ssochange.StatusPending,
		RequestedByEmail: by.Email,
		CreatedAt:        now,
		ExpiresAt:        now.Add(s.ttl),
	}
	if !by.AdminID.IsZero() {
		id := by.AdminID
		c.RequestedByAdmin = &id
	}
	if err := s.repo.Create(ctx, c); err != nil {
		return nil, err
	}
	s.notifyOwners(ctx, c)
	return &SSOChangeResult{Change: c}, nil
}

// notifyOwners tells every active owner, in-app and by email. The change is
// already stored, so a delivery failure is logged, not returned.
func (s *SSOChangeService) notifyOwners(ctx context.Context, c *ssochange.Change) {
	owners, err := s.owners.ListActiveOwners(ctx, c.TenantID)
	if err != nil {
		s.logger.Error("list owners for sso change notification", "tenant_id", c.TenantID.String(), "error", err)
		return
	}
	orgName := c.TenantID.String()
	if s.tenants != nil {
		if t, terr := s.tenants.GetByID(ctx, c.TenantID); terr == nil && t != nil {
			orgName = t.Name()
		}
	}
	summary := DescribeSSOChange(c)
	requester := c.RequestedByEmail
	if requester == "" {
		requester = "a platform administrator"
	}
	body := fmt.Sprintf("A platform administrator (%s) proposed this SSO change for %s: %s. "+
		"It does not take effect until an owner approves it, and expires on %s.",
		requester, orgName, summary, c.ExpiresAt.UTC().Format("2006-01-02 15:04 MST"))
	changeID := c.ID
	for _, o := range owners {
		uid := o.UserID
		if s.inApp != nil {
			if err := s.inApp.Notify(ctx, notificationdom.NotificationParams{
				TenantID:         c.TenantID,
				Audience:         notificationdom.AudienceUser,
				AudienceID:       &uid,
				NotificationType: notificationdom.TypeSSOChangePending,
				Title:            "An SSO change is waiting for your approval",
				Body:             body,
				Severity:         notificationdom.SeverityHigh,
				ResourceType:     "sso_change",
				ResourceID:       &changeID,
				URL:              SSOChangeReviewPath,
			}); err != nil {
				s.logger.Error("notify owner of sso change", "tenant_id", c.TenantID.String(), "error", err)
			}
		}
		if s.mailer != nil && o.Email != "" {
			s.mailer.NotifySSOChangePending(ctx, o.Email, o.Name, orgName, body)
		}
	}
}

// SSOChangeReviewPath is the web page where an owner reviews pending changes.
const SSOChangeReviewPath = "/settings/sso-approvals"

// identityProviderNoun names a provider type for a summary: "Google
// Workspace identity provider", or just "identity provider" for an unknown id
// (never the raw id).
func identityProviderNoun(provider string) string {
	if label := identityproviderdom.Provider(provider).Label(); label != "" {
		return label + " identity provider"
	}
	return "identity provider"
}

// DescribeSSOChange is a one-line, secret-free description of a change.
func DescribeSSOChange(c *ssochange.Change) string {
	switch c.Kind {
	case ssochange.KindSAMLConfig:
		var p SAMLChangePayload
		_ = json.Unmarshal(c.Payload, &p)
		return fmt.Sprintf("set the SAML configuration (IdP entity %q, sign-in URL %q, signing certificate SHA-256 %s, auto-provision %s, enabled %s)",
			p.IDPEntityID, p.IDPSSOURL, shortFingerprint(CertificateFingerprint(p.IDPCertificate)), onOff(p.AutoProvision), onOff(p.Enabled))
	case ssochange.KindIdPCreate:
		var p IdPCreatePayload
		_ = json.Unmarshal(c.Payload, &p)
		return fmt.Sprintf("add the %s %q (client ID %q, auto-provision %s)",
			identityProviderNoun(p.Provider), p.DisplayName, p.ClientID, onOff(p.AutoProvision))
	case ssochange.KindIdPUpdate:
		var p IdPUpdatePayload
		_ = json.Unmarshal(c.Payload, &p)
		var fields []string
		add := func(set bool, name string) {
			if set {
				fields = append(fields, name)
			}
		}
		add(p.DisplayName != nil, "display name")
		add(p.ClientID != nil, "client ID")
		add(p.ClientSecretChanged, "client secret")
		add(p.IssuerURL != nil, "issuer URL")
		add(p.TenantIdentifier != nil, "tenant identifier")
		add(p.Scopes != nil, "scopes")
		add(p.AllowedDomains != nil, "allowed domains")
		add(p.AutoProvision != nil, "auto-provision")
		add(p.DefaultRole != nil, "default role")
		add(p.IsActive != nil, "active")
		if len(fields) == 0 {
			fields = []string{"no fields"}
		}
		// Never the provider id: a person approves this text.
		target := "an identity provider"
		if p.TargetName != "" {
			target = fmt.Sprintf("the %s %q", identityProviderNoun(p.TargetProvider), p.TargetName)
		}
		return "change " + target + " (" + strings.Join(fields, ", ") + ")"
	case ssochange.KindDomainJIT:
		return describeDomainJIT(c)
	}
	return string(c.Kind)
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func shortFingerprint(fp string) string {
	if len(fp) > 16 {
		return fp[:16] + "..."
	}
	if fp == "" {
		return "(none)"
	}
	return fp
}

// --- reading and deciding ---

// List returns the organization's SSO changes, newest first.
func (s *SSOChangeService) List(ctx context.Context, tenantID shared.ID, pendingOnly bool) ([]*ssochange.Change, error) {
	return s.repo.List(ctx, tenantID, pendingOnly, 50)
}

// Approve applies a pending change. approverID must be an active owner of the
// organization (checked in the database, not taken from the caller's token).
// The change and the live write commit together.
func (s *SSOChangeService) Approve(ctx context.Context, tenantID, changeID, approverID shared.ID) (*ssochange.Change, error) {
	if err := s.requireOwner(ctx, tenantID, approverID); err != nil {
		return nil, err
	}
	c, err := s.decidable(ctx, tenantID, changeID)
	if err != nil {
		return nil, err
	}
	write, err := s.liveWrite(ctx, c)
	if err != nil {
		return nil, err
	}
	if err := s.repo.Approve(ctx, tenantID, changeID, approverID, write); err != nil {
		return nil, err
	}
	return s.repo.Get(ctx, tenantID, changeID)
}

// Reject discards a pending change.
func (s *SSOChangeService) Reject(ctx context.Context, tenantID, changeID, approverID shared.ID) (*ssochange.Change, error) {
	if err := s.requireOwner(ctx, tenantID, approverID); err != nil {
		return nil, err
	}
	if _, err := s.decidable(ctx, tenantID, changeID); err != nil {
		return nil, err
	}
	if err := s.repo.Reject(ctx, tenantID, changeID, approverID); err != nil {
		return nil, err
	}
	return s.repo.Get(ctx, tenantID, changeID)
}

func (s *SSOChangeService) requireOwner(ctx context.Context, tenantID, userID shared.ID) error {
	if userID.IsZero() {
		return ssochange.ErrNotOwner
	}
	ok, err := s.owners.IsActiveOwner(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if !ok {
		return ssochange.ErrNotOwner
	}
	return nil
}

func (s *SSOChangeService) decidable(ctx context.Context, tenantID, changeID shared.ID) (*ssochange.Change, error) {
	c, err := s.repo.Get(ctx, tenantID, changeID)
	if err != nil {
		return nil, err
	}
	if c.Status != ssochange.StatusPending {
		if c.Status == ssochange.StatusExpired {
			return nil, ssochange.ErrExpired
		}
		return nil, ssochange.ErrNotPending
	}
	if c.IsExpired(s.now()) {
		return nil, ssochange.ErrExpired
	}
	return c, nil
}

// liveWrite rebuilds the live config from the stored change, re-running the
// same validation the direct path runs.
func (s *SSOChangeService) liveWrite(ctx context.Context, c *ssochange.Change) (ssochange.LiveWrite, error) {
	secret := ""
	if c.SecretEncrypted != "" {
		plain, err := s.sso.encryptor.DecryptString(c.SecretEncrypted)
		if err != nil {
			return ssochange.LiveWrite{}, fmt.Errorf("decrypt pending client secret: %w", err)
		}
		secret = plain
	}
	switch c.Kind {
	case ssochange.KindSAMLConfig:
		var p SAMLChangePayload
		if err := json.Unmarshal(c.Payload, &p); err != nil {
			return ssochange.LiveWrite{}, fmt.Errorf("decode saml change: %w", err)
		}
		cfg, err := s.saml.BuildConfig(ctx, c.TenantID, SAMLConfigInput(p))
		if err != nil {
			return ssochange.LiveWrite{}, err
		}
		return ssochange.LiveWrite{SAML: cfg}, nil
	case ssochange.KindIdPCreate:
		var p IdPCreatePayload
		if err := json.Unmarshal(c.Payload, &p); err != nil {
			return ssochange.LiveWrite{}, fmt.Errorf("decode identity provider change: %w", err)
		}
		ip, err := s.sso.BuildProvider(CreateProviderInput{
			TenantID: c.TenantID.String(), Provider: p.Provider, DisplayName: p.DisplayName,
			ClientID: p.ClientID, ClientSecret: secret, IssuerURL: p.IssuerURL,
			TenantIdentifier: p.TenantIdentifier, Scopes: p.Scopes, AllowedDomains: p.AllowedDomains,
			AutoProvision: p.AutoProvision, DefaultRole: p.DefaultRole,
		})
		if err != nil {
			return ssochange.LiveWrite{}, err
		}
		return ssochange.LiveWrite{IdPCreate: ip}, nil
	case ssochange.KindIdPUpdate:
		var p IdPUpdatePayload
		if err := json.Unmarshal(c.Payload, &p); err != nil {
			return ssochange.LiveWrite{}, fmt.Errorf("decode identity provider change: %w", err)
		}
		in := UpdateProviderInput{
			ID: c.TargetID, TenantID: c.TenantID.String(), DisplayName: p.DisplayName,
			ClientID: p.ClientID, IssuerURL: p.IssuerURL, TenantIdentifier: p.TenantIdentifier,
			Scopes: p.Scopes, AllowedDomains: p.AllowedDomains, AutoProvision: p.AutoProvision,
			DefaultRole: p.DefaultRole, IsActive: p.IsActive,
		}
		if secret != "" {
			in.ClientSecret = &secret
		}
		ip, err := s.sso.BuildProviderUpdate(ctx, in)
		if err != nil {
			return ssochange.LiveWrite{}, err
		}
		return ssochange.LiveWrite{IdPUpdate: ip}, nil
	case ssochange.KindDomainJIT:
		return s.domainJITWrite(ctx, c)
	}
	return ssochange.LiveWrite{}, fmt.Errorf("%w: unknown sso change kind %q", shared.ErrValidation, c.Kind)
}

var (
	errIdPAlreadyExists = identityproviderdom.ErrAlreadyExists
	errIdPNotFound      = identityproviderdom.ErrNotFound
)

func providerOf(p string) identityproviderdom.Provider { return identityproviderdom.Provider(p) }

// CertificateFingerprint is the SHA-256 (hex) of a PEM/base64 certificate's
// normalized text, for showing which certificate a change installs without
// repeating it.
func CertificateFingerprint(cert string) string {
	norm := strings.Join(strings.Fields(cert), "")
	if norm == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}
