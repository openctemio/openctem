package auth

// An organization's own mail relay for its organization mail (invitations,
// account setup, member notices, scheduled reports). Design: research 308,
// decision D12; docs/architecture/notification-system.md, "Organization mail
// relay".
//
// The relay is the organization's e-mail notification integration with the
// flag org_mail. It is used only when the platform mode (email.tenant_relay)
// allows it, the relay meets the transport rule (pkg/email
// ValidateTenantRelay) and, in verified_sender mode, the sender address is on
// a DNS-verified domain of the same organization. Account security mail
// never asks this resolver (EmailService sends it through the platform
// relay only).

import (
	"context"
	"encoding/json"
	"errors"
	"net/mail"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
	emaildom "github.com/openctemio/openctem/api/pkg/email"
	"github.com/openctemio/openctem/api/pkg/logger"
)

var errRelayLookup = errors.New("the organization's integrations could not be read")

// RelayModeSource is the platform setting email.tenant_relay.
type RelayModeSource interface {
	RelayMode(ctx context.Context) emaildom.RelayMode
}

// SenderDomains answers whether a domain is DNS-verified for an organization.
type SenderDomains interface {
	GetByTenantAndDomain(ctx context.Context, tenantID shared.ID, domain string) (*verifieddomain.VerifiedDomain, error)
}

// IntegrationSMTPResolver resolves an organization's relay from its e-mail
// notification integration.
type IntegrationSMTPResolver struct {
	integrationRepo integration.Repository
	decrypt         func(string) (string, error)
	mode            RelayModeSource
	domains         SenderDomains
	logger          *logger.Logger
}

// NewIntegrationSMTPResolver creates the resolver. decrypt reads the
// integration's encrypted login; mode and domains may be nil, which turns
// the organization relay off (fail closed).
func NewIntegrationSMTPResolver(repo integration.Repository, decrypt func(string) (string, error), mode RelayModeSource, domains SenderDomains, log *logger.Logger) *IntegrationSMTPResolver {
	return &IntegrationSMTPResolver{
		integrationRepo: repo,
		decrypt:         decrypt,
		mode:            mode,
		domains:         domains,
		logger:          log.With("component", "tenant_smtp_resolver"),
	}
}

// GetTenantSMTPConfig returns the relay to use for the organization's own
// mail. It returns (nil, nil) when none applies (mode off, no integration
// with org_mail): the platform relay is then the configured sender. It
// returns an error wrapping emaildom.ErrTenantRelayUnusable when the
// organization chose a relay that cannot be used now: the caller decides
// whether the mail may fall back to the platform relay.
func (r *IntegrationSMTPResolver) GetTenantSMTPConfig(ctx context.Context, tenantID string) (*emaildom.Config, error) {
	parsedTenantID, idErr := shared.IDFromString(tenantID)
	if idErr != nil {
		return nil, nil //nolint:nilerr // not an organization id: there is no organization relay to look up
	}
	if r.mode == nil || r.mode.RelayMode(ctx) == emaildom.RelayModeOff {
		return nil, nil
	}
	mode := r.mode.RelayMode(ctx)

	integrations, err := r.integrationRepo.ListByCategory(ctx, parsedTenantID, integration.CategoryNotification)
	if err != nil {
		// Unknown whether the organization has a relay: do not guess.
		r.logger.Warn("organization mail relay lookup failed", "tenant_id", tenantID, "error", err)
		return nil, emaildom.RelayUnusable(errRelayLookup)
	}
	for _, intg := range integrations {
		if intg.Provider() != integration.ProviderEmail || intg.TenantID() != parsedTenantID {
			continue
		}
		if on, _ := intg.Metadata()[integration.MetaEmailOrgMail].(bool); !on {
			continue
		}
		cfg, err := r.relayConfig(ctx, intg, mode)
		if err != nil {
			r.logger.Warn("organization mail relay not usable",
				"tenant_id", tenantID, "integration_id", intg.ID().String(), "error", err)
			return nil, emaildom.RelayUnusable(err)
		}
		return cfg, nil
	}
	return nil, nil
}

// relayConfig builds the relay from the stored shape: connection settings in
// the integration metadata, the login in the encrypted credentials.
func (r *IntegrationSMTPResolver) relayConfig(ctx context.Context, intg *integration.Integration, mode emaildom.RelayMode) (*emaildom.Config, error) {
	if intg.Status() != integration.StatusConnected {
		return nil, errors.New("the e-mail integration is not connected")
	}
	meta := intg.Metadata()
	host, _ := meta["smtp_host"].(string)
	from, _ := meta["from_email"].(string)
	if host == "" || from == "" {
		return nil, errors.New("the relay has no host or sender address")
	}
	port := metaInt(meta["smtp_port"])
	implicitTLS, _ := meta["use_tls"].(bool)
	startTLS, _ := meta["use_starttls"].(bool)

	var login struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if enc := intg.CredentialsEncrypted(); enc != "" && r.decrypt != nil {
		plain, err := r.decrypt(enc)
		if err != nil {
			return nil, errors.New("the relay login cannot be read")
		}
		_ = json.Unmarshal([]byte(plain), &login)
	}

	if err := emaildom.ValidateTenantRelay(port, implicitTLS, startTLS, login.Username, login.Password); err != nil {
		return nil, err
	}
	if mode == emaildom.RelayModeVerifiedSender {
		if err := r.checkSenderDomain(ctx, intg.TenantID(), from); err != nil {
			return nil, err
		}
	}

	fromName, _ := meta["from_name"].(string)
	return &emaildom.Config{
		Host:        host,
		Port:        port,
		User:        login.Username,
		Password:    login.Password,
		From:        from,
		FromName:    fromName,
		TLS:         startTLS && !implicitTLS,
		ImplicitTLS: implicitTLS,
		// The relay's certificate is always verified.
		SkipVerify: false,
	}, nil
}

// checkSenderDomain requires the sender address to be on a verified domain of
// this organization (the lookup is scoped by tenant).
func (r *IntegrationSMTPResolver) checkSenderDomain(ctx context.Context, tenantID shared.ID, from string) error {
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return errors.New("the sender address is not valid")
	}
	at := strings.LastIndex(addr.Address, "@")
	if at < 0 {
		return errors.New("the sender address is not valid")
	}
	domain, err := verifieddomain.NormalizeDomain(addr.Address[at+1:])
	if err != nil {
		return errors.New("the sender domain is not valid")
	}
	if r.domains == nil {
		return errors.New("sender domains cannot be checked")
	}
	d, err := r.domains.GetByTenantAndDomain(ctx, tenantID, domain)
	if err != nil || d == nil || !d.IsVerified() {
		return errors.New("the sender domain is not verified for this organization")
	}
	return nil
}

func metaInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

func init() {
	// Compile-time check that the resolver implements TenantSMTPResolver.
	var _ TenantSMTPResolver = (*IntegrationSMTPResolver)(nil)
}
