package mcpoauth

import (
	"context"
	"errors"
	"fmt"
	"slices"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Client registration (RFC-062 §5): clients an organization registers in
// advance, and, when the operator turns it on, dynamic registration (RFC
// 7591, deprecated by MCP 2026-07-28 in favor of metadata documents).

// ErrRegistrationUnavailable means the service was built without the client
// store, or dynamic registration is off.
var ErrRegistrationUnavailable = errors.New("client registration is not available")

func (s *Service) clientStore() (mcpoauth.ClientRepository, error) {
	if s.clients == nil {
		return nil, ErrRegistrationUnavailable
	}
	return s.clients, nil
}

// validateClientInput checks a name and redirect URIs an organization or a
// registering client supplies.
func validateClientInput(name string, redirectURIs []string) (string, error) {
	clean := cleanClientName(name)
	if clean == "" {
		return "", fmt.Errorf("%w: a name is required", shared.ErrValidation)
	}
	if len(redirectURIs) == 0 || len(redirectURIs) > maxRedirectURIs {
		return "", fmt.Errorf("%w: list 1 to %d redirect URIs", shared.ErrValidation, maxRedirectURIs)
	}
	for _, r := range redirectURIs {
		if err := mcpoauth.ValidateRedirectURI(r); err != nil {
			return "", err
		}
	}
	return clean, nil
}

// CreateOrganizationClient registers a client for an organization: the
// organization's members see it as "registered by your organization" and
// other organizations can never use it. The client id is not a secret: the
// client authenticates with PKCE.
func (s *Service) CreateOrganizationClient(ctx context.Context, tenantID, actorID shared.ID, name string, redirectURIs []string, actor Actor) (*mcpoauth.Client, error) {
	store, err := s.clientStore()
	if err != nil {
		return nil, err
	}
	clean, err := validateClientInput(name, redirectURIs)
	if err != nil {
		return nil, err
	}
	id, err := randomToken(mcpoauth.OrganizationClientPrefix)
	if err != nil {
		return nil, err
	}
	c, err := store.CreateClient(ctx, &mcpoauth.Client{
		ClientID: id, Kind: mcpoauth.ClientKindOrganization, TenantID: &tenantID, Name: clean, RedirectURIs: redirectURIs,
	})
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, tenantID.String(), actorID.String(), actor,
		auditapp.NewSuccessEvent(auditdom.ActionMCPClientRegistered, auditdom.ResourceTypeMCPGrant, c.ID.String()).
			WithResourceName(c.Name).
			WithMessage("MCP client registered: "+c.Name).
			WithMetadata("client_id", c.ClientID).
			WithMetadata("redirect_uris", redirectURIs))
	return c, nil
}

// ListOrganizationClients returns the organization's registered clients.
func (s *Service) ListOrganizationClients(ctx context.Context, tenantID shared.ID) ([]mcpoauth.Client, error) {
	store, err := s.clientStore()
	if err != nil {
		return nil, err
	}
	return store.ListOrganizationClients(ctx, tenantID)
}

// DeleteOrganizationClient removes a registered client; its connections end.
func (s *Service) DeleteOrganizationClient(ctx context.Context, tenantID, actorID, id shared.ID, actor Actor) error {
	store, err := s.clientStore()
	if err != nil {
		return err
	}
	if err := store.DeleteOrganizationClient(ctx, tenantID, id); err != nil {
		return err
	}
	s.logAudit(ctx, tenantID.String(), actorID.String(), actor,
		auditapp.NewSuccessEvent(auditdom.ActionMCPClientDeleted, auditdom.ResourceTypeMCPGrant, id.String()).
			WithMessage("MCP client deleted; its connections ended"))
	return nil
}

// DynamicRegistration is an RFC 7591 registration request.
type DynamicRegistration struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ApplicationType         string   `json:"application_type"`
	ClientURI               string   `json:"client_uri"`
}

// DynamicClient is the RFC 7591 registration response.
type DynamicClient struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// DynamicRegistrationEnabled reports whether POST /oauth/register works.
func (s *Service) DynamicRegistrationEnabled() bool { return s.dcrEnabled && s.clients != nil }

// RegisterDynamicClient handles POST /oauth/register. Only public clients
// using the authorization code grant are accepted; such clients are always
// shown as unverified and only organizations that allow any application can
// use them.
func (s *Service) RegisterDynamicClient(ctx context.Context, in DynamicRegistration) (*DynamicClient, *OAuthError) {
	if !s.DynamicRegistrationEnabled() {
		return nil, oauthErr("invalid_request", "dynamic client registration is not enabled")
	}
	if m := in.TokenEndpointAuthMethod; m != "" && m != authMethodNone {
		return nil, oauthErr("invalid_client_metadata", "only public clients (token_endpoint_auth_method none) are accepted")
	}
	for _, g := range in.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			return nil, oauthErr("invalid_client_metadata", "grant_types may only be authorization_code and refresh_token")
		}
	}
	for _, rt := range in.ResponseTypes {
		if rt != "code" {
			return nil, oauthErr("invalid_client_metadata", "response_types may only be code")
		}
	}
	if t := in.ApplicationType; t != "" && t != "native" && t != "web" {
		return nil, oauthErr("invalid_client_metadata", "application_type must be native or web")
	}
	name := in.ClientName
	if name == "" {
		name = "Unnamed application"
	}
	clean, err := validateClientInput(name, in.RedirectURIs)
	if err != nil {
		return nil, oauthErr("invalid_redirect_uri", "redirect_uris must be https, or http on a loopback address, without fragments")
	}
	id, err := randomToken(mcpoauth.DynamicClientPrefix)
	if err != nil {
		return nil, oauthErr("server_error", "try again")
	}
	c, err := s.clients.CreateClient(ctx, &mcpoauth.Client{
		ClientID: id, Kind: mcpoauth.ClientKindDynamic, Name: clean, RedirectURIs: in.RedirectURIs,
	})
	if err != nil {
		s.log.Error("mcp oauth: register dynamic client", "error", err.Error())
		return nil, oauthErr("server_error", "try again")
	}
	grants := []string{"authorization_code", "refresh_token"}
	if len(in.GrantTypes) > 0 && !slices.Contains(in.GrantTypes, "refresh_token") {
		grants = []string{"authorization_code"}
	}
	return &DynamicClient{
		ClientID: c.ClientID, ClientIDIssuedAt: c.CreatedAt.Unix(), ClientName: c.Name, RedirectURIs: c.RedirectURIs,
		GrantTypes: grants, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: authMethodNone,
	}, nil
}

// authMethodNone is the token endpoint authentication of a public client.
const authMethodNone = "none"
