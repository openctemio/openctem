// Package identityprovider provides the domain model for tenant-scoped
// identity provider configurations (Entra ID, Okta, Google Workspace, etc.).
package identityprovider

import (
	"time"
)

// Provider represents a supported identity provider type.
type Provider string

const (
	ProviderEntraID         Provider = "entra_id"
	ProviderOkta            Provider = "okta"
	ProviderGoogleWorkspace Provider = "google_workspace"
)

// IsValid checks if the provider is supported.
func (p Provider) IsValid() bool {
	switch p {
	case ProviderEntraID, ProviderOkta, ProviderGoogleWorkspace:
		return true
	}
	return false
}

// AuthEndpoints returns the authorization and token URLs for the provider.
func (p Provider) AuthEndpoints(tenantIdentifier string) (authURL, tokenURL, userInfoURL string) {
	switch p {
	case ProviderEntraID:
		tid := tenantIdentifier
		if tid == "" {
			tid = "common"
		}
		base := "https://login.microsoftonline.com/" + tid + "/oauth2/v2.0"
		return base + "/authorize", base + "/token", "https://graph.microsoft.com/v1.0/me"
	case ProviderOkta:
		base := tenantIdentifier + "/oauth2/default/v1"
		return base + "/authorize", base + "/token", base + "/userinfo"
	case ProviderGoogleWorkspace:
		return "https://accounts.google.com/o/oauth2/v2/auth",
			"https://oauth2.googleapis.com/token",
			"https://www.googleapis.com/oauth2/v3/userinfo"
	}
	return "", "", ""
}

// IdentityProvider represents a tenant-scoped SSO configuration.
type IdentityProvider struct {
	id                    string
	tenantID              string
	provider              Provider
	displayName           string
	clientID              string
	clientSecretEncrypted string
	issuerURL             string
	tenantIdentifier      string
	scopes                []string
	allowedDomains        []string
	autoProvision         bool
	defaultRole           string
	isActive              bool
	metadata              map[string]any
	createdAt             time.Time
	updatedAt             time.Time
	createdBy             string
}

// New creates a new IdentityProvider.
func New(
	id, tenantID string,
	provider Provider,
	displayName, clientID, clientSecretEncrypted string,
) *IdentityProvider {
	now := time.Now()
	return &IdentityProvider{
		id:                    id,
		tenantID:              tenantID,
		provider:              provider,
		displayName:           displayName,
		clientID:              clientID,
		clientSecretEncrypted: clientSecretEncrypted,
		scopes:                []string{"openid", "email", "profile", "User.Read"},
		autoProvision:         true,
		defaultRole:           "member",
		isActive:              true,
		metadata:              make(map[string]any),
		createdAt:             now,
		updatedAt:             now,
	}
}

// Reconstruct rebuilds an IdentityProvider from persistence.
func Reconstruct(
	id, tenantID string,
	provider Provider,
	displayName, clientID, clientSecretEncrypted string,
	issuerURL, tenantIdentifier string,
	scopes, allowedDomains []string,
	autoProvision bool,
	defaultRole string,
	isActive bool,
	metadata map[string]any,
	createdAt, updatedAt time.Time,
	createdBy string,
) *IdentityProvider {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	if scopes == nil {
		scopes = []string{"openid", "email", "profile", "User.Read"}
	}
	return &IdentityProvider{
		id:                    id,
		tenantID:              tenantID,
		provider:              provider,
		displayName:           displayName,
		clientID:              clientID,
		clientSecretEncrypted: clientSecretEncrypted,
		issuerURL:             issuerURL,
		tenantIdentifier:      tenantIdentifier,
		scopes:                scopes,
		allowedDomains:        allowedDomains,
		autoProvision:         autoProvision,
		defaultRole:           defaultRole,
		isActive:              isActive,
		metadata:              metadata,
		createdAt:             createdAt,
		updatedAt:             updatedAt,
		createdBy:             createdBy,
	}
}

// Getters
func (ip *IdentityProvider) ID() string                    { return ip.id }
func (ip *IdentityProvider) TenantID() string              { return ip.tenantID }
func (ip *IdentityProvider) Provider() Provider            { return ip.provider }
func (ip *IdentityProvider) DisplayName() string           { return ip.displayName }
func (ip *IdentityProvider) ClientID() string              { return ip.clientID }
func (ip *IdentityProvider) ClientSecretEncrypted() string { return ip.clientSecretEncrypted }
func (ip *IdentityProvider) IssuerURL() string             { return ip.issuerURL }
func (ip *IdentityProvider) TenantIdentifier() string      { return ip.tenantIdentifier }
func (ip *IdentityProvider) Scopes() []string              { return ip.scopes }
func (ip *IdentityProvider) AllowedDomains() []string      { return ip.allowedDomains }
func (ip *IdentityProvider) AutoProvision() bool           { return ip.autoProvision }
func (ip *IdentityProvider) DefaultRole() string           { return ip.defaultRole }
func (ip *IdentityProvider) IsActive() bool                { return ip.isActive }
func (ip *IdentityProvider) Metadata() map[string]any      { return ip.metadata }
func (ip *IdentityProvider) CreatedAt() time.Time          { return ip.createdAt }
func (ip *IdentityProvider) UpdatedAt() time.Time          { return ip.updatedAt }
func (ip *IdentityProvider) CreatedBy() string             { return ip.createdBy }

// Setters
func (ip *IdentityProvider) SetDisplayName(name string) {
	ip.displayName = name
	ip.updatedAt = time.Now()
}

func (ip *IdentityProvider) SetClientID(clientID string) {
	ip.clientID = clientID
	ip.updatedAt = time.Now()
}

func (ip *IdentityProvider) SetClientSecretEncrypted(secret string) {
	ip.clientSecretEncrypted = secret
	ip.updatedAt = time.Now()
}

func (ip *IdentityProvider) SetIssuerURL(url string) {
	ip.issuerURL = url
	ip.updatedAt = time.Now()
}

func (ip *IdentityProvider) SetTenantIdentifier(tid string) {
	ip.tenantIdentifier = tid
	ip.updatedAt = time.Now()
}

func (ip *IdentityProvider) SetScopes(scopes []string) {
	ip.scopes = scopes
	ip.updatedAt = time.Now()
}

func (ip *IdentityProvider) SetAllowedDomains(domains []string) {
	ip.allowedDomains = domains
	ip.updatedAt = time.Now()
}

func (ip *IdentityProvider) SetAutoProvision(auto bool) {
	ip.autoProvision = auto
	ip.updatedAt = time.Now()
}

func (ip *IdentityProvider) SetDefaultRole(role string) {
	ip.defaultRole = role
	ip.updatedAt = time.Now()
}

func (ip *IdentityProvider) SetActive(active bool) {
	ip.isActive = active
	ip.updatedAt = time.Now()
}

func (ip *IdentityProvider) SetMetadata(metadata map[string]any) {
	ip.metadata = metadata
	ip.updatedAt = time.Now()
}

func (ip *IdentityProvider) SetCreatedBy(userID string) {
	ip.createdBy = userID
}

// IsDomainAllowed checks if an email domain is allowed.
// Returns true if no domain restrictions are configured.
func (ip *IdentityProvider) IsDomainAllowed(emailDomain string) bool {
	if len(ip.allowedDomains) == 0 {
		return true
	}
	for _, d := range ip.allowedDomains {
		if d == emailDomain {
			return true
		}
	}
	return false
}
