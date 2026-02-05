// Package credential defines the Credential domain entity for secure credential storage.
package secretstore

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// CredentialType represents the type of credential.
type CredentialType string

const (
	// CredentialTypeAPIKey represents an API key credential.
	CredentialTypeAPIKey CredentialType = "api_key"
	// CredentialTypeBearerToken represents a bearer token credential.
	CredentialTypeBearerToken CredentialType = "bearer_token"
	// CredentialTypeBasicAuth represents basic authentication credentials.
	CredentialTypeBasicAuth CredentialType = "basic_auth"
	// CredentialTypeSSHKey represents an SSH key credential.
	CredentialTypeSSHKey CredentialType = "ssh_key"
	// CredentialTypeAWSRole represents an AWS IAM role credential.
	CredentialTypeAWSRole CredentialType = "aws_role"
	// CredentialTypeGCPServiceAccount represents a GCP service account credential.
	CredentialTypeGCPServiceAccount CredentialType = "gcp_service_account"
	// CredentialTypeAzureServicePrincipal represents an Azure service principal credential.
	CredentialTypeAzureServicePrincipal CredentialType = "azure_service_principal"
	// CredentialTypeGitHubApp represents a GitHub App credential.
	CredentialTypeGitHubApp CredentialType = "github_app"
	// CredentialTypeGitLabToken represents a GitLab token credential.
	CredentialTypeGitLabToken CredentialType = "gitlab_token"
)

// IsValid checks if the credential type is valid.
func (c CredentialType) IsValid() bool {
	switch c {
	case CredentialTypeAPIKey, CredentialTypeBearerToken, CredentialTypeBasicAuth,
		CredentialTypeSSHKey, CredentialTypeAWSRole, CredentialTypeGCPServiceAccount,
		CredentialTypeAzureServicePrincipal, CredentialTypeGitHubApp, CredentialTypeGitLabToken:
		return true
	}
	return false
}

// Credential represents a stored credential for external integrations.
type Credential struct {
	ID             shared.ID
	TenantID       shared.ID
	Name           string
	CredentialType CredentialType
	Description    string

	// Encrypted credential data (AES-256-GCM encrypted JSON)
	EncryptedData []byte

	// Key management
	KeyVersion          int
	EncryptionAlgorithm string

	// Metadata
	LastUsedAt    *time.Time
	LastRotatedAt *time.Time
	ExpiresAt     *time.Time

	// Audit fields
	CreatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// APIKeyData represents the decrypted data for an API key credential.
type APIKeyData struct {
	Key string `json:"key"`
}

// BearerTokenData represents the decrypted data for a bearer token credential.
type BearerTokenData struct {
	Token string `json:"token"`
}

// BasicAuthData represents the decrypted data for basic auth credentials.
type BasicAuthData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// SSHKeyData represents the decrypted data for an SSH key credential.
type SSHKeyData struct {
	PrivateKey string `json:"private_key"`
	Passphrase string `json:"passphrase,omitempty"`
}

// AWSRoleData represents the decrypted data for an AWS role credential.
type AWSRoleData struct {
	RoleARN    string `json:"role_arn"`
	ExternalID string `json:"external_id,omitempty"`
}

// GCPServiceAccountData represents the decrypted data for a GCP service account.
type GCPServiceAccountData struct {
	JSONKey string `json:"json_key"`
}

// AzureServicePrincipalData represents the decrypted data for an Azure service principal.
type AzureServicePrincipalData struct {
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// GitHubAppData represents the decrypted data for a GitHub App credential.
type GitHubAppData struct {
	AppID          string `json:"app_id"`
	InstallationID string `json:"installation_id"`
	PrivateKey     string `json:"private_key"`
}

// GitLabTokenData represents the decrypted data for a GitLab token credential.
type GitLabTokenData struct {
	Token string `json:"token"`
}

// NewCredential creates a new Credential with default values.
func NewCredential(
	tenantID shared.ID,
	name string,
	credentialType CredentialType,
	encryptedData []byte,
	createdBy *shared.ID,
) *Credential {
	now := time.Now()
	return &Credential{
		ID:                  shared.NewID(),
		TenantID:            tenantID,
		Name:                name,
		CredentialType:      credentialType,
		EncryptedData:       encryptedData,
		KeyVersion:          1,
		EncryptionAlgorithm: "AES-256-GCM",
		CreatedBy:           createdBy,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
}

// IsExpired checks if the credential has expired.
func (c *Credential) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*c.ExpiresAt)
}

// MarkUsed updates the last used timestamp.
func (c *Credential) MarkUsed() {
	now := time.Now()
	c.LastUsedAt = &now
}

// Rotate updates the credential with new encrypted data and increments key version.
func (c *Credential) Rotate(newEncryptedData []byte) {
	c.EncryptedData = newEncryptedData
	c.KeyVersion++
	now := time.Now()
	c.LastRotatedAt = &now
	c.UpdatedAt = now
}
