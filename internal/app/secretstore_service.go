package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/secretstore"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// SecretStoreService handles credential storage business logic.
type SecretStoreService struct {
	repo         secretstore.Repository
	encryptor    *secretstore.Encryptor
	logger       *logger.Logger
	auditService *AuditService
}

// NewSecretStoreService creates a new SecretStoreService.
func NewSecretStoreService(
	repo secretstore.Repository,
	encryptionKey []byte,
	auditService *AuditService,
	log *logger.Logger,
) (*SecretStoreService, error) {
	encryptor, err := secretstore.NewEncryptor(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	return &SecretStoreService{
		repo:         repo,
		encryptor:    encryptor,
		logger:       log.With("service", "secretstore"),
		auditService: auditService,
	}, nil
}

// CreateCredentialInput contains input for creating a secretstore.
type CreateCredentialInput struct {
	TenantID       shared.ID
	UserID         shared.ID
	Name           string
	CredentialType secretstore.CredentialType
	Description    string
	Data           any // One of the credential data types
	ExpiresAt      *time.Time
}

// CreateCredential creates a new credential in the secret store.
func (s *SecretStoreService) CreateCredential(ctx context.Context, input CreateCredentialInput) (*secretstore.Credential, error) {
	// Validate credential type
	if !input.CredentialType.IsValid() {
		return nil, shared.NewDomainError("VALIDATION", "invalid credential type", shared.ErrValidation)
	}

	// Validate data matches type
	if err := s.validateCredentialData(input.CredentialType, input.Data); err != nil {
		return nil, err
	}

	// Encrypt the data
	encryptedData, err := s.encryptor.EncryptJSON(input.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt credential data: %w", err)
	}

	// Create the credential
	cred := secretstore.NewCredential(
		input.TenantID,
		input.Name,
		input.CredentialType,
		encryptedData,
		&input.UserID,
	)
	cred.Description = input.Description
	cred.ExpiresAt = input.ExpiresAt

	if err := s.repo.Create(ctx, cred); err != nil {
		return nil, err
	}

	s.logger.Info("credential created",
		"id", cred.ID.String(),
		"name", cred.Name,
		"type", cred.CredentialType,
	)

	// Audit creation
	actx := AuditContext{
		TenantID: input.TenantID.String(),
		ActorID:  input.UserID.String(),
		// IP/UA would need to be passed in input or context
	}
	_ = s.auditService.LogCredentialCreated(ctx, actx, cred.ID.String(), cred.Name, string(cred.CredentialType))

	return cred, nil
}

// GetCredential retrieves a credential by ID.
func (s *SecretStoreService) GetCredential(ctx context.Context, tenantID shared.ID, credentialID string) (*secretstore.Credential, error) {
	id, err := shared.IDFromString(credentialID)
	if err != nil {
		return nil, shared.NewDomainError("VALIDATION", "invalid credential ID", shared.ErrValidation)
	}

	return s.repo.GetByTenantAndID(ctx, tenantID, id)
}

// ListCredentialsInput contains input for listing credentials.
type ListCredentialsInput struct {
	TenantID       shared.ID
	CredentialType *string
	Page           int
	PageSize       int
	SortBy         string
	SortOrder      string
}

// ListCredentialsOutput contains the result of listing credentials.
type ListCredentialsOutput struct {
	Items      []*secretstore.Credential
	TotalCount int
}

// ListCredentials lists credentials with filtering and pagination.
func (s *SecretStoreService) ListCredentials(ctx context.Context, input ListCredentialsInput) (*ListCredentialsOutput, error) {
	listInput := secretstore.ListInput{
		TenantID:  input.TenantID,
		Page:      input.Page,
		PageSize:  input.PageSize,
		SortBy:    input.SortBy,
		SortOrder: input.SortOrder,
	}

	if input.CredentialType != nil {
		ct := secretstore.CredentialType(*input.CredentialType)
		listInput.CredentialType = &ct
	}

	result, err := s.repo.List(ctx, listInput)
	if err != nil {
		return nil, err
	}

	return &ListCredentialsOutput{
		Items:      result.Items,
		TotalCount: result.TotalCount,
	}, nil
}

// UpdateCredentialInput contains input for updating a secretstore.
type UpdateCredentialInput struct {
	TenantID     shared.ID
	CredentialID string
	Name         string
	Description  string
	Data         any // One of the credential data types (nil to keep existing)
	ExpiresAt    *time.Time
}

// UpdateCredential updates a credential in the secret store.
func (s *SecretStoreService) UpdateCredential(ctx context.Context, input UpdateCredentialInput) (*secretstore.Credential, error) {
	id, err := shared.IDFromString(input.CredentialID)
	if err != nil {
		return nil, shared.NewDomainError("VALIDATION", "invalid credential ID", shared.ErrValidation)
	}

	cred, err := s.repo.GetByTenantAndID(ctx, input.TenantID, id)
	if err != nil {
		return nil, err
	}

	// Update fields
	if input.Name != "" {
		cred.Name = input.Name
	}
	cred.Description = input.Description
	cred.ExpiresAt = input.ExpiresAt
	cred.UpdatedAt = time.Now()

	// Update encrypted data if provided
	if input.Data != nil {
		if err := s.validateCredentialData(cred.CredentialType, input.Data); err != nil {
			return nil, err
		}

		encryptedData, err := s.encryptor.EncryptJSON(input.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt credential data: %w", err)
		}
		cred.EncryptedData = encryptedData
	}

	if err := s.repo.Update(ctx, cred); err != nil {
		return nil, err
	}

	s.logger.Info("credential updated",
		"id", cred.ID.String(),
		"name", cred.Name,
	)

	// Audit update
	actx := AuditContext{
		TenantID: input.TenantID.String(),
		// ActorID would need to be passed in input
	}
	_ = s.auditService.LogCredentialUpdated(ctx, actx, cred.ID.String(), cred.Name)

	return cred, nil
}

// RotateCredential rotates a credential with new data.
func (s *SecretStoreService) RotateCredential(ctx context.Context, tenantID shared.ID, credentialID string, newData any) (*secretstore.Credential, error) {
	id, err := shared.IDFromString(credentialID)
	if err != nil {
		return nil, shared.NewDomainError("VALIDATION", "invalid credential ID", shared.ErrValidation)
	}

	cred, err := s.repo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}

	// Validate new data
	if err := s.validateCredentialData(cred.CredentialType, newData); err != nil {
		return nil, err
	}

	// Encrypt new data
	encryptedData, err := s.encryptor.EncryptJSON(newData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt credential data: %w", err)
	}

	// Rotate
	cred.Rotate(encryptedData)

	if err := s.repo.Update(ctx, cred); err != nil {
		return nil, err
	}

	s.logger.Info("credential rotated",
		"id", cred.ID.String(),
		"name", cred.Name,
		"key_version", cred.KeyVersion,
	)

	// Audit rotation (treat as update)
	actx := AuditContext{
		TenantID: tenantID.String(),
	}
	_ = s.auditService.LogCredentialUpdated(ctx, actx, cred.ID.String(), cred.Name)

	return cred, nil
}

// DeleteCredential deletes a credential from the secret store.
func (s *SecretStoreService) DeleteCredential(ctx context.Context, tenantID shared.ID, credentialID string) error {
	id, err := shared.IDFromString(credentialID)
	if err != nil {
		return shared.NewDomainError("VALIDATION", "invalid credential ID", shared.ErrValidation)
	}

	// Delete with tenant validation (single atomic operation)
	if err := s.repo.DeleteByTenantAndID(ctx, tenantID, id); err != nil {
		return err
	}

	s.logger.Info("credential deleted", "id", credentialID)

	// Audit deletion
	actx := AuditContext{
		TenantID: tenantID.String(),
	}
	_ = s.auditService.LogCredentialDeleted(ctx, actx, credentialID)

	return nil
}

// DecryptCredentialData decrypts and returns the credential data.
// This also updates the last_used_at timestamp.
func (s *SecretStoreService) DecryptCredentialData(ctx context.Context, tenantID shared.ID, credentialID string) (any, error) {
	id, err := shared.IDFromString(credentialID)
	if err != nil {
		return nil, shared.NewDomainError("VALIDATION", "invalid credential ID", shared.ErrValidation)
	}

	cred, err := s.repo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}

	// Check if expired
	if cred.IsExpired() {
		return nil, shared.NewDomainError("CREDENTIAL_EXPIRED", "credential has expired", shared.ErrValidation)
	}

	// Decrypt based on type
	var data any
	switch cred.CredentialType {
	case secretstore.CredentialTypeAPIKey:
		data = &secretstore.APIKeyData{}
	case secretstore.CredentialTypeBearerToken:
		data = &secretstore.BearerTokenData{}
	case secretstore.CredentialTypeBasicAuth:
		data = &secretstore.BasicAuthData{}
	case secretstore.CredentialTypeSSHKey:
		data = &secretstore.SSHKeyData{}
	case secretstore.CredentialTypeAWSRole:
		data = &secretstore.AWSRoleData{}
	case secretstore.CredentialTypeGCPServiceAccount:
		data = &secretstore.GCPServiceAccountData{}
	case secretstore.CredentialTypeAzureServicePrincipal:
		data = &secretstore.AzureServicePrincipalData{}
	case secretstore.CredentialTypeGitHubApp:
		data = &secretstore.GitHubAppData{}
	case secretstore.CredentialTypeGitLabToken:
		data = &secretstore.GitLabTokenData{}
	default:
		return nil, shared.NewDomainError("UNKNOWN_TYPE", "unknown credential type", shared.ErrValidation)
	}

	if err := s.encryptor.DecryptJSON(cred.EncryptedData, data); err != nil {
		return nil, fmt.Errorf("failed to decrypt credential data: %w", err)
	}

	// Update last used (with tenant validation)
	_ = s.repo.UpdateLastUsedByTenantAndID(ctx, tenantID, id)

	// Audit access (CRITICAL)
	actx := AuditContext{
		TenantID: tenantID.String(),
	}
	_ = s.auditService.LogCredentialAccessed(ctx, actx, credentialID, cred.Name)

	return data, nil
}

// validateCredentialData validates that the data matches the credential type.
func (s *SecretStoreService) validateCredentialData(credType secretstore.CredentialType, data any) error {
	// Marshal and unmarshal to verify structure
	jsonData, err := json.Marshal(data)
	if err != nil {
		return shared.NewDomainError("VALIDATION", "invalid credential data", shared.ErrValidation)
	}

	var target any
	switch credType {
	case secretstore.CredentialTypeAPIKey:
		target = &secretstore.APIKeyData{}
	case secretstore.CredentialTypeBearerToken:
		target = &secretstore.BearerTokenData{}
	case secretstore.CredentialTypeBasicAuth:
		target = &secretstore.BasicAuthData{}
	case secretstore.CredentialTypeSSHKey:
		target = &secretstore.SSHKeyData{}
	case secretstore.CredentialTypeAWSRole:
		target = &secretstore.AWSRoleData{}
	case secretstore.CredentialTypeGCPServiceAccount:
		target = &secretstore.GCPServiceAccountData{}
	case secretstore.CredentialTypeAzureServicePrincipal:
		target = &secretstore.AzureServicePrincipalData{}
	case secretstore.CredentialTypeGitHubApp:
		target = &secretstore.GitHubAppData{}
	case secretstore.CredentialTypeGitLabToken:
		target = &secretstore.GitLabTokenData{}
	default:
		return shared.NewDomainError("VALIDATION", "unsupported credential type", shared.ErrValidation)
	}

	if err := json.Unmarshal(jsonData, target); err != nil {
		return shared.NewDomainError("VALIDATION", "credential data does not match type", shared.ErrValidation)
	}

	return nil
}
