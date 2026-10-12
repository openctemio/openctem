package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"

	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/secretstore"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SecretStoreService handles credential storage business logic.
type SecretStoreService struct {
	repo         secretstore.Repository
	encryptor    *secretstore.Encryptor
	logger       *logger.Logger
	auditService *auditapp.AuditService
}

// NewSecretStoreService creates a new SecretStoreService.
func NewSecretStoreService(
	repo secretstore.Repository,
	encryptionKey []byte,
	auditService *auditapp.AuditService,
	log *logger.Logger,
	previousKeys ...[]byte,
) (*SecretStoreService, error) {
	encryptor, err := secretstore.NewEncryptor(encryptionKey, previousKeys...)
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
	if err := validateExpiry(input.ExpiresAt); err != nil {
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
	actx := auditapp.AuditContext{
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

// OptionalTime is a PATCH-style time field: Set=false leaves the stored value
// as it is, Set with a nil Value clears it, Set with a Value replaces it.
type OptionalTime struct {
	Set   bool
	Value *time.Time
}

// UpdateCredentialInput contains input for updating a credential's metadata.
// Every field is optional: an absent field is left unchanged (it used to be
// wiped, so a member editing the name silently removed an expiry). The secret
// itself changes only through RotateCredential.
type UpdateCredentialInput struct {
	TenantID     shared.ID
	CredentialID string
	ActorID      shared.ID
	Name         *string
	Description  *string
	ExpiresAt    OptionalTime
}

// validateExpiry refuses an expiry in the past: it would make the credential
// unusable the moment it is saved.
func validateExpiry(t *time.Time) error {
	if t != nil && !t.After(time.Now()) {
		return shared.NewDomainError("VALIDATION", "expires_at must be in the future", shared.ErrValidation)
	}
	return nil
}

// UpdateCredential updates a credential's metadata (name, description,
// expiry), leaving absent fields unchanged.
func (s *SecretStoreService) UpdateCredential(ctx context.Context, input UpdateCredentialInput) (*secretstore.Credential, error) {
	id, err := shared.IDFromString(input.CredentialID)
	if err != nil {
		return nil, shared.NewDomainError("VALIDATION", "invalid credential ID", shared.ErrValidation)
	}

	cred, err := s.repo.GetByTenantAndID(ctx, input.TenantID, id)
	if err != nil {
		return nil, err
	}

	changed := make([]string, 0, 3)
	if input.Name != nil {
		if *input.Name == "" {
			return nil, shared.NewDomainError("VALIDATION", "name cannot be empty", shared.ErrValidation)
		}
		if *input.Name != cred.Name {
			cred.Name = *input.Name
			changed = append(changed, "name")
		}
	}
	if input.Description != nil && *input.Description != cred.Description {
		cred.Description = *input.Description
		changed = append(changed, "description")
	}
	if input.ExpiresAt.Set {
		if err := validateExpiry(input.ExpiresAt.Value); err != nil {
			return nil, err
		}
		cred.ExpiresAt = input.ExpiresAt.Value
		changed = append(changed, "expires_at")
	}
	cred.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, cred); err != nil {
		return nil, err
	}

	s.logger.Info("credential updated",
		"id", cred.ID.String(),
		"name", cred.Name,
	)

	event := auditapp.NewSuccessEvent(auditdom.ActionCredentialUpdated, auditdom.ResourceTypeToken, cred.ID.String()).
		WithResourceName(cred.Name).
		WithMessage(fmt.Sprintf("Credential '%s' updated", cred.Name)).
		WithMetadata("changed_fields", changed)
	if input.ExpiresAt.Set {
		if input.ExpiresAt.Value == nil {
			event = event.WithMetadata("expires_at", nil)
		} else {
			event = event.WithMetadata("expires_at", input.ExpiresAt.Value.UTC().Format(time.RFC3339))
		}
	}
	s.logAudit(ctx, input.TenantID, input.ActorID, event)

	return cred, nil
}

// RotateCredentialInput replaces a credential's secret value.
type RotateCredentialInput struct {
	TenantID     shared.ID
	CredentialID string
	ActorID      shared.ID
	Data         any // one of the credential data types, matching the stored type
}

// RotateCredential replaces the secret of a credential in place (the type
// stays; key_version and last_rotated_at advance). Sources bound to it use the
// new value on their next fetch.
func (s *SecretStoreService) RotateCredential(ctx context.Context, input RotateCredentialInput) (*secretstore.Credential, error) {
	tenantID, credentialID, newData := input.TenantID, input.CredentialID, input.Data
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

	event := auditapp.NewSuccessEvent(auditdom.ActionCredentialUpdated, auditdom.ResourceTypeToken, cred.ID.String()).
		WithResourceName(cred.Name).
		WithMessage(fmt.Sprintf("Credential '%s' rotated (secret replaced)", cred.Name)).
		WithMetadata("rotated", true).
		WithMetadata("key_version", cred.KeyVersion).
		WithSeverity(auditdom.SeverityHigh)
	s.logAudit(ctx, tenantID, input.ActorID, event)

	return cred, nil
}

// logAudit records an event with the acting user (or a system actor named in
// the metadata when there is none). Audit is best-effort here: the change has
// already been committed.
func (s *SecretStoreService) logAudit(ctx context.Context, tenantID, actorID shared.ID, event auditapp.AuditEvent) {
	if s.auditService == nil {
		return
	}
	actx := auditapp.AuditContext{TenantID: tenantID.String()}
	if !actorID.IsZero() {
		actx.ActorID = actorID.String()
	} else {
		event = event.WithMetadata("system_actor", "secret-store")
	}
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("failed to audit secret store change", "error", err)
	}
}

// actorFromContext is the authenticated user of the request, when there is one
// (a template sync started by a person carries them; a scheduled sync does
// not).
func actorFromContext(ctx context.Context) shared.ID {
	if s, ok := ctx.Value(logger.ContextKeyUserID).(string); ok {
		if id, err := shared.IDFromString(s); err == nil {
			return id
		}
	}
	return shared.ID{}
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

	event := auditapp.NewSuccessEvent(auditdom.ActionCredentialDeleted, auditdom.ResourceTypeToken, credentialID).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("Credential %s deleted", credentialID))
	s.logAudit(ctx, tenantID, actorFromContext(ctx), event)

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

	// Audit access (high sensitivity): the person who started the sync, or a
	// named system actor for a scheduled one.
	event := auditapp.NewSuccessEvent(auditdom.ActionCredentialAccessed, auditdom.ResourceTypeToken, credentialID).
		WithResourceName(cred.Name).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("Credential '%s' decrypted/accessed", cred.Name))
	actor := actorFromContext(ctx)
	if actor.IsZero() {
		event = event.WithMetadata("system_actor", "template-sync")
	}
	s.logAudit(ctx, tenantID, actor, event)

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
