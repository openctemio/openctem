package agent

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// RegistrationToken represents a token for agent auto-registration.
type RegistrationToken struct {
	ID       shared.ID
	TenantID shared.ID
	Name     string

	// Token identification
	TokenHash   string
	TokenPrefix string

	// Pre-configuration for registered agents
	AgentType           AgentType
	AgentNamePrefix     string
	DefaultScopes       []string
	DefaultCapabilities []string
	DefaultTools        []string
	DefaultLabels       map[string]any

	// Usage limits
	MaxUses   *int // nil = unlimited
	UsesCount int

	// Lifecycle
	ExpiresAt *time.Time
	IsActive  bool

	// Audit
	CreatedBy *shared.ID
	CreatedAt time.Time
}

// NewRegistrationToken creates a new registration token.
func NewRegistrationToken(
	tenantID shared.ID,
	name string,
	agentType AgentType,
	maxUses *int,
	expiresAt *time.Time,
) (*RegistrationToken, error) {
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}

	if !agentType.IsValid() {
		agentType = AgentTypeWorker
	}

	return &RegistrationToken{
		ID:                  shared.NewID(),
		TenantID:            tenantID,
		Name:                name,
		AgentType:           agentType,
		DefaultScopes:       DefaultAgentScopes(),
		DefaultCapabilities: []string{},
		DefaultTools:        []string{},
		DefaultLabels:       make(map[string]any),
		MaxUses:             maxUses,
		UsesCount:           0,
		ExpiresAt:           expiresAt,
		IsActive:            true,
		CreatedAt:           time.Now(),
	}, nil
}

// SetTokenHash sets the token hash and prefix.
func (t *RegistrationToken) SetTokenHash(hash, prefix string) {
	t.TokenHash = hash
	t.TokenPrefix = prefix
}

// SetDefaults sets default configuration for registered agents.
func (t *RegistrationToken) SetDefaults(scopes, capabilities, tools []string, labels map[string]any) {
	if len(scopes) > 0 {
		t.DefaultScopes = scopes
	}
	if len(capabilities) > 0 {
		t.DefaultCapabilities = capabilities
	}
	if len(tools) > 0 {
		t.DefaultTools = tools
	}
	if labels != nil {
		t.DefaultLabels = labels
	}
}

// SetCreatedBy sets the user who created the token.
func (t *RegistrationToken) SetCreatedBy(userID shared.ID) {
	t.CreatedBy = &userID
}

// IncrementUsage increments the usage counter.
func (t *RegistrationToken) IncrementUsage() {
	t.UsesCount++
}

// IsExpired checks if the token is expired.
func (t *RegistrationToken) IsExpired() bool {
	if t.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*t.ExpiresAt)
}

// IsExhausted checks if the token has reached its usage limit.
func (t *RegistrationToken) IsExhausted() bool {
	if t.MaxUses == nil {
		return false
	}
	return t.UsesCount >= *t.MaxUses
}

// IsValid checks if the token can be used for registration.
func (t *RegistrationToken) IsValid() bool {
	return t.IsActive && !t.IsExpired() && !t.IsExhausted()
}

// CanRegister checks if the token can be used and returns an error if not.
func (t *RegistrationToken) CanRegister() error {
	if !t.IsActive {
		return shared.NewDomainError("TOKEN_INACTIVE", "registration token is inactive", shared.ErrValidation)
	}
	if t.IsExpired() {
		return shared.NewDomainError("TOKEN_EXPIRED", "registration token has expired", shared.ErrValidation)
	}
	if t.IsExhausted() {
		return shared.NewDomainError("TOKEN_EXHAUSTED", "registration token has reached its usage limit", shared.ErrValidation)
	}
	return nil
}

// Deactivate deactivates the token.
func (t *RegistrationToken) Deactivate() {
	t.IsActive = false
}
