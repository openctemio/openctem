package integration

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ID is a type alias for integration ID.
type ID = shared.ID

// ParseID parses a string into an integration ID.
func ParseID(s string) (ID, error) {
	return shared.IDFromString(s)
}

// Category represents the integration category.
type Category string

const (
	CategorySCM          Category = "scm"
	CategorySecurity     Category = "security"
	CategoryCloud        Category = "cloud"
	CategoryTicketing    Category = "ticketing"
	CategoryNotification Category = "notification"
	CategoryCustom       Category = "custom"
)

// String returns the string representation of the category.
func (c Category) String() string {
	return string(c)
}

// IsValid checks if the category is valid.
func (c Category) IsValid() bool {
	switch c {
	case CategorySCM, CategorySecurity, CategoryCloud, CategoryTicketing, CategoryNotification, CategoryCustom:
		return true
	default:
		return false
	}
}

// Provider represents the integration provider.
type Provider string

// SCM Providers
const (
	ProviderGitHub      Provider = "github"
	ProviderGitLab      Provider = "gitlab"
	ProviderBitbucket   Provider = "bitbucket"
	ProviderAzureDevOps Provider = "azure_devops"
)

// Security Providers
const (
	ProviderWiz         Provider = "wiz"
	ProviderSnyk        Provider = "snyk"
	ProviderTenable     Provider = "tenable"
	ProviderCrowdStrike Provider = "crowdstrike"
)

// Cloud Providers
const (
	ProviderAWS   Provider = "aws"
	ProviderGCP   Provider = "gcp"
	ProviderAzure Provider = "azure"
)

// Ticketing Providers
const (
	ProviderJira   Provider = "jira"
	ProviderLinear Provider = "linear"
	ProviderAsana  Provider = "asana"
)

// Notification Providers
const (
	ProviderSlack    Provider = "slack"
	ProviderTeams    Provider = "teams"
	ProviderTelegram Provider = "telegram"
	ProviderEmail    Provider = "email"
	ProviderWebhook  Provider = "webhook"
)

// String returns the string representation of the provider.
func (p Provider) String() string {
	return string(p)
}

// IsValid checks if the provider is valid.
func (p Provider) IsValid() bool {
	switch p {
	// SCM
	case ProviderGitHub, ProviderGitLab, ProviderBitbucket, ProviderAzureDevOps:
		return true
	// Security
	case ProviderWiz, ProviderSnyk, ProviderTenable, ProviderCrowdStrike:
		return true
	// Cloud
	case ProviderAWS, ProviderGCP, ProviderAzure:
		return true
	// Ticketing
	case ProviderJira, ProviderLinear, ProviderAsana:
		return true
	// Notification
	case ProviderSlack, ProviderTeams, ProviderTelegram, ProviderEmail, ProviderWebhook:
		return true
	default:
		return false
	}
}

// Category returns the category for this provider.
func (p Provider) Category() Category {
	switch p {
	case ProviderGitHub, ProviderGitLab, ProviderBitbucket, ProviderAzureDevOps:
		return CategorySCM
	case ProviderWiz, ProviderSnyk, ProviderTenable, ProviderCrowdStrike:
		return CategorySecurity
	case ProviderAWS, ProviderGCP, ProviderAzure:
		return CategoryCloud
	case ProviderJira, ProviderLinear, ProviderAsana:
		return CategoryTicketing
	case ProviderSlack, ProviderTeams, ProviderTelegram, ProviderEmail, ProviderWebhook:
		return CategoryNotification
	default:
		return CategoryCustom
	}
}

// Status represents the integration connection status.
type Status string

const (
	StatusPending      Status = "pending"
	StatusConnected    Status = "connected"
	StatusDisconnected Status = "disconnected"
	StatusError        Status = "error"
	StatusExpired      Status = "expired"
	StatusDisabled     Status = "disabled"
)

// String returns the string representation of the status.
func (s Status) String() string {
	return string(s)
}

// IsValid checks if the status is valid.
func (s Status) IsValid() bool {
	switch s {
	case StatusPending, StatusConnected, StatusDisconnected, StatusError, StatusExpired, StatusDisabled:
		return true
	default:
		return false
	}
}

// AuthType represents the authentication type.
type AuthType string

const (
	AuthTypeToken   AuthType = "token"
	AuthTypeOAuth   AuthType = "oauth"
	AuthTypeAPIKey  AuthType = "api_key"
	AuthTypeBasic   AuthType = "basic"
	AuthTypeApp     AuthType = "app"
	AuthTypeIAMRole AuthType = "iam_role"
)

// String returns the string representation of the auth type.
func (a AuthType) String() string {
	return string(a)
}

// IsValid checks if the auth type is valid.
func (a AuthType) IsValid() bool {
	switch a {
	case AuthTypeToken, AuthTypeOAuth, AuthTypeAPIKey, AuthTypeBasic, AuthTypeApp, AuthTypeIAMRole:
		return true
	default:
		return false
	}
}

// Stats represents integration statistics.
type Stats struct {
	TotalAssets       int `json:"total_assets"`
	TotalFindings     int `json:"total_findings"`
	TotalRepositories int `json:"total_repositories,omitempty"`
}

// Integration represents a connection to an external service.
type Integration struct {
	id          ID
	tenantID    ID
	name        string
	description string

	// Classification
	category Category
	provider Provider

	// Connection status
	status        Status
	statusMessage string

	// Authentication
	authType             AuthType
	baseURL              string
	credentialsEncrypted string

	// Sync tracking
	lastSyncAt          *time.Time
	nextSyncAt          *time.Time
	syncIntervalMinutes int
	syncError           string

	// Flexible configuration
	config   map[string]any
	metadata map[string]any

	// Statistics
	stats Stats

	// Timestamps
	createdAt time.Time
	updatedAt time.Time
	createdBy *ID
}

// NewIntegration creates a new integration.
func NewIntegration(
	id ID,
	tenantID ID,
	name string,
	category Category,
	provider Provider,
	authType AuthType,
) *Integration {
	now := time.Now()
	return &Integration{
		id:                  id,
		tenantID:            tenantID,
		name:                name,
		category:            category,
		provider:            provider,
		authType:            authType,
		status:              StatusPending,
		syncIntervalMinutes: 60,
		config:              make(map[string]any),
		metadata:            make(map[string]any),
		stats:               Stats{},
		createdAt:           now,
		updatedAt:           now,
	}
}

// Reconstruct creates an integration from stored data.
func Reconstruct(
	id ID,
	tenantID ID,
	name string,
	description string,
	category Category,
	provider Provider,
	status Status,
	statusMessage string,
	authType AuthType,
	baseURL string,
	credentialsEncrypted string,
	lastSyncAt *time.Time,
	nextSyncAt *time.Time,
	syncIntervalMinutes int,
	syncError string,
	config map[string]any,
	metadata map[string]any,
	stats Stats,
	createdAt time.Time,
	updatedAt time.Time,
	createdBy *ID,
) *Integration {
	if config == nil {
		config = make(map[string]any)
	}
	if metadata == nil {
		metadata = make(map[string]any)
	}
	return &Integration{
		id:                   id,
		tenantID:             tenantID,
		name:                 name,
		description:          description,
		category:             category,
		provider:             provider,
		status:               status,
		statusMessage:        statusMessage,
		authType:             authType,
		baseURL:              baseURL,
		credentialsEncrypted: credentialsEncrypted,
		lastSyncAt:           lastSyncAt,
		nextSyncAt:           nextSyncAt,
		syncIntervalMinutes:  syncIntervalMinutes,
		syncError:            syncError,
		config:               config,
		metadata:             metadata,
		stats:                stats,
		createdAt:            createdAt,
		updatedAt:            updatedAt,
		createdBy:            createdBy,
	}
}

// Getters

func (i *Integration) ID() ID                       { return i.id }
func (i *Integration) TenantID() ID                 { return i.tenantID }
func (i *Integration) Name() string                 { return i.name }
func (i *Integration) Description() string          { return i.description }
func (i *Integration) Category() Category           { return i.category }
func (i *Integration) Provider() Provider           { return i.provider }
func (i *Integration) Status() Status               { return i.status }
func (i *Integration) StatusMessage() string        { return i.statusMessage }
func (i *Integration) AuthType() AuthType           { return i.authType }
func (i *Integration) BaseURL() string              { return i.baseURL }
func (i *Integration) CredentialsEncrypted() string { return i.credentialsEncrypted }
func (i *Integration) LastSyncAt() *time.Time       { return i.lastSyncAt }
func (i *Integration) NextSyncAt() *time.Time       { return i.nextSyncAt }
func (i *Integration) SyncIntervalMinutes() int     { return i.syncIntervalMinutes }
func (i *Integration) SyncError() string            { return i.syncError }
func (i *Integration) Config() map[string]any       { return i.config }
func (i *Integration) Metadata() map[string]any     { return i.metadata }
func (i *Integration) Stats() Stats                 { return i.stats }
func (i *Integration) CreatedAt() time.Time         { return i.createdAt }
func (i *Integration) UpdatedAt() time.Time         { return i.updatedAt }
func (i *Integration) CreatedBy() *ID               { return i.createdBy }

// IsSCM returns true if this is an SCM integration.
func (i *Integration) IsSCM() bool {
	return i.category == CategorySCM
}

// IsConnected returns true if the integration is connected.
func (i *Integration) IsConnected() bool {
	return i.status == StatusConnected
}

// Setters/Mutations

func (i *Integration) SetName(name string) {
	i.name = name
	i.updatedAt = time.Now()
}

func (i *Integration) SetDescription(description string) {
	i.description = description
	i.updatedAt = time.Now()
}

func (i *Integration) SetBaseURL(baseURL string) {
	i.baseURL = baseURL
	i.updatedAt = time.Now()
}

func (i *Integration) SetCredentials(encrypted string) {
	i.credentialsEncrypted = encrypted
	i.updatedAt = time.Now()
}

func (i *Integration) SetStatus(status Status) {
	i.status = status
	i.updatedAt = time.Now()
}

func (i *Integration) SetStatusMessage(message string) {
	i.statusMessage = message
	i.updatedAt = time.Now()
}

func (i *Integration) SetConnected() {
	i.status = StatusConnected
	i.statusMessage = ""
	i.syncError = ""
	now := time.Now()
	i.lastSyncAt = &now
	i.updatedAt = now
}

func (i *Integration) SetError(err string) {
	i.status = StatusError
	i.syncError = err
	i.statusMessage = err
	now := time.Now()
	i.lastSyncAt = &now
	i.updatedAt = now
}

func (i *Integration) SetDisconnected() {
	i.status = StatusDisconnected
	i.updatedAt = time.Now()
}

func (i *Integration) SetSyncInterval(minutes int) {
	i.syncIntervalMinutes = minutes
	i.updatedAt = time.Now()
}

func (i *Integration) SetConfig(config map[string]any) {
	i.config = config
	i.updatedAt = time.Now()
}

func (i *Integration) SetMetadata(metadata map[string]any) {
	i.metadata = metadata
	i.updatedAt = time.Now()
}

func (i *Integration) SetStats(stats Stats) {
	i.stats = stats
	i.updatedAt = time.Now()
}

func (i *Integration) UpdateLastSync() {
	now := time.Now()
	i.lastSyncAt = &now
	i.updatedAt = now
}
