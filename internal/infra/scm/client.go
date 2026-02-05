// Package scm provides client implementations for various SCM (Source Code Management) providers
package scm

import (
	"context"
	"time"
)

// Provider represents the SCM provider type
type Provider string

const (
	ProviderGitHub    Provider = "github"
	ProviderGitLab    Provider = "gitlab"
	ProviderBitbucket Provider = "bitbucket"
	ProviderAzure     Provider = "azure"
)

// AuthType represents the authentication method
type AuthType string

const (
	AuthTypeToken AuthType = "token"
	AuthTypeOAuth AuthType = "oauth"
	AuthTypeApp   AuthType = "app"
)

// Config holds the configuration for an SCM client
type Config struct {
	Provider     Provider
	BaseURL      string // Base URL for self-hosted instances
	AccessToken  string
	Organization string // Optional: filter by organization/group
	AuthType     AuthType
}

// User represents an authenticated user from the SCM provider
type User struct {
	ID        string
	Username  string
	Name      string
	Email     string
	AvatarURL string
}

// Organization represents an organization/group from the SCM provider
type Organization struct {
	ID          string
	Name        string
	Description string
	AvatarURL   string
	RepoCount   int
}

// Repository represents a repository from the SCM provider
type Repository struct {
	ID            string
	Name          string
	FullName      string
	Description   string
	HTMLURL       string
	CloneURL      string
	SSHURL        string
	DefaultBranch string
	IsPrivate     bool
	IsFork        bool
	IsArchived    bool
	Language      string         // Primary language
	Languages     map[string]int // All languages with byte counts
	Topics        []string
	Stars         int
	Forks         int
	Size          int // Size in KB
	CreatedAt     time.Time
	UpdatedAt     time.Time
	PushedAt      time.Time
}

// ConnectionTestResult represents the result of testing a connection
type ConnectionTestResult struct {
	Success      bool
	Message      string
	User         *User
	Organization *Organization
	RepoCount    int
	RateLimit    *RateLimit
}

// RateLimit represents API rate limit information
type RateLimit struct {
	Limit     int
	Remaining int
	ResetAt   time.Time
}

// ListOptions represents pagination options
type ListOptions struct {
	Page    int
	PerPage int
	Search  string
}

// ListResult represents a paginated list result
type ListResult struct {
	Repositories []Repository
	Total        int
	HasMore      bool
	NextPage     int
}

// Client defines the interface for SCM provider clients
type Client interface {
	// TestConnection verifies the connection and returns user/org info
	TestConnection(ctx context.Context) (*ConnectionTestResult, error)

	// GetUser returns the authenticated user
	GetUser(ctx context.Context) (*User, error)

	// ListOrganizations returns organizations the user has access to
	ListOrganizations(ctx context.Context, opts ListOptions) ([]Organization, error)

	// ListRepositories returns repositories accessible to the user
	// If organization is set in config, filters by that organization
	ListRepositories(ctx context.Context, opts ListOptions) (*ListResult, error)

	// GetRepository returns a single repository by full name (owner/repo)
	GetRepository(ctx context.Context, fullName string) (*Repository, error)
}

// ClientFactory creates SCM clients based on provider
type ClientFactory struct{}

// NewClientFactory creates a new ClientFactory
func NewClientFactory() *ClientFactory {
	return &ClientFactory{}
}

// CreateClient creates an SCM client for the given config
func (f *ClientFactory) CreateClient(config Config) (Client, error) {
	switch config.Provider {
	case ProviderGitHub:
		return NewGitHubClient(config)
	case ProviderGitLab:
		return NewGitLabClient(config)
	case ProviderBitbucket:
		return NewBitbucketClient(config)
	case ProviderAzure:
		return NewAzureClient(config)
	default:
		return nil, ErrUnsupportedProvider
	}
}

// Common errors
var (
	ErrUnsupportedProvider = NewSCMError("unsupported SCM provider", "UNSUPPORTED_PROVIDER")
	ErrAuthFailed          = NewSCMError("authentication failed", "AUTH_FAILED")
	ErrRateLimited         = NewSCMError("rate limit exceeded", "RATE_LIMITED")
	ErrNotFound            = NewSCMError("resource not found", "NOT_FOUND")
	ErrPermissionDenied    = NewSCMError("permission denied", "PERMISSION_DENIED")
)

// SCMError represents an error from an SCM provider
type SCMError struct {
	Message string
	Code    string
	Wrapped error
}

// NewSCMError creates a new SCMError
func NewSCMError(message, code string) *SCMError {
	return &SCMError{Message: message, Code: code}
}

// Error implements the error interface
func (e *SCMError) Error() string {
	if e.Wrapped != nil {
		return e.Message + ": " + e.Wrapped.Error()
	}
	return e.Message
}

// Wrap wraps an underlying error
func (e *SCMError) Wrap(err error) *SCMError {
	return &SCMError{
		Message: e.Message,
		Code:    e.Code,
		Wrapped: err,
	}
}

// Unwrap returns the wrapped error
func (e *SCMError) Unwrap() error {
	return e.Wrapped
}
