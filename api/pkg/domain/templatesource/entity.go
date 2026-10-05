// Package templatesource defines the TemplateSource domain entity for managing external template sources.
package templatesource

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SourceType represents the type of template source.
type SourceType string

const (
	// SourceTypeGit represents a Git repository source.
	SourceTypeGit SourceType = "git"
	// SourceTypeS3 represents an S3/MinIO bucket source.
	SourceTypeS3 SourceType = "s3"
	// SourceTypeHTTP represents an HTTP URL source.
	SourceTypeHTTP SourceType = "http"
)

// IsValid checks if the source type is valid.
func (s SourceType) IsValid() bool {
	switch s {
	case SourceTypeGit, SourceTypeS3, SourceTypeHTTP:
		return true
	}
	return false
}

// SyncStatus represents the status of the last sync operation.
type SyncStatus string

const (
	// SyncStatusPending means sync has not been attempted yet.
	SyncStatusPending SyncStatus = "pending"
	// SyncStatusInProgress means sync is currently running.
	SyncStatusInProgress SyncStatus = "in_progress"
	// SyncStatusSuccess means the last sync was successful.
	SyncStatusSuccess SyncStatus = "success"
	// SyncStatusFailed means the last sync failed.
	SyncStatusFailed SyncStatus = "failed"
)

// IsValid checks if the sync status is valid.
func (s SyncStatus) IsValid() bool {
	switch s {
	case SyncStatusPending, SyncStatusInProgress, SyncStatusSuccess, SyncStatusFailed:
		return true
	}
	return false
}

// GitSourceConfig holds configuration for Git repository sources.
type GitSourceConfig struct {
	URL      string `json:"url"`                 // https://github.com/org/repo
	Branch   string `json:"branch"`              // main, develop
	Path     string `json:"path,omitempty"`      // templates/nuclei/
	AuthType string `json:"auth_type,omitempty"` // none, ssh, token, oauth
}

// Validate validates the Git source configuration.
func (c *GitSourceConfig) Validate() error {
	if c.URL == "" {
		return shared.NewDomainError("VALIDATION", "git url is required", shared.ErrValidation)
	}
	if _, err := GitURLHost(c.URL); err != nil {
		return shared.NewDomainError("VALIDATION", err.Error(), shared.ErrValidation)
	}
	if err := checkSourceURLTransport(c.URL, true); err != nil {
		return shared.NewDomainError("VALIDATION", "git url: "+err.Error(), shared.ErrValidation)
	}
	if c.Branch == "" {
		return shared.NewDomainError("VALIDATION", "git branch is required", shared.ErrValidation)
	}
	if strings.HasPrefix(c.Branch, "-") || strings.ContainsAny(c.Branch, " \t\n\r\x00\\:~^?*[") || strings.Contains(c.Branch, "..") {
		return shared.NewDomainError("VALIDATION", "git branch is not a valid branch name", shared.ErrValidation)
	}
	clean, err := CleanRepoPath(c.Path)
	if err != nil {
		return shared.NewDomainError("VALIDATION", err.Error(), shared.ErrValidation)
	}
	c.Path = clean
	return nil
}

// maxRepoPathLen bounds a repository sub-path.
const maxRepoPathLen = 512

// CleanRepoPath normalizes a path inside a repository ("templates/nuclei/",
// "./x") to its clean slash-separated form, "" for the repository root. It
// refuses anything that could name a location outside the repository: an
// absolute path, any ".." segment, a backslash or a NUL byte. The fetcher
// also confines the resolved path at read time (symlinks), so this is the
// first of two checks, not the only one.
func CleanRepoPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", nil
	}
	if len(p) > maxRepoPathLen {
		return "", fmt.Errorf("repository path is too long")
	}
	if strings.ContainsAny(p, "\\\x00") {
		return "", fmt.Errorf("repository path must use forward slashes")
	}
	if path.IsAbs(p) {
		return "", fmt.Errorf("repository path must be relative to the repository root")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", fmt.Errorf("repository path must not contain '..'")
		}
	}
	clean := path.Clean(p)
	if clean == "." {
		return "", nil
	}
	return clean, nil
}

// scpLikeGitURL matches the scp-style ssh form "user@host:path".
var scpLikeGitURL = regexp.MustCompile(`^[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):\S+$`)

// GitURLHost validates a template-source repository URL and returns its
// host. Only remote transports are accepted: https, http, ssh and the
// scp-style "git@host:org/repo.git". file://, bare local paths (both served
// in-process by go-git from the API server's disk) and git:// (an unguarded
// raw TCP connection) are refused.
func GitURLHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("git url is required")
	}
	if m := scpLikeGitURL.FindStringSubmatch(raw); m != nil {
		host := m[1]
		if strings.HasPrefix(host, "-") {
			return "", fmt.Errorf("git url host is invalid")
		}
		return host, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("git url is invalid")
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "http", "ssh":
	default:
		return "", fmt.Errorf("git url must use https, http or ssh")
	}
	host := u.Hostname()
	if host == "" || strings.HasPrefix(host, "-") {
		return "", fmt.Errorf("git url must name a host")
	}
	return host, nil
}

// S3SourceConfig holds configuration for S3/MinIO bucket sources.
type S3SourceConfig struct {
	Bucket     string `json:"bucket"`
	Region     string `json:"region"`
	Prefix     string `json:"prefix,omitempty"`      // scanner-templates/nuclei/
	Endpoint   string `json:"endpoint,omitempty"`    // For MinIO
	AuthType   string `json:"auth_type,omitempty"`   // keys, sts_role
	RoleArn    string `json:"role_arn,omitempty"`    // For cross-account
	ExternalID string `json:"external_id,omitempty"` // For STS
}

// S3 authentication types. Both use credentials the tenant stored in the
// secret store; the server's own (ambient) AWS identity is never used for a
// tenant-configured source.
const (
	S3AuthKeys    = "keys"     // tenant access key + secret key
	S3AuthSTSRole = "sts_role" // assume RoleArn using the tenant's keys
)

var (
	s3RegionPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	s3BucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

// Validate validates the S3 source configuration.
func (c *S3SourceConfig) Validate() error {
	if c.Bucket == "" {
		return shared.NewDomainError("VALIDATION", "s3 bucket is required", shared.ErrValidation)
	}
	if !s3BucketPattern.MatchString(c.Bucket) {
		return shared.NewDomainError("VALIDATION", "s3 bucket name is invalid", shared.ErrValidation)
	}
	if c.Region == "" {
		return shared.NewDomainError("VALIDATION", "s3 region is required", shared.ErrValidation)
	}
	if !s3RegionPattern.MatchString(c.Region) {
		return shared.NewDomainError("VALIDATION", "s3 region is invalid", shared.ErrValidation)
	}
	switch c.AuthType {
	case S3AuthKeys:
	case S3AuthSTSRole:
		if c.RoleArn == "" {
			return shared.NewDomainError("VALIDATION", "s3 role_arn is required for sts_role", shared.ErrValidation)
		}
	default:
		return shared.NewDomainError("VALIDATION", "s3 auth_type must be 'keys' or 'sts_role'; the server's own AWS credentials are never used for a tenant source", shared.ErrValidation)
	}
	if c.Endpoint != "" {
		if err := ValidateEndpointURL(c.Endpoint); err != nil {
			return shared.NewDomainError("VALIDATION", "s3 endpoint: "+err.Error(), shared.ErrValidation)
		}
	}
	return nil
}

// ValidateEndpointURL checks the shape of a custom S3-compatible endpoint: an
// absolute http(s) URL with a host and no credentials, query or fragment.
// Where it resolves to is checked at connect time by the SSRF guard.
func ValidateEndpointURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("must be an http or https URL")
	}
	if u.Hostname() == "" {
		return fmt.Errorf("must name a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must not contain credentials, a query or a fragment")
	}
	return nil
}

// HTTPSourceConfig holds configuration for HTTP URL sources.
type HTTPSourceConfig struct {
	URL      string            `json:"url"`
	AuthType string            `json:"auth_type,omitempty"` // none, bearer, basic, api_key
	Headers  map[string]string `json:"headers,omitempty"`
	Timeout  int               `json:"timeout,omitempty"` // Seconds
}

// Limits on the HTTP source configuration.
const (
	maxHTTPSourceHeaders  = 20
	maxHTTPSourceTimeout  = 300 // seconds
	maxHTTPHeaderValueLen = 1024
)

var headerNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// IsSecretHeader reports whether a request header carries a credential. Such
// headers belong in Source credentials (encrypted, write-only), not in the
// source configuration, which is stored as plain JSON and shown to anyone who
// can read template sources.
func IsSecretHeader(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "authorization", "proxy-authorization", "cookie":
		return true
	}
	for _, marker := range []string{"token", "secret", "password", "api-key", "apikey", "auth", "key"} {
		if strings.Contains(n, marker) {
			return true
		}
	}
	return false
}

// Validate validates the HTTP source configuration: an https URL with a host
// and no embedded credentials, a bounded set of non-secret headers, and a
// bounded timeout.
func (c *HTTPSourceConfig) Validate() error {
	if c.URL == "" {
		return shared.NewDomainError("VALIDATION", "http url is required", shared.ErrValidation)
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Hostname() == "" {
		return shared.NewDomainError("VALIDATION", "http url is invalid", shared.ErrValidation)
	}
	if err := checkSourceURLTransport(c.URL, false); err != nil {
		return shared.NewDomainError("VALIDATION", "http url: "+err.Error(), shared.ErrValidation)
	}
	if len(c.Headers) > maxHTTPSourceHeaders {
		return shared.NewDomainError("VALIDATION", fmt.Sprintf("at most %d headers", maxHTTPSourceHeaders), shared.ErrValidation)
	}
	for name, value := range c.Headers {
		if !headerNamePattern.MatchString(name) {
			return shared.NewDomainError("VALIDATION", "header name is invalid", shared.ErrValidation)
		}
		if IsSecretHeader(name) {
			return shared.NewDomainError("VALIDATION",
				fmt.Sprintf("header %q carries a credential: store it in Source credentials and bind that credential to the source", name),
				shared.ErrValidation)
		}
		if len(value) > maxHTTPHeaderValueLen || strings.ContainsAny(value, "\r\n") {
			return shared.NewDomainError("VALIDATION", "header value is invalid", shared.ErrValidation)
		}
	}
	if c.Timeout < 0 || c.Timeout > maxHTTPSourceTimeout {
		return shared.NewDomainError("VALIDATION", fmt.Sprintf("timeout must be 0-%d seconds", maxHTTPSourceTimeout), shared.ErrValidation)
	}
	return nil
}

// checkSourceURLTransport refuses plain http (the fetched templates run on
// sensors, so they must not be swappable in transit) and a URL that embeds a
// password or token in its userinfo part: credentials belong in
// Source credentials. allowSSH also accepts ssh:// and the scp-style form.
func checkSourceURLTransport(raw string, allowSSH bool) error {
	raw = strings.TrimSpace(raw)
	if allowSSH && scpLikeGitURL.MatchString(raw) {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("is invalid")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "ssh":
		if !allowSSH {
			return fmt.Errorf("must use https")
		}
	default:
		return fmt.Errorf("must use https")
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			return fmt.Errorf("must not embed a password or token; store it in Source credentials")
		}
		if strings.EqualFold(u.Scheme, "https") {
			return fmt.Errorf("must not embed user info; store credentials in Source credentials")
		}
	}
	return nil
}

// MaskedURL hides the password of a URL with user info, for responses.
func MaskedURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, has := u.User.Password(); has {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
		return u.String()
	}
	return raw
}

// TemplateSource represents an external source for scanner templates.
type TemplateSource struct {
	ID           shared.ID
	TenantID     shared.ID
	Name         string
	SourceType   SourceType
	TemplateType scannertemplate.TemplateType
	Description  string
	Enabled      bool

	// Source-specific configuration (polymorphic)
	GitConfig  *GitSourceConfig  `json:"git_config,omitempty"`
	S3Config   *S3SourceConfig   `json:"s3_config,omitempty"`
	HTTPConfig *HTTPSourceConfig `json:"http_config,omitempty"`

	// Lazy sync settings (NO background polling - sync on scan trigger)
	AutoSyncOnScan  bool // Check for updates when scan triggers
	CacheTTLMinutes int  // Minutes to cache before re-check (default: 60)

	// Last sync info
	LastSyncAt     *time.Time
	LastSyncHash   string // ETag/commit hash for change detection
	LastSyncStatus SyncStatus
	LastSyncError  *string

	// Sync statistics
	TotalTemplates int
	LastSyncCount  int // Templates synced in last sync

	// Credential reference
	CredentialID *shared.ID

	// Audit
	CreatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewTemplateSource creates a new template source.
func NewTemplateSource(
	tenantID shared.ID,
	name string,
	sourceType SourceType,
	templateType scannertemplate.TemplateType,
	createdBy *shared.ID,
) (*TemplateSource, error) {
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}
	if len(name) > 255 {
		return nil, shared.NewDomainError("VALIDATION", "name must be less than 255 characters", shared.ErrValidation)
	}
	if !sourceType.IsValid() {
		return nil, shared.NewDomainError("VALIDATION", "invalid source type", shared.ErrValidation)
	}
	if !templateType.IsValid() {
		return nil, shared.NewDomainError("VALIDATION", "invalid template type", shared.ErrValidation)
	}

	now := time.Now()
	return &TemplateSource{
		ID:              shared.NewID(),
		TenantID:        tenantID,
		Name:            name,
		SourceType:      sourceType,
		TemplateType:    templateType,
		Enabled:         true,
		AutoSyncOnScan:  true,
		CacheTTLMinutes: 60,
		LastSyncStatus:  SyncStatusPending,
		CreatedBy:       createdBy,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

// SetGitConfig sets the Git source configuration.
func (s *TemplateSource) SetGitConfig(config *GitSourceConfig) error {
	if s.SourceType != SourceTypeGit {
		return shared.NewDomainError("VALIDATION", "cannot set git config for non-git source", shared.ErrValidation)
	}
	if config == nil {
		return shared.NewDomainError("VALIDATION", "git config is required", shared.ErrValidation)
	}
	if err := config.Validate(); err != nil {
		return err
	}
	s.GitConfig = config
	s.UpdatedAt = time.Now()
	return nil
}

// SetS3Config sets the S3 source configuration.
func (s *TemplateSource) SetS3Config(config *S3SourceConfig) error {
	if s.SourceType != SourceTypeS3 {
		return shared.NewDomainError("VALIDATION", "cannot set s3 config for non-s3 source", shared.ErrValidation)
	}
	if config == nil {
		return shared.NewDomainError("VALIDATION", "s3 config is required", shared.ErrValidation)
	}
	if err := config.Validate(); err != nil {
		return err
	}
	s.S3Config = config
	s.UpdatedAt = time.Now()
	return nil
}

// SetHTTPConfig sets the HTTP source configuration.
func (s *TemplateSource) SetHTTPConfig(config *HTTPSourceConfig) error {
	if s.SourceType != SourceTypeHTTP {
		return shared.NewDomainError("VALIDATION", "cannot set http config for non-http source", shared.ErrValidation)
	}
	if config == nil {
		return shared.NewDomainError("VALIDATION", "http config is required", shared.ErrValidation)
	}
	if err := config.Validate(); err != nil {
		return err
	}
	s.HTTPConfig = config
	s.UpdatedAt = time.Now()
	return nil
}

// Update updates the template source.
func (s *TemplateSource) Update(name, description string, autoSyncOnScan bool, cacheTTLMinutes int) error {
	if name != "" {
		if len(name) > 255 {
			return shared.NewDomainError("VALIDATION", "name must be less than 255 characters", shared.ErrValidation)
		}
		s.Name = name
	}
	s.Description = description
	s.AutoSyncOnScan = autoSyncOnScan

	if cacheTTLMinutes > 0 {
		s.CacheTTLMinutes = cacheTTLMinutes
	}

	s.UpdatedAt = time.Now()
	return nil
}

// SetCredential sets the credential reference.
func (s *TemplateSource) SetCredential(credentialID shared.ID) {
	s.CredentialID = &credentialID
	s.UpdatedAt = time.Now()
}

// ClearCredential clears the credential reference.
func (s *TemplateSource) ClearCredential() {
	s.CredentialID = nil
	s.UpdatedAt = time.Now()
}

// Enable enables the source.
func (s *TemplateSource) Enable() {
	s.Enabled = true
	s.UpdatedAt = time.Now()
}

// Disable disables the source.
func (s *TemplateSource) Disable() {
	s.Enabled = false
	s.UpdatedAt = time.Now()
}

// NeedsSync checks if the source needs to be synced based on cache TTL.
func (s *TemplateSource) NeedsSync() bool {
	if !s.Enabled || !s.AutoSyncOnScan {
		return false
	}
	if s.LastSyncAt == nil {
		return true
	}
	cacheDuration := time.Duration(s.CacheTTLMinutes) * time.Minute
	return time.Since(*s.LastSyncAt) > cacheDuration
}

// StartSync marks the sync as in progress.
func (s *TemplateSource) StartSync() {
	s.LastSyncStatus = SyncStatusInProgress
	s.LastSyncError = nil
	s.UpdatedAt = time.Now()
}

// CompleteSyncSuccess marks the sync as successful.
func (s *TemplateSource) CompleteSyncSuccess(hash string, templateCount int) {
	now := time.Now()
	s.LastSyncAt = &now
	s.LastSyncHash = hash
	s.LastSyncStatus = SyncStatusSuccess
	s.LastSyncError = nil
	s.LastSyncCount = templateCount
	s.TotalTemplates = templateCount
	s.UpdatedAt = now
}

// CompleteSyncFailure marks the sync as failed.
func (s *TemplateSource) CompleteSyncFailure(err string) {
	now := time.Now()
	s.LastSyncAt = &now
	s.LastSyncStatus = SyncStatusFailed
	s.LastSyncError = &err
	s.UpdatedAt = now
}

// CanManage checks if the given tenant can manage this source.
func (s *TemplateSource) CanManage(tenantID shared.ID) error {
	if !s.TenantID.Equals(tenantID) {
		return shared.NewDomainError("FORBIDDEN", "source belongs to another tenant", shared.ErrForbidden)
	}
	return nil
}

// BelongsToTenant checks if this source belongs to the specified tenant.
func (s *TemplateSource) BelongsToTenant(tenantID shared.ID) bool {
	return s.TenantID.Equals(tenantID)
}

// GetSourceConfig returns the active source configuration based on source type.
func (s *TemplateSource) GetSourceConfig() any {
	switch s.SourceType {
	case SourceTypeGit:
		return s.GitConfig
	case SourceTypeS3:
		return s.S3Config
	case SourceTypeHTTP:
		return s.HTTPConfig
	default:
		return nil
	}
}

// Validate validates the source configuration.
func (s *TemplateSource) Validate() error {
	switch s.SourceType {
	case SourceTypeGit:
		if s.GitConfig == nil {
			return shared.NewDomainError("VALIDATION", "git config is required for git source", shared.ErrValidation)
		}
		return s.GitConfig.Validate()
	case SourceTypeS3:
		if s.S3Config == nil {
			return shared.NewDomainError("VALIDATION", "s3 config is required for s3 source", shared.ErrValidation)
		}
		if s.CredentialID == nil {
			return shared.NewDomainError("VALIDATION", "s3 source requires a credential from the secret store", shared.ErrValidation)
		}
		return s.S3Config.Validate()
	case SourceTypeHTTP:
		if s.HTTPConfig == nil {
			return shared.NewDomainError("VALIDATION", "http config is required for http source", shared.ErrValidation)
		}
		return s.HTTPConfig.Validate()
	default:
		return shared.NewDomainError("VALIDATION", "invalid source type", shared.ErrValidation)
	}
}
