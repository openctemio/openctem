package template

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/secretstore"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	ts "github.com/openctemio/openctem/api/pkg/domain/templatesource"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// MaxSourcesPerTenant is the maximum number of template sources a tenant can have.
const MaxSourcesPerTenant = 50

// CredentialReader looks up a stored credential in the tenant's secret store.
// *integration.SecretStoreService satisfies it.
type CredentialReader interface {
	GetCredential(ctx context.Context, tenantID shared.ID, credentialID string) (*secretstore.Credential, error)
}

// AuditLogger records tenant audit events. *audit.AuditService satisfies it.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// ErrCredentialBindForbidden is returned when the caller may not attach a
// stored credential to a template source, or point a source that carries one
// somewhere else.
var ErrCredentialBindForbidden = shared.NewDomainError("CREDENTIAL_BIND_FORBIDDEN",
	"only an owner or admin, or the user who stored the credential, can attach a stored credential to a template source or change where such a source points",
	shared.ErrForbidden)

// SourceService handles template source business operations.
type SourceService struct {
	repo           ts.Repository
	templateSyncer *Syncer
	syncingMap     sync.Map // Tracks currently syncing sources
	credentials    CredentialReader
	audit          AuditLogger
	logger         *logger.Logger
}

// SetCredentialGuard wires the secret store lookup used to authorize binding a
// stored credential to a source, and the audit log the binding is recorded
// in. Without a credential reader only owners/admins can bind credentials.
func (s *SourceService) SetCredentialGuard(creds CredentialReader, audit AuditLogger) {
	s.credentials = creds
	s.audit = audit
}

// NewSourceService creates a new SourceService.
func NewSourceService(repo ts.Repository, log *logger.Logger) *SourceService {
	return &SourceService{
		repo:   repo,
		logger: log.With("service", "template_source"),
	}
}

// SetTemplateSyncer sets the template syncer for force sync operations.
func (s *SourceService) SetTemplateSyncer(syncer *Syncer) {
	s.templateSyncer = syncer
}

// CreateSourceInput represents the input for creating a template source.
type CreateSourceInput struct {
	TenantID        string               `json:"tenant_id" validate:"required,uuid"`
	UserID          string               `json:"user_id" validate:"omitempty,uuid"`
	Name            string               `json:"name" validate:"required,min=1,max=255"`
	SourceType      string               `json:"source_type" validate:"required,oneof=git s3 http"`
	TemplateType    string               `json:"template_type" validate:"required,oneof=nuclei semgrep betterleaks"`
	Description     string               `json:"description" validate:"max=1000"`
	Enabled         bool                 `json:"enabled"`
	AutoSyncOnScan  bool                 `json:"auto_sync_on_scan"`
	CacheTTLMinutes int                  `json:"cache_ttl_minutes" validate:"min=0,max=10080"` // Max 1 week
	GitConfig       *ts.GitSourceConfig  `json:"git_config,omitempty"`
	S3Config        *ts.S3SourceConfig   `json:"s3_config,omitempty"`
	HTTPConfig      *ts.HTTPSourceConfig `json:"http_config,omitempty"`
	CredentialID    string               `json:"credential_id" validate:"omitempty,uuid"`

	// ActorIsAdmin is true when the caller is a tenant owner/admin. Only
	// they, or the user who stored the credential, can bind CredentialID.
	ActorIsAdmin bool `json:"-"`
	// Audit attributes the credential-binding audit event.
	Audit auditapp.AuditContext `json:"-"`
}

// CreateSource creates a new template source.
func (s *SourceService) CreateSource(ctx context.Context, input CreateSourceInput) (*ts.TemplateSource, error) {
	s.logger.Info("creating template source", "name", input.Name, "source_type", input.SourceType, "template_type", input.TemplateType)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	var createdBy *shared.ID
	if input.UserID != "" {
		uid, err := shared.IDFromString(input.UserID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
		}
		createdBy = &uid
	}

	sourceType := ts.SourceType(input.SourceType)
	if !sourceType.IsValid() {
		return nil, fmt.Errorf("%w: invalid source type", shared.ErrValidation)
	}

	templateType := scannertemplate.TemplateType(input.TemplateType)
	if !templateType.IsValid() {
		return nil, fmt.Errorf("%w: invalid template type", shared.ErrValidation)
	}

	// Check source limit per tenant
	count, err := s.repo.CountByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to count sources: %w", err)
	}
	if count >= MaxSourcesPerTenant {
		return nil, shared.NewDomainError("LIMIT_EXCEEDED", fmt.Sprintf("maximum of %d template sources per tenant", MaxSourcesPerTenant), shared.ErrForbidden)
	}

	// Check if name already exists
	existing, err := s.repo.GetByTenantAndName(ctx, tenantID, input.Name)
	if err == nil && existing != nil {
		return nil, shared.NewDomainError("ALREADY_EXISTS", "template source with this name already exists", shared.ErrAlreadyExists)
	}

	// Create source
	source, err := ts.NewTemplateSource(tenantID, input.Name, sourceType, templateType, createdBy)
	if err != nil {
		return nil, err
	}

	// Set additional fields
	source.Description = input.Description
	source.Enabled = input.Enabled
	source.AutoSyncOnScan = input.AutoSyncOnScan
	if input.CacheTTLMinutes > 0 {
		source.CacheTTLMinutes = input.CacheTTLMinutes
	}

	// Set source-specific config
	switch sourceType {
	case ts.SourceTypeGit:
		if input.GitConfig == nil {
			return nil, shared.NewDomainError("VALIDATION", "git config is required for git source", shared.ErrValidation)
		}
		if err := source.SetGitConfig(input.GitConfig); err != nil {
			return nil, err
		}
	case ts.SourceTypeS3:
		if input.S3Config == nil {
			return nil, shared.NewDomainError("VALIDATION", "s3 config is required for s3 source", shared.ErrValidation)
		}
		if err := source.SetS3Config(input.S3Config); err != nil {
			return nil, err
		}
	case ts.SourceTypeHTTP:
		if input.HTTPConfig == nil {
			return nil, shared.NewDomainError("VALIDATION", "http config is required for http source", shared.ErrValidation)
		}
		if err := source.SetHTTPConfig(input.HTTPConfig); err != nil {
			return nil, err
		}
	}

	// Set credential if provided. The server decrypts it and sends it to the
	// source's URL on every sync, so only someone entitled to that secret may
	// choose the destination.
	var boundCred *secretstore.Credential
	if input.CredentialID != "" {
		credID, err := shared.IDFromString(input.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid credential id", shared.ErrValidation)
		}
		boundCred, err = s.authorizeCredentialBinding(ctx, tenantID, credID, input.UserID, input.ActorIsAdmin)
		if err != nil {
			s.auditCredentialDenied(ctx, input.Audit, tenantID, source, credID, err)
			return nil, err
		}
		source.SetCredential(credID)
	}

	if err := source.Validate(); err != nil {
		return nil, err
	}

	// Persist
	if err := s.repo.Create(ctx, source); err != nil {
		return nil, err
	}

	if source.CredentialID != nil {
		s.auditCredentialAttached(ctx, input.Audit, tenantID, source, boundCred, false)
	}

	s.logger.Info("created template source", "id", source.ID.String(), "name", source.Name)
	return source, nil
}

// authorizeCredentialBinding decides whether the caller may bind credID to a
// source (or keep it bound while changing the source's destination). Owners
// and admins may; so may the user who stored the credential. Everyone else is
// refused — scans:secret_store:write and scans:sources:write are member
// permissions, and together they would otherwise let any member send any
// stored secret to a URL of their choosing.
func (s *SourceService) authorizeCredentialBinding(ctx context.Context, tenantID, credID shared.ID, actorID string, actorIsAdmin bool) (*secretstore.Credential, error) {
	if s.credentials == nil {
		if actorIsAdmin {
			return nil, nil
		}
		return nil, ErrCredentialBindForbidden
	}
	cred, err := s.credentials.GetCredential(ctx, tenantID, credID.String())
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, shared.NewDomainError("VALIDATION", "credential not found", shared.ErrValidation)
		}
		return nil, fmt.Errorf("look up credential: %w", err)
	}
	if actorIsAdmin {
		return cred, nil
	}
	if actorID != "" && cred.CreatedBy != nil && cred.CreatedBy.String() == actorID {
		return cred, nil
	}
	return nil, ErrCredentialBindForbidden
}

// sourceDestination identifies where a sync sends the source's credential.
// Two sources with the same destination receive the same secret.
func sourceDestination(src *ts.TemplateSource) string {
	switch src.SourceType {
	case ts.SourceTypeGit:
		if src.GitConfig != nil {
			return "git|" + strings.TrimSpace(src.GitConfig.URL)
		}
	case ts.SourceTypeHTTP:
		if src.HTTPConfig != nil {
			return "http|" + strings.TrimSpace(src.HTTPConfig.URL)
		}
	case ts.SourceTypeS3:
		if c := src.S3Config; c != nil {
			return strings.Join([]string{"s3", c.Endpoint, c.Region, c.Bucket, c.RoleArn}, "|")
		}
	}
	return ""
}

// destinationHost is the host part of the source's destination, for audit
// metadata. It never includes userinfo or a path.
func destinationHost(src *ts.TemplateSource) string {
	switch src.SourceType {
	case ts.SourceTypeGit:
		if src.GitConfig != nil {
			if h, err := ts.GitURLHost(src.GitConfig.URL); err == nil {
				return h
			}
		}
	case ts.SourceTypeHTTP:
		if src.HTTPConfig != nil {
			if u, err := url.Parse(src.HTTPConfig.URL); err == nil {
				return u.Host
			}
		}
	case ts.SourceTypeS3:
		if c := src.S3Config; c != nil {
			if c.Endpoint != "" {
				if u, err := url.Parse(c.Endpoint); err == nil && u.Host != "" {
					return u.Host + "/" + c.Bucket
				}
				return c.Endpoint + "/" + c.Bucket
			}
			return "s3:" + c.Region + "/" + c.Bucket
		}
	}
	return ""
}

func (s *SourceService) logAudit(ctx context.Context, actx auditapp.AuditContext, tenantID shared.ID, event auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	actx.TenantID = tenantID.String()
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.logger.Error("failed to log template source audit event", "error", err, "action", event.Action)
	}
}

func (s *SourceService) auditCredentialAttached(ctx context.Context, actx auditapp.AuditContext, tenantID shared.ID, src *ts.TemplateSource, cred *secretstore.Credential, repointed bool) {
	event := auditapp.NewSuccessEvent(audit.ActionTemplateSourceCredentialAttached, audit.ResourceTypeTemplateSource, src.ID.String()).
		WithResourceName(src.Name).
		WithMessage(fmt.Sprintf("Stored credential attached to template source '%s' (sent to %s on sync)", src.Name, destinationHost(src))).
		WithMetadata("credential_id", src.CredentialID.String()).
		WithMetadata("destination_host", destinationHost(src)).
		WithMetadata("source_type", string(src.SourceType)).
		WithMetadata("repointed", repointed).
		WithSeverity(audit.SeverityHigh)
	if cred != nil {
		event = event.WithMetadata("credential_name", cred.Name)
	}
	s.logAudit(ctx, actx, tenantID, event)
}

func (s *SourceService) auditCredentialDetached(ctx context.Context, actx auditapp.AuditContext, tenantID shared.ID, src *ts.TemplateSource, credID shared.ID, reason string) {
	event := auditapp.NewSuccessEvent(audit.ActionTemplateSourceCredentialDetached, audit.ResourceTypeTemplateSource, src.ID.String()).
		WithResourceName(src.Name).
		WithMessage(fmt.Sprintf("Stored credential detached from template source '%s' (%s)", src.Name, reason)).
		WithMetadata("credential_id", credID.String()).
		WithMetadata("destination_host", destinationHost(src)).
		WithMetadata("reason", reason).
		WithSeverity(audit.SeverityMedium)
	s.logAudit(ctx, actx, tenantID, event)
}

func (s *SourceService) auditCredentialDenied(ctx context.Context, actx auditapp.AuditContext, tenantID shared.ID, src *ts.TemplateSource, credID shared.ID, cause error) {
	if !errors.Is(cause, shared.ErrForbidden) {
		return
	}
	event := auditapp.NewDeniedEvent(audit.ActionTemplateSourceCredentialAttached, audit.ResourceTypeTemplateSource, src.ID.String(), "caller may not bind this stored credential").
		WithResourceName(src.Name).
		WithMetadata("credential_id", credID.String()).
		WithMetadata("destination_host", destinationHost(src)).
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, tenantID, event)
}

// GetSource retrieves a template source by ID.
func (s *SourceService) GetSource(ctx context.Context, tenantID, sourceID string) (*ts.TemplateSource, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sid, err := shared.IDFromString(sourceID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid source id", shared.ErrValidation)
	}

	source, err := s.repo.GetByID(ctx, sid)
	if err != nil {
		return nil, err
	}

	// Validate ownership
	if !source.BelongsToTenant(tid) {
		return nil, shared.NewDomainError("FORBIDDEN", "source belongs to another tenant", shared.ErrForbidden)
	}

	return source, nil
}

// ListSourcesInput represents the input for listing template sources.
type ListSourcesInput struct {
	TenantID     string  `json:"tenant_id" validate:"required,uuid"`
	SourceType   *string `json:"source_type" validate:"omitempty,oneof=git s3 http"`
	TemplateType *string `json:"template_type" validate:"omitempty,oneof=nuclei semgrep betterleaks"`
	Enabled      *bool   `json:"enabled"`
	Page         int     `json:"page"`
	PageSize     int     `json:"page_size"`
	SortBy       string  `json:"sort_by"`
	SortOrder    string  `json:"sort_order"`
}

// ListSources lists template sources with filters.
func (s *SourceService) ListSources(ctx context.Context, input ListSourcesInput) (*ts.ListOutput, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	listInput := ts.ListInput{
		TenantID:  tenantID,
		Enabled:   input.Enabled,
		Page:      input.Page,
		PageSize:  input.PageSize,
		SortBy:    input.SortBy,
		SortOrder: input.SortOrder,
	}

	if input.SourceType != nil {
		st := ts.SourceType(*input.SourceType)
		listInput.SourceType = &st
	}

	if input.TemplateType != nil {
		tt := scannertemplate.TemplateType(*input.TemplateType)
		listInput.TemplateType = &tt
	}

	return s.repo.List(ctx, listInput)
}

// UpdateSourceInput represents the input for updating a template source.
type UpdateSourceInput struct {
	TenantID        string               `json:"tenant_id" validate:"required,uuid"`
	SourceID        string               `json:"source_id" validate:"required,uuid"`
	Name            string               `json:"name" validate:"omitempty,min=1,max=255"`
	Description     string               `json:"description" validate:"max=1000"`
	Enabled         *bool                `json:"enabled"`
	AutoSyncOnScan  *bool                `json:"auto_sync_on_scan"`
	CacheTTLMinutes *int                 `json:"cache_ttl_minutes" validate:"omitempty,min=0,max=10080"`
	GitConfig       *ts.GitSourceConfig  `json:"git_config,omitempty"`
	S3Config        *ts.S3SourceConfig   `json:"s3_config,omitempty"`
	HTTPConfig      *ts.HTTPSourceConfig `json:"http_config,omitempty"`
	CredentialID    *string              `json:"credential_id" validate:"omitempty,uuid"`

	// UserID and ActorIsAdmin identify the caller for the credential-binding
	// check (see CreateSourceInput).
	UserID       string `json:"-"`
	ActorIsAdmin bool   `json:"-"`
	// Audit attributes the credential-binding audit events.
	Audit auditapp.AuditContext `json:"-"`
}

// UpdateSource updates an existing template source.
func (s *SourceService) UpdateSource(ctx context.Context, input UpdateSourceInput) (*ts.TemplateSource, error) {
	s.logger.Info("updating template source", "source_id", input.SourceID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	source, err := s.GetSource(ctx, input.TenantID, input.SourceID)
	if err != nil {
		return nil, err
	}

	// Validate ownership
	if err := source.CanManage(tenantID); err != nil {
		return nil, err
	}

	// Update basic fields
	autoSync := source.AutoSyncOnScan
	if input.AutoSyncOnScan != nil {
		autoSync = *input.AutoSyncOnScan
	}
	cacheTTL := source.CacheTTLMinutes
	if input.CacheTTLMinutes != nil {
		cacheTTL = *input.CacheTTLMinutes
	}
	if err := source.Update(input.Name, input.Description, autoSync, cacheTTL); err != nil {
		return nil, err
	}

	// Update enabled status
	if input.Enabled != nil {
		if *input.Enabled {
			source.Enable()
		} else {
			source.Disable()
		}
	}

	// Snapshot where the bound credential is sent today, before the config
	// changes below.
	prevCred := source.CredentialID
	prevDestination := sourceDestination(source)

	// Update source-specific config
	switch source.SourceType {
	case ts.SourceTypeGit:
		if input.GitConfig != nil {
			if err := source.SetGitConfig(input.GitConfig); err != nil {
				return nil, err
			}
		}
	case ts.SourceTypeS3:
		if input.S3Config != nil {
			if err := source.SetS3Config(input.S3Config); err != nil {
				return nil, err
			}
		}
	case ts.SourceTypeHTTP:
		if input.HTTPConfig != nil {
			if err := source.SetHTTPConfig(input.HTTPConfig); err != nil {
				return nil, err
			}
		}
	}

	// Update credential. A stored credential follows the source's
	// destination, so binding one, or keeping one while the destination
	// changes, needs the same right as attaching it in the first place. A
	// destination change that does not re-bind the credential drops it.
	moved := sourceDestination(source) != prevDestination
	type pendingAudit struct {
		attached  bool
		cred      *secretstore.Credential
		detachID  shared.ID
		reason    string
		repointed bool
	}
	var pending *pendingAudit
	switch {
	case input.CredentialID != nil && *input.CredentialID == "":
		source.ClearCredential()
		if prevCred != nil {
			pending = &pendingAudit{detachID: *prevCred, reason: "removed"}
		}
	case input.CredentialID != nil:
		credID, err := shared.IDFromString(*input.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid credential id", shared.ErrValidation)
		}
		if prevCred == nil || !prevCred.Equals(credID) || moved {
			cred, err := s.authorizeCredentialBinding(ctx, tenantID, credID, input.UserID, input.ActorIsAdmin)
			if err != nil {
				s.auditCredentialDenied(ctx, input.Audit, tenantID, source, credID, err)
				return nil, err
			}
			source.SetCredential(credID)
			pending = &pendingAudit{attached: true, cred: cred, repointed: prevCred != nil && moved}
		}
	case moved && prevCred != nil:
		source.ClearCredential()
		pending = &pendingAudit{detachID: *prevCred, reason: "destination changed"}
	}

	// An S3 source signs with the tenant's own keys only; refuse an edit
	// that would leave it without them. (Checked only when the edit touches
	// the S3 config or the credential, so a legacy source can still be
	// disabled or renamed.)
	if source.SourceType == ts.SourceTypeS3 && (input.S3Config != nil || input.CredentialID != nil) {
		if err := source.Validate(); err != nil {
			return nil, err
		}
	}

	if err := s.repo.Update(ctx, source); err != nil {
		return nil, err
	}

	if pending != nil {
		if pending.attached {
			s.auditCredentialAttached(ctx, input.Audit, tenantID, source, pending.cred, pending.repointed)
		} else {
			s.auditCredentialDetached(ctx, input.Audit, tenantID, source, pending.detachID, pending.reason)
		}
	}

	return source, nil
}

// DeleteSource deletes a template source.
func (s *SourceService) DeleteSource(ctx context.Context, tenantID, sourceID string) error {
	s.logger.Info("deleting template source", "source_id", sourceID)

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	source, err := s.GetSource(ctx, tenantID, sourceID)
	if err != nil {
		return err
	}

	// Validate ownership
	if err := source.CanManage(tid); err != nil {
		return err
	}

	return s.repo.Delete(ctx, source.ID)
}

// EnableSource enables a template source.
func (s *SourceService) EnableSource(ctx context.Context, tenantID, sourceID string) (*ts.TemplateSource, error) {
	source, err := s.GetSource(ctx, tenantID, sourceID)
	if err != nil {
		return nil, err
	}

	tid, _ := shared.IDFromString(tenantID)
	if err := source.CanManage(tid); err != nil {
		return nil, err
	}

	source.Enable()

	if err := s.repo.Update(ctx, source); err != nil {
		return nil, err
	}

	return source, nil
}

// DisableSource disables a template source.
func (s *SourceService) DisableSource(ctx context.Context, tenantID, sourceID string) (*ts.TemplateSource, error) {
	source, err := s.GetSource(ctx, tenantID, sourceID)
	if err != nil {
		return nil, err
	}

	tid, _ := shared.IDFromString(tenantID)
	if err := source.CanManage(tid); err != nil {
		return nil, err
	}

	source.Disable()

	if err := s.repo.Update(ctx, source); err != nil {
		return nil, err
	}

	return source, nil
}

// GetSourcesForScan retrieves enabled template sources linked to a scan profile.
func (s *SourceService) GetSourcesForScan(ctx context.Context, tenantID string, templateTypes []scannertemplate.TemplateType) ([]*ts.TemplateSource, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	var allSources []*ts.TemplateSource
	for _, tt := range templateTypes {
		sources, err := s.repo.ListByTenantAndTemplateType(ctx, tid, tt)
		if err != nil {
			return nil, err
		}
		allSources = append(allSources, sources...)
	}

	return allSources, nil
}

// GetSourcesNeedingSync returns sources that need to be synced (cache expired).
func (s *SourceService) GetSourcesNeedingSync(ctx context.Context, tenantID string) ([]*ts.TemplateSource, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sources, err := s.repo.ListEnabledForSync(ctx, tid)
	if err != nil {
		return nil, err
	}

	// Filter to only those that need sync
	var needsSync []*ts.TemplateSource
	for _, src := range sources {
		if src.NeedsSync() {
			needsSync = append(needsSync, src)
		}
	}

	return needsSync, nil
}

// UpdateSyncStatus updates the sync status of a template source.
func (s *SourceService) UpdateSyncStatus(ctx context.Context, source *ts.TemplateSource) error {
	return s.repo.UpdateSyncStatus(ctx, source)
}

// ErrSourceFetchFailed is returned by ForceSync when the template source
// itself could not be fetched (the upstream server, repository or bucket
// failed or refused the request). It is not a server error.
var ErrSourceFetchFailed = errors.New("template source could not be fetched")

// ForceSync triggers an immediate sync for a specific source.
// This is used for manual "force sync" requests from the API.
func (s *SourceService) ForceSync(ctx context.Context, tenantID, sourceID string) (*SyncResult, error) {
	if s.templateSyncer == nil {
		return nil, shared.NewDomainError("SYNCER_NOT_CONFIGURED", "template syncer is not configured", nil)
	}

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sid, err := shared.IDFromString(sourceID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid source id", shared.ErrValidation)
	}

	// Get the source
	source, err := s.repo.GetByTenantAndID(ctx, tid, sid)
	if err != nil {
		return nil, err
	}

	// Check if already syncing
	if _, syncing := s.syncingMap.Load(sid); syncing {
		return nil, shared.NewDomainError("SYNC_IN_PROGRESS", "source is already being synced", nil)
	}

	// Mark as syncing
	s.syncingMap.Store(sid, true)
	defer s.syncingMap.Delete(sid)

	s.logger.Info("force syncing template source",
		"source_id", sourceID,
		"source_name", source.Name,
		"source_type", string(source.SourceType))

	// Perform sync
	result, err := s.templateSyncer.SyncSource(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSourceFetchFailed, err)
	}

	// Record metrics
	metrics.TemplateSyncsTotal.WithLabelValues(string(source.SourceType)).Inc()
	if result.Success {
		metrics.TemplateSyncsSuccessTotal.WithLabelValues().Inc()
	} else {
		metrics.TemplateSyncsFailedTotal.WithLabelValues().Inc()
	}

	s.logger.Info("force sync completed",
		"source_id", sourceID,
		"success", result.Success,
		"templates_found", result.TemplatesFound,
		"templates_added", result.TemplatesAdded,
		"duration", result.Duration)

	return result, nil
}
