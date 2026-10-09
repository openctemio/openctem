package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/template"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ScannerTemplateService handles scanner template business operations.
type ScannerTemplateService struct {
	repo          scannertemplate.Repository
	signingSecret string
	logger        *logger.Logger
	quota         scannertemplate.TemplateQuota
	// keys signs custom templates for sensors (SigningKey shows a tenant
	// its public key); nil when no key is configured. It is the fallback
	// for sensors that do not verify signed jobs (RFC-040 §11.5).
	keys *scannertemplate.Keyring
	// ledger and approvalPolicy approve template versions for sensors
	// (scanner_template_ledger.go).
	ledger         TemplateLedger
	approvalPolicy TemplateApprovalPolicy
}

// ErrTemplateSigningDisabled is returned by SigningKey when the platform has
// no template-signing key (no APP_TEMPLATE_SIGNING_KEY or
// APP_ENCRYPTION_KEY): custom templates are then sent unsigned and sensors
// refuse them.
var ErrTemplateSigningDisabled = errors.New("custom template signing is not configured on this platform")

// NewScannerTemplateService creates a new ScannerTemplateService.
func NewScannerTemplateService(repo scannertemplate.Repository, signingSecret string, log *logger.Logger) *ScannerTemplateService {
	return &ScannerTemplateService{
		repo:          repo,
		signingSecret: signingSecret,
		logger:        log.With("service", "scanner_template"),
		quota:         scannertemplate.DefaultQuota(),
	}
}

// SetSigningKeys sets the keyring custom templates are signed with for
// sensors.
func (s *ScannerTemplateService) SetSigningKeys(k *scannertemplate.Keyring) {
	s.keys = k
}

// TemplateSigningKey is a tenant's template-signing public key, to pin on
// the tenant's sensors (SENSOR_TEMPLATE_SIGNING_KEYS).
type TemplateSigningKey struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // base64 (standard)
	SensorEnv string `json:"sensor_env"` // the sensor setting it goes in
}

// SigningKey returns tenantID's template-signing public key.
func (s *ScannerTemplateService) SigningKey(tenantID string) (*TemplateSigningKey, error) {
	if _, err := shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	if s.keys == nil {
		return nil, ErrTemplateSigningDisabled
	}
	pub, id, err := s.keys.PublicKey(tenantID)
	if err != nil {
		return nil, err
	}
	return &TemplateSigningKey{
		Algorithm: "ed25519",
		KeyID:     id,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		SensorEnv: "SENSOR_TEMPLATE_SIGNING_KEYS",
	}, nil
}

// SetQuota sets custom quota limits for the service.
func (s *ScannerTemplateService) SetQuota(quota scannertemplate.TemplateQuota) {
	s.quota = quota
}

// CreateScannerTemplateInput represents the input for creating a scanner template.
type CreateScannerTemplateInput struct {
	TenantID     string   `json:"tenant_id" validate:"required,uuid"`
	UserID       string   `json:"user_id" validate:"omitempty,uuid"`
	Name         string   `json:"name" validate:"required,min=1,max=255"`
	TemplateType string   `json:"template_type" validate:"required,oneof=nuclei semgrep betterleaks"`
	Description  string   `json:"description" validate:"max=1000"`
	Content      string   `json:"content" validate:"required"` // Base64 encoded
	Tags         []string `json:"tags" validate:"max=20,dive,max=50"`
}

// CreateTemplate creates a new scanner template.
func (s *ScannerTemplateService) CreateTemplate(ctx context.Context, input CreateScannerTemplateInput) (*scannertemplate.ScannerTemplate, error) {
	s.logger.Info("creating scanner template", "name", input.Name, "type", input.TemplateType)

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

	templateType := scannertemplate.TemplateType(input.TemplateType)
	if !templateType.IsValid() {
		return nil, fmt.Errorf("%w: invalid template type", shared.ErrValidation)
	}

	// Decode base64 content
	content, err := base64.StdEncoding.DecodeString(input.Content)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64 content", shared.ErrValidation)
	}

	// Check size limit
	if int64(len(content)) > templateType.MaxSize() {
		return nil, fmt.Errorf("%w: content exceeds maximum size of %d bytes", shared.ErrValidation, templateType.MaxSize())
	}

	// Check quota limits
	if err := s.checkQuota(ctx, tenantID, templateType, int64(len(content))); err != nil {
		return nil, err
	}

	// Check if name already exists
	exists, err := s.repo.ExistsByName(ctx, tenantID, templateType, input.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing template: %w", err)
	}
	if exists {
		return nil, shared.NewDomainError("ALREADY_EXISTS", "template with this name already exists", shared.ErrAlreadyExists)
	}

	// Validate template content
	validationResult := template.ValidateTemplate(templateType, content)
	if !validationResult.Valid {
		return nil, shared.NewDomainError("VALIDATION", validationResult.ErrorMessages(), shared.ErrValidation)
	}

	// Create template
	template, err := scannertemplate.NewScannerTemplate(tenantID, input.Name, templateType, content, createdBy)
	if err != nil {
		return nil, err
	}

	// Set additional fields
	template.Description = input.Description
	template.Tags = input.Tags
	template.RuleCount = validationResult.RuleCount

	// Set metadata from validation
	for k, v := range validationResult.Metadata {
		template.SetMetadata(k, v)
	}

	// Sign the template
	signature := scannertemplate.ComputeSignature(content, s.signingSecret)
	template.SetSignature(signature)

	// Approved for sensors at once when the policy asks no approval: the
	// signer accepts the version before it is saved.
	if err := s.approveIfPolicyAllows(ctx, template); err != nil {
		return nil, err
	}

	// Persist
	if err := s.repo.Create(ctx, template); err != nil {
		return nil, err
	}

	s.logger.Info("created scanner template", "id", template.ID.String(), "name", template.Name, "rule_count", template.RuleCount)
	return template, nil
}

// GetTemplate retrieves a scanner template by ID.
func (s *ScannerTemplateService) GetTemplate(ctx context.Context, tenantID, templateID string) (*scannertemplate.ScannerTemplate, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	tmplID, err := shared.IDFromString(templateID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid template id", shared.ErrValidation)
	}

	return s.repo.GetByTenantAndID(ctx, tid, tmplID)
}

// ListScannerTemplatesInput represents the input for listing scanner templates.
type ListScannerTemplatesInput struct {
	TenantID     string   `json:"tenant_id" validate:"required,uuid"`
	TemplateType *string  `json:"template_type" validate:"omitempty,oneof=nuclei semgrep betterleaks"`
	Status       *string  `json:"status" validate:"omitempty,oneof=active pending_review deprecated revoked"`
	Tags         []string `json:"tags"`
	Search       string   `json:"search" validate:"max=255"`
	Page         int      `json:"page"`
	PerPage      int      `json:"per_page"`
}

// ListTemplates lists scanner templates with filters.
func (s *ScannerTemplateService) ListTemplates(ctx context.Context, input ListScannerTemplatesInput) (pagination.Result[*scannertemplate.ScannerTemplate], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*scannertemplate.ScannerTemplate]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := scannertemplate.Filter{
		TenantID: &tenantID,
		Tags:     input.Tags,
		Search:   input.Search,
	}

	if input.TemplateType != nil {
		tt := scannertemplate.TemplateType(*input.TemplateType)
		filter.TemplateType = &tt
	}

	if input.Status != nil {
		st := scannertemplate.TemplateStatus(*input.Status)
		filter.Status = &st
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.repo.List(ctx, filter, page)
}

// UpdateScannerTemplateInput represents the input for updating a scanner template.
type UpdateScannerTemplateInput struct {
	TenantID    string   `json:"tenant_id" validate:"required,uuid"`
	TemplateID  string   `json:"template_id" validate:"required,uuid"`
	Name        string   `json:"name" validate:"omitempty,min=1,max=255"`
	Description string   `json:"description" validate:"max=1000"`
	Content     string   `json:"content"` // Base64 encoded, optional
	Tags        []string `json:"tags" validate:"max=20,dive,max=50"`
	// UserID is who changes it: the author of a new content version.
	UserID string `json:"-"`
}

// UpdateTemplate updates an existing scanner template.
func (s *ScannerTemplateService) UpdateTemplate(ctx context.Context, input UpdateScannerTemplateInput) (*scannertemplate.ScannerTemplate, error) {
	s.logger.Info("updating scanner template", "template_id", input.TemplateID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	tmpl, err := s.GetTemplate(ctx, input.TenantID, input.TemplateID)
	if err != nil {
		return nil, err
	}

	// Validate ownership
	if err := tmpl.CanManage(tenantID); err != nil {
		return nil, err
	}

	// Decode content if provided
	var content []byte
	if input.Content != "" {
		content, err = base64.StdEncoding.DecodeString(input.Content)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid base64 content", shared.ErrValidation)
		}

		// Validate new content
		validationResult := template.ValidateTemplate(tmpl.TemplateType, content)
		if !validationResult.Valid {
			return nil, shared.NewDomainError("VALIDATION", validationResult.ErrorMessages(), shared.ErrValidation)
		}

		// Update rule count and metadata
		tmpl.RuleCount = validationResult.RuleCount
		for k, v := range validationResult.Metadata {
			tmpl.SetMetadata(k, v)
		}
	}

	// Update template
	wasApproved := tmpl.ApprovedForSensors()
	if err := tmpl.Update(input.Name, input.Description, content, input.Tags); err != nil {
		return nil, err
	}

	// Re-sign if content changed
	if content != nil {
		signature := scannertemplate.ComputeSignature(content, s.signingSecret)
		tmpl.SetSignature(signature)
		if !tmpl.ApprovedForSensors() {
			// A new version: its author cannot approve it, and it is
			// approved at once only when the policy asks no approval.
			var author *shared.ID
			if id, err := shared.IDFromString(input.UserID); err == nil {
				author = &id
			}
			tmpl.SetContentAuthor(author)
			if err := s.approveIfPolicyAllows(ctx, tmpl); err != nil {
				return nil, err
			}
		}
	}

	if err := s.repo.Update(ctx, tmpl); err != nil {
		return nil, err
	}
	if wasApproved && !tmpl.ApprovedForSensors() {
		s.removeTemplate(ctx, tmpl)
	}

	return tmpl, nil
}

// DeleteTemplate deletes a scanner template.
func (s *ScannerTemplateService) DeleteTemplate(ctx context.Context, tenantID, templateID string) error {
	s.logger.Info("deleting scanner template", "template_id", templateID)

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	template, err := s.GetTemplate(ctx, tenantID, templateID)
	if err != nil {
		return err
	}

	// Validate ownership
	if err := template.CanManage(tid); err != nil {
		return err
	}

	if err := s.repo.Delete(ctx, tid, template.ID); err != nil {
		return err
	}
	if template.ApprovedForSensors() {
		s.removeTemplate(ctx, template)
	}
	return nil
}

// ValidateTemplateInput represents the input for validating template content.
type ValidateTemplateInput struct {
	TemplateType string `json:"template_type" validate:"required,oneof=nuclei semgrep betterleaks"`
	Content      string `json:"content" validate:"required"` // Base64 encoded
}

// ValidateTemplate validates template content without saving.
func (s *ScannerTemplateService) ValidateTemplate(ctx context.Context, input ValidateTemplateInput) (*template.ValidationResult, error) {
	templateType := scannertemplate.TemplateType(input.TemplateType)
	if !templateType.IsValid() {
		return nil, fmt.Errorf("%w: invalid template type", shared.ErrValidation)
	}

	content, err := base64.StdEncoding.DecodeString(input.Content)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64 content", shared.ErrValidation)
	}

	// Check size limit
	if int64(len(content)) > templateType.MaxSize() {
		result := &template.ValidationResult{Valid: false}
		result.AddError("content", fmt.Sprintf("content exceeds maximum size of %d bytes", templateType.MaxSize()), "SIZE_EXCEEDED")
		return result, nil
	}

	return template.ValidateTemplate(templateType, content), nil
}

// DownloadTemplate returns the template content for download.
func (s *ScannerTemplateService) DownloadTemplate(ctx context.Context, tenantID, templateID string) ([]byte, string, error) {
	template, err := s.GetTemplate(ctx, tenantID, templateID)
	if err != nil {
		return nil, "", err
	}

	filename := template.Name + template.TemplateType.FileExtension()
	return template.Content, filename, nil
}

// DeprecateTemplate marks a template as deprecated.
func (s *ScannerTemplateService) DeprecateTemplate(ctx context.Context, tenantID, templateID string) (*scannertemplate.ScannerTemplate, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	template, err := s.GetTemplate(ctx, tenantID, templateID)
	if err != nil {
		return nil, err
	}

	if err := template.CanManage(tid); err != nil {
		return nil, err
	}

	wasApproved := template.ApprovedForSensors()
	template.Deprecate()

	if err := s.repo.Update(ctx, template); err != nil {
		return nil, err
	}
	if wasApproved {
		s.removeTemplate(ctx, template)
	}

	return template, nil
}

// GetTemplatesByIDs retrieves multiple templates by their IDs.
func (s *ScannerTemplateService) GetTemplatesByIDs(ctx context.Context, tenantID string, templateIDs []string) ([]*scannertemplate.ScannerTemplate, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	ids := make([]shared.ID, 0, len(templateIDs))
	for _, idStr := range templateIDs {
		id, err := shared.IDFromString(idStr)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid template id: %s", shared.ErrValidation, idStr)
		}
		ids = append(ids, id)
	}

	return s.repo.ListByIDs(ctx, tid, ids)
}

// VerifyTemplateSignature verifies the signature of a template.
func (s *ScannerTemplateService) VerifyTemplateSignature(template *scannertemplate.ScannerTemplate) bool {
	return template.VerifySignature(s.signingSecret)
}

// GetUsage returns the current template usage for a tenant.
func (s *ScannerTemplateService) GetUsage(ctx context.Context, tenantID string) (*TemplateUsageResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	usage, err := s.repo.GetUsage(ctx, tid)
	if err != nil {
		return nil, err
	}

	return &TemplateUsageResult{
		Usage: *usage,
		Quota: s.quota,
	}, nil
}

// GetQuota returns the current quota configuration.
func (s *ScannerTemplateService) GetQuota() scannertemplate.TemplateQuota {
	return s.quota
}

// TemplateUsageResult combines usage and quota information.
type TemplateUsageResult struct {
	Usage scannertemplate.TemplateUsage `json:"usage"`
	Quota scannertemplate.TemplateQuota `json:"quota"`
}

// checkQuota verifies that adding a new template won't exceed quota limits.
func (s *ScannerTemplateService) checkQuota(ctx context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType, contentSize int64) error {
	usage, err := s.repo.GetUsage(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to check quota: %w", err)
	}

	// Check total template count
	if usage.TotalTemplates >= int64(s.quota.MaxTemplates) {
		return shared.NewDomainError(
			"QUOTA_EXCEEDED",
			fmt.Sprintf("template quota exceeded: maximum %d templates allowed, currently have %d", s.quota.MaxTemplates, usage.TotalTemplates),
			shared.ErrForbidden,
		)
	}

	// Check per-type template count
	maxForType := s.quota.GetMaxForType(templateType)
	var currentCount int64
	switch templateType {
	case scannertemplate.TemplateTypeNuclei:
		currentCount = usage.NucleiTemplates
	case scannertemplate.TemplateTypeSemgrep:
		currentCount = usage.SemgrepTemplates
	case scannertemplate.TemplateTypeBetterleaks:
		currentCount = usage.BetterleaksTemplates
	}

	if currentCount >= int64(maxForType) {
		return shared.NewDomainError(
			"QUOTA_EXCEEDED",
			fmt.Sprintf("%s template quota exceeded: maximum %d templates allowed, currently have %d", templateType, maxForType, currentCount),
			shared.ErrForbidden,
		)
	}

	// Check total storage
	if usage.TotalStorageBytes+contentSize > s.quota.MaxTotalStorageBytes {
		return shared.NewDomainError(
			"QUOTA_EXCEEDED",
			fmt.Sprintf("storage quota exceeded: maximum %d bytes allowed, current usage %d bytes, requested %d bytes",
				s.quota.MaxTotalStorageBytes, usage.TotalStorageBytes, contentSize),
			shared.ErrForbidden,
		)
	}

	return nil
}
