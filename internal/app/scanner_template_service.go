package app

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/openctemio/api/internal/app/validators"
	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ScannerTemplateService handles scanner template business operations.
type ScannerTemplateService struct {
	repo          scannertemplate.Repository
	signingSecret string
	logger        *logger.Logger
	quota         scannertemplate.TemplateQuota
}

// NewScannerTemplateService creates a new ScannerTemplateService.
func NewScannerTemplateService(repo scannertemplate.Repository, signingSecret string, log *logger.Logger) *ScannerTemplateService {
	return &ScannerTemplateService{
		repo:          repo,
		signingSecret: signingSecret,
		logger:        log.With("service", "scanner_template"),
		quota:         scannertemplate.DefaultQuota(),
	}
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
	TemplateType string   `json:"template_type" validate:"required,oneof=nuclei semgrep gitleaks"`
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
	validationResult := validators.ValidateTemplate(templateType, content)
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
	TemplateType *string  `json:"template_type" validate:"omitempty,oneof=nuclei semgrep gitleaks"`
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
}

// UpdateTemplate updates an existing scanner template.
func (s *ScannerTemplateService) UpdateTemplate(ctx context.Context, input UpdateScannerTemplateInput) (*scannertemplate.ScannerTemplate, error) {
	s.logger.Info("updating scanner template", "template_id", input.TemplateID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	template, err := s.GetTemplate(ctx, input.TenantID, input.TemplateID)
	if err != nil {
		return nil, err
	}

	// Validate ownership
	if err := template.CanManage(tenantID); err != nil {
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
		validationResult := validators.ValidateTemplate(template.TemplateType, content)
		if !validationResult.Valid {
			return nil, shared.NewDomainError("VALIDATION", validationResult.ErrorMessages(), shared.ErrValidation)
		}

		// Update rule count and metadata
		template.RuleCount = validationResult.RuleCount
		for k, v := range validationResult.Metadata {
			template.SetMetadata(k, v)
		}
	}

	// Update template
	if err := template.Update(input.Name, input.Description, content, input.Tags); err != nil {
		return nil, err
	}

	// Re-sign if content changed
	if content != nil {
		signature := scannertemplate.ComputeSignature(content, s.signingSecret)
		template.SetSignature(signature)
	}

	if err := s.repo.Update(ctx, template); err != nil {
		return nil, err
	}

	return template, nil
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

	return s.repo.Delete(ctx, template.ID)
}

// ValidateTemplateInput represents the input for validating template content.
type ValidateTemplateInput struct {
	TemplateType string `json:"template_type" validate:"required,oneof=nuclei semgrep gitleaks"`
	Content      string `json:"content" validate:"required"` // Base64 encoded
}

// ValidateTemplate validates template content without saving.
func (s *ScannerTemplateService) ValidateTemplate(ctx context.Context, input ValidateTemplateInput) (*validators.ValidationResult, error) {
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
		result := &validators.ValidationResult{Valid: false}
		result.AddError("content", fmt.Sprintf("content exceeds maximum size of %d bytes", templateType.MaxSize()), "SIZE_EXCEEDED")
		return result, nil
	}

	return validators.ValidateTemplate(templateType, content), nil
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

	template.Deprecate()

	if err := s.repo.Update(ctx, template); err != nil {
		return nil, err
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
	case scannertemplate.TemplateTypeGitleaks:
		currentCount = usage.GitleaksTemplates
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
