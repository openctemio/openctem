package auth

import (
	"context"

	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	emaildom "github.com/openctemio/api/pkg/email"
	"github.com/openctemio/api/pkg/logger"
)

// IntegrationSMTPResolver resolves per-tenant SMTP config from notification integrations.
// When a tenant creates an email integration (category=notification, provider=email),
// the SMTP settings are stored encrypted in the integration's config/credentials.
type IntegrationSMTPResolver struct {
	integrationRepo integration.Repository
	logger          *logger.Logger
}

// NewIntegrationSMTPResolver creates a new resolver.
func NewIntegrationSMTPResolver(repo integration.Repository, log *logger.Logger) *IntegrationSMTPResolver {
	return &IntegrationSMTPResolver{
		integrationRepo: repo,
		logger:          log.With("component", "tenant_smtp_resolver"),
	}
}

// GetTenantSMTPConfig looks up the tenant's email integration and returns SMTP config.
// Returns nil if no email integration is configured for this tenant.
func (r *IntegrationSMTPResolver) GetTenantSMTPConfig(ctx context.Context, tenantID string) (*emaildom.Config, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, nil // Invalid tenant ID, use default
	}

	// Find email notification integration for this tenant
	integrations, err := r.integrationRepo.ListByCategory(ctx, parsedTenantID, integration.CategoryNotification)
	if err != nil {
		r.logger.Debug("failed to list integrations", "tenant_id", tenantID, "error", err)
		return nil, nil // Fallback to default on error
	}

	// Find the first active email provider integration
	for _, intg := range integrations {
		if intg.Provider() == integration.ProviderEmail && intg.Status() == integration.StatusConnected {
			cfg := r.extractSMTPConfig(intg)
			if cfg != nil {
				r.logger.Debug("using tenant SMTP config",
					"tenant_id", tenantID,
					"integration_id", intg.ID().String(),
				)
				return cfg, nil
			}
		}
	}

	return nil, nil // No email integration found
}

// extractSMTPConfig builds emaildom.Config from integration metadata.
func (r *IntegrationSMTPResolver) extractSMTPConfig(intg *integration.Integration) *emaildom.Config {
	meta := intg.Metadata()
	if meta == nil {
		return nil
	}

	host, _ := meta["smtp_host"].(string)
	if host == "" {
		return nil
	}

	port := 587
	if p, ok := meta["smtp_port"].(float64); ok {
		port = int(p)
	}

	cfg := &emaildom.Config{
		Host: host,
		Port: port,
	}

	if user, ok := meta["smtp_user"].(string); ok {
		cfg.User = user
	}
	if pass, ok := meta["smtp_password"].(string); ok {
		cfg.Password = pass
	}
	if from, ok := meta["smtp_from"].(string); ok {
		cfg.From = from
	}
	if fromName, ok := meta["smtp_from_name"].(string); ok {
		cfg.FromName = fromName
	}
	if tls, ok := meta["smtp_tls"].(bool); ok {
		cfg.TLS = tls
	}

	// Validate minimum config
	if cfg.Host == "" || cfg.Port == 0 || cfg.From == "" {
		return nil
	}

	return cfg
}

// ListByTenantAndCategory is a helper interface check.
// This method should exist on integration.Repository.
// If not, we need to use List with filter.
func init() {
	// Compile-time check that the resolver implements TenantSMTPResolver
	var _ TenantSMTPResolver = (*IntegrationSMTPResolver)(nil)
}

// SMTPConfigFromIntegrationMeta extracts SMTP config fields for creating an email integration.
// Used by the UI when creating/editing an email notification integration.
func SMTPConfigFromIntegrationMeta() map[string]string {
	return map[string]string{
		"smtp_host":      "SMTP server hostname (e.g., smtp.gmail.com)",
		"smtp_port":      "SMTP port (587 for STARTTLS, 465 for TLS)",
		"smtp_user":      "SMTP username",
		"smtp_password":  "SMTP password",
		"smtp_from":      "Sender email address",
		"smtp_from_name": "Sender display name",
		"smtp_tls":       "Use TLS (true/false)",
	}
}
