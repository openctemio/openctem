package jira

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	appjira "github.com/openctemio/api/internal/app/jira"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// clientAdapter adapts the concrete infra *Client to the app-layer
// appjira.Client interface (the two packages declare distinct
// CreateIssueInput/Result types, so the conversion happens here).
type clientAdapter struct{ c *Client }

func (a clientAdapter) CreateIssue(ctx context.Context, in appjira.CreateIssueInput) (*appjira.CreateIssueResult, error) {
	res, err := a.c.CreateIssue(ctx, CreateIssueInput{
		ProjectKey:  in.ProjectKey,
		Summary:     in.Summary,
		Description: in.Description,
		IssueType:   in.IssueType,
		Priority:    in.Priority,
		Labels:      in.Labels,
	})
	if err != nil {
		return nil, err
	}
	return &appjira.CreateIssueResult{
		ID:        res.ID,
		Key:       res.Key,
		BrowseURL: res.BrowseURL,
	}, nil
}

func (a clientAdapter) TestConnection(ctx context.Context) error {
	return a.c.TestConnection(ctx)
}

// IntegrationClientResolver resolves a per-tenant Jira client from the tenant's
// ticketing integration. It mirrors the per-tenant SMTP resolver: load the
// tenant's active integration, decrypt its credentials, and build a client on
// demand. Without this, outbound ticket creation is inert (the SyncService is
// wired with a nil static client in production).
type IntegrationClientResolver struct {
	integrationRepo integration.Repository
	decrypt         func(string) (string, error)
	logger          *logger.Logger
}

// NewIntegrationClientResolver creates a resolver. The encryptor is used to
// decrypt the stored Jira API token; a nil encryptor falls back to treating
// credentials as plaintext (dev only), matching IntegrationService behaviour.
func NewIntegrationClientResolver(repo integration.Repository, encryptor crypto.Encryptor, log *logger.Logger) *IntegrationClientResolver {
	decrypt := func(s string) (string, error) { return s, nil }
	if encryptor != nil {
		decrypt = encryptor.DecryptString
	}
	return &IntegrationClientResolver{
		integrationRepo: repo,
		decrypt:         decrypt,
		logger:          log.With("component", "jira_client_resolver"),
	}
}

// Compile-time check that the resolver satisfies the app-layer interface.
var _ appjira.ClientResolver = (*IntegrationClientResolver)(nil)

// Resolve returns a Jira client for the tenant's first connected Jira
// integration. Returns appjira.ErrNoTicketingIntegration when none is usable.
func (r *IntegrationClientResolver) Resolve(ctx context.Context, tenantID shared.ID) (appjira.Client, error) {
	integrations, err := r.integrationRepo.ListByProvider(ctx, tenantID, integration.ProviderJira)
	if err != nil {
		return nil, fmt.Errorf("list jira integrations: %w", err)
	}

	for _, intg := range integrations {
		if intg.Status() != integration.StatusConnected {
			continue
		}
		client, err := r.buildClient(intg)
		if err != nil {
			// Skip misconfigured integrations rather than failing hard — a
			// tenant may have several, only some usable. The reason is logged.
			r.logger.Warn("skipping jira integration: cannot build client",
				"integration_id", intg.ID().String(),
				"tenant_id", tenantID.String(),
				"error", err,
			)
			continue
		}
		return client, nil
	}

	return nil, appjira.ErrNoTicketingIntegration
}

// buildClient assembles a Jira client from an integration's base URL and
// decrypted credentials.
func (r *IntegrationClientResolver) buildClient(intg *integration.Integration) (appjira.Client, error) {
	baseURL := intg.BaseURL()
	if baseURL == "" {
		baseURL = stringFromMap(intg.Config(), "base_url")
	}
	if baseURL == "" {
		return nil, fmt.Errorf("integration %s has no base URL", intg.ID())
	}

	email, token, err := r.resolveCredentials(intg)
	if err != nil {
		return nil, err
	}

	c, err := NewClient(baseURL, email, token)
	if err != nil {
		return nil, err
	}
	return clientAdapter{c: c}, nil
}

// resolveCredentials extracts the Jira account email + API token from an
// integration. Jira Cloud basic auth needs both. Supported credential shapes,
// in priority order:
//
//  1. JSON object: {"email":"...","api_token":"..."} (preferred — the UI sends
//     this so both fields travel encrypted together).
//  2. Bare token string, with the email read from config/metadata["email"].
//  3. Legacy packed "email:token" string.
func (r *IntegrationClientResolver) resolveCredentials(intg *integration.Integration) (email, token string, err error) {
	raw := intg.CredentialsEncrypted()
	if raw == "" {
		return "", "", fmt.Errorf("integration %s has no credentials", intg.ID())
	}

	dec, derr := r.decrypt(raw)
	if derr != nil {
		// Decryption failed — assume the value was stored plaintext (backward
		// compatible with pre-encryption integrations, matching IntegrationService).
		dec = raw
	}
	dec = strings.TrimSpace(dec)

	// Shape 1: JSON credentials.
	var creds struct {
		Email    string `json:"email"`
		APIToken string `json:"api_token"`
		Token    string `json:"token"`
	}
	if json.Unmarshal([]byte(dec), &creds) == nil && (creds.APIToken != "" || creds.Token != "") {
		email = creds.Email
		token = creds.APIToken
		if token == "" {
			token = creds.Token
		}
	} else {
		// Shape 2: bare token.
		token = dec
	}

	// Email fallback from non-sensitive config/metadata.
	if email == "" {
		email = stringFromMap(intg.Config(), "email")
	}
	if email == "" {
		email = stringFromMap(intg.Metadata(), "email")
	}

	// Shape 3: legacy "email:token" packed form.
	if email == "" && strings.Count(token, ":") == 1 {
		parts := strings.SplitN(token, ":", 2)
		if strings.Contains(parts[0], "@") {
			email, token = parts[0], parts[1]
		}
	}

	if token == "" {
		return "", "", fmt.Errorf("integration %s missing api token", intg.ID())
	}
	if email == "" {
		return "", "", fmt.Errorf("integration %s missing account email (store it in JSON credentials or config)", intg.ID())
	}
	return email, token, nil
}

// stringFromMap reads a string value from a map, tolerating a nil map.
func stringFromMap(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
