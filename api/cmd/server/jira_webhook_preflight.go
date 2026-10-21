package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// Startup check for inbound Jira webhook secrets.
//
// The inbound Jira webhook verifies every delivery with the HMAC secret of
// the integration named in its URL (/hooks/jira-integrations/{id}; there is
// no platform-wide secret). A connected Jira integration without its own
// secret therefore has every delivery refused, which is safe but silent. This check runs once at
// startup and logs a warning so the operator sees the gap.
//
// It never refuses to start: a missing secret only affects that
// organization's webhook, and one organization's configuration must not
// stop the platform for every other organization.
//
// Cross-tenant read is intentional here: this is a platform-level operator
// check (a count, no tenant data leaves it).

// jiraIntegrationProbe is the minimum DB surface the check needs.
// *sql.DB satisfies it directly.
type jiraIntegrationProbe interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// countJiraIntegrationsWithoutSecret counts connected Jira integrations that
// have no per-organization webhook secret.
func countJiraIntegrationsWithoutSecret(ctx context.Context, db jiraIntegrationProbe) (int, error) {
	if db == nil {
		return 0, nil
	}
	const q = `SELECT COUNT(*) FROM integrations
		WHERE provider = 'jira' AND status = 'connected'
		AND COALESCE(metadata->>'webhook_secret_encrypted', '') = ''`
	var n int
	if err := db.QueryRowContext(ctx, q).Scan(&n); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("jira integration preflight query: %w", err)
	}
	return n, nil
}

// warnJiraIntegrationsWithoutSecret logs a warning when a connected Jira
// integration has no webhook secret. Query errors are logged and ignored:
// the HMAC middleware is the enforcement, this is only an operator aid.
func warnJiraIntegrationsWithoutSecret(ctx context.Context, db jiraIntegrationProbe, log *logger.Logger) {
	n, err := countJiraIntegrationsWithoutSecret(ctx, db)
	if err != nil {
		log.Warn("jira webhook preflight query failed; skipping", "error", err)
		return
	}
	if n == 0 {
		return
	}
	log.Warn("jira webhook preflight: connected Jira integrations have no webhook secret",
		"count", n,
		"impact", "their inbound webhook deliveries are refused (401) until the organization sets a secret",
		"remediation", "the organization rotates its secret with POST /api/v1/integrations/jira/webhook-secret/rotate")
}
