package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/logger"
)

// P0-2: startup preflight for Jira webhook HMAC configuration.
//
// F-1 added an HMAC gate on the inbound Jira webhook. The middleware fails
// closed on every request when the secret is empty — which is correct from
// a security standpoint but silent from an operator standpoint. An operator
// who forgets to set JIRA_WEBHOOK_SECRET while a tenant has an active Jira
// integration will see Jira deliveries start 401'ing with no clear root
// cause.
//
// This preflight runs once at startup, checks whether any tenant has a
// connected Jira integration, and:
//
//   - in production: refuses to start if the secret is missing
//   - elsewhere: logs a loud WARN so the operator sees the gap in logs
//
// Running the query once at startup is cheap (indexed on provider).
// Cross-tenant read is intentional here — this is a platform-level
// operator check, not a per-tenant query.

// ErrJiraWebhookSecretMissing is returned when a Jira integration exists
// but neither a per-tenant webhook secret nor the platform JIRA_WEBHOOK_SECRET
// is configured in production.
var ErrJiraWebhookSecretMissing = errors.New("a Jira integration is active with no webhook secret configured (neither a per-tenant secret nor JIRA_WEBHOOK_SECRET); inbound webhooks will fail until one is set")

// jiraIntegrationProbe is the minimum DB surface the preflight needs.
// *sql.DB satisfies this directly; the narrow interface also keeps the
// preflight unit-testable without pulling in a sqlmock dependency.
type jiraIntegrationProbe interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// DB-level behaviour is covered by an integration test once the shared
// test harness lands (see `tests/integration/`). The unit tests in this
// package focus on the config-branching logic and error sentinel.

// anyJiraIntegrationWithoutSecret reports whether any tenant has a connected
// Jira integration that has NOT configured a per-tenant webhook secret (in
// metadata). Such integrations rely on the platform JIRA_WEBHOOK_SECRET; if
// that is also unset their inbound webhooks fail closed. Uses SELECT 1 / LIMIT 1
// so we do not scan the whole table.
func anyJiraIntegrationWithoutSecret(ctx context.Context, db jiraIntegrationProbe) (bool, error) {
	if db == nil {
		return false, nil
	}
	const q = `SELECT 1 FROM integrations
		WHERE provider = 'jira' AND status = 'connected'
		AND COALESCE(metadata->>'webhook_secret_encrypted', '') = ''
		LIMIT 1`
	row := db.QueryRowContext(ctx, q)
	var dummy int
	err := row.Scan(&dummy)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("jira integration preflight query: %w", err)
	}
	return true, nil
}

// checkJiraWebhookPreflight runs P0-2. Returns an error only in production
// when a Jira integration is active but no secret is configured. In any
// other environment it logs a WARN and returns nil so local dev is
// uninterrupted.
func checkJiraWebhookPreflight(ctx context.Context, cfg *config.Config, db jiraIntegrationProbe, log *logger.Logger) error {
	// Platform secret configured — it covers every tenant as a fallback, so
	// no integration can be left without a usable secret.
	if cfg.Webhooks.JiraSecret != "" {
		return nil
	}

	// No platform fallback: flag any connected Jira integration that also lacks
	// its own per-tenant secret (those, and only those, would fail closed).
	anyUncovered, err := anyJiraIntegrationWithoutSecret(ctx, db)
	if err != nil {
		// Do not fail startup on a preflight query error — log and continue.
		// The HMAC middleware itself is the enforcement; the preflight is
		// only an operator aid.
		log.Warn("jira webhook preflight query failed; skipping", "error", err)
		return nil
	}
	if !anyUncovered {
		return nil
	}

	if cfg.IsProduction() {
		log.Error("jira webhook preflight: refusing to start in production",
			"reason", "a connected Jira integration has no per-tenant webhook secret and JIRA_WEBHOOK_SECRET is unset",
			"remediation", "configure the tenant's webhook secret via POST /api/v1/integrations/jira/webhook-secret/rotate, or set JIRA_WEBHOOK_SECRET as a platform fallback")
		return ErrJiraWebhookSecretMissing
	}

	log.Warn("jira webhook preflight: a connected Jira integration has no per-tenant webhook secret and JIRA_WEBHOOK_SECRET is empty",
		"impact", "that tenant's inbound webhook deliveries will return 401 until a secret is set",
		"remediation", "configure a per-tenant secret (GET/rotate /api/v1/integrations/jira/webhook-secret) or set JIRA_WEBHOOK_SECRET")
	return nil
}
