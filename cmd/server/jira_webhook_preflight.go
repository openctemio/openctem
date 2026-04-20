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
// but the HMAC secret is not configured in production.
var ErrJiraWebhookSecretMissing = errors.New("JIRA_WEBHOOK_SECRET is required when a Jira integration is active; inbound webhooks will fail until it is set")

// jiraIntegrationProbe is the minimum DB surface the preflight needs.
// *sql.DB satisfies this directly; the narrow interface also keeps the
// preflight unit-testable without pulling in a sqlmock dependency.
type jiraIntegrationProbe interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// DB-level behaviour is covered by an integration test once the shared
// test harness lands (see `tests/integration/`). The unit tests in this
// package focus on the config-branching logic and error sentinel.

// anyJiraIntegrationConnected reports whether any tenant currently has a
// connected Jira integration row. Uses a plain SELECT 1 with LIMIT 1 so we
// do not scan the whole table.
func anyJiraIntegrationConnected(ctx context.Context, db jiraIntegrationProbe) (bool, error) {
	if db == nil {
		return false, nil
	}
	const q = `SELECT 1 FROM integrations WHERE provider = 'jira' AND status = 'connected' LIMIT 1`
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
	// Secret configured — nothing to check.
	if cfg.Webhooks.JiraSecret != "" {
		return nil
	}

	anyJira, err := anyJiraIntegrationConnected(ctx, db)
	if err != nil {
		// Do not fail startup on a preflight query error — log and continue.
		// The HMAC middleware itself is the enforcement; the preflight is
		// only an operator aid.
		log.Warn("jira webhook preflight query failed; skipping", "error", err)
		return nil
	}
	if !anyJira {
		return nil
	}

	if cfg.IsProduction() {
		log.Error("jira webhook preflight: refusing to start in production",
			"reason", "JIRA_WEBHOOK_SECRET not set but an active Jira integration exists",
			"remediation", "set JIRA_WEBHOOK_SECRET to the shared HMAC secret configured in your Jira automation rule")
		return ErrJiraWebhookSecretMissing
	}

	log.Warn("jira webhook preflight: active Jira integration found but JIRA_WEBHOOK_SECRET is empty",
		"impact", "inbound webhook deliveries will return 401 until the secret is set",
		"remediation", "set JIRA_WEBHOOK_SECRET=<same shared secret used in Jira automation rule>")
	return nil
}
