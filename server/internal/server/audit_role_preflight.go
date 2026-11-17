package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/server/pkg/logger"
)

// Startup check: does the API connect as the owner of the audit tables?
//
// Audit history may only be deleted or rewritten through the schema owner's
// functions audit_chain_prune_prefix and audit_chain_rebaseline_apply
// (docs/architecture/audit-hash-chain.md). That holds against the API's own
// credentials only when the API connects as a role that does not own the
// tables (deploy/postgres/least-privilege-roles.sql). An installation that
// runs migrations and the API as one role keeps working, but there anyone
// holding the API's credentials can change audit history (the owner may drop
// a trigger), and only chain verification would show it. The check logs a
// warning so the operator sees it. It never refuses to start.

type auditOwnerProbe interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// apiRoleOwnsAuditLog reports whether the connected role owns audit_logs
// (directly or through role membership).
func apiRoleOwnsAuditLog(ctx context.Context, db auditOwnerProbe) (bool, error) {
	if db == nil {
		return false, nil
	}
	var owns bool
	err := db.QueryRowContext(ctx, `
		SELECT pg_has_role(current_user, c.relowner, 'USAGE')
		  FROM pg_class c
		 WHERE c.oid = to_regclass('public.audit_logs')`).Scan(&owns)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("audit owner preflight query: %w", err)
	}
	return owns, nil
}

func warnAPIRoleOwnsAuditLog(ctx context.Context, db auditOwnerProbe, log *logger.Logger) {
	owns, err := apiRoleOwnsAuditLog(ctx, db)
	if err != nil {
		log.Warn("audit owner preflight query failed; skipping", "error", err)
		return
	}
	if !owns {
		return
	}
	log.Warn("audit log preflight: the API connects as the owner of the audit tables",
		"impact", "the database cannot stop a holder of the API's credentials from changing audit history; chain verification still reports it",
		"remediation", "run deploy/postgres/least-privilege-roles.sql and connect the API as the app role (docs/deployment/database-roles.md)")
}
