package main

import (
	"context"
	"database/sql"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// warnIfAppRoleWritesConsoleTables: with DB_ADMIN_USER set the split only
// protects anything once the least-privilege bootstrap ran with admin_user
// (the db-roles job). Until then DB_USER still writes admin_users; say so
// loudly instead of pretending.
func warnIfAppRoleWritesConsoleTables(ctx context.Context, db *sql.DB, log *logger.Logger) {
	var writes bool
	err := db.QueryRowContext(ctx, `SELECT to_regclass('public.admin_users') IS NOT NULL
		AND has_table_privilege(current_user, 'public.admin_users', 'INSERT')`).Scan(&writes)
	if err != nil {
		log.Warn("could not check the API role's privileges on admin_users", "error", err)
		return
	}
	if writes {
		log.Error("DB_ADMIN_USER is set but DB_USER can still write admin_users: " +
			"rerun the least-privilege bootstrap with admin_user (the db-roles job)")
	}
}
