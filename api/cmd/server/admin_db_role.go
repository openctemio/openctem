package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// appRoleWritesConsoleTables reports whether the connected role can write the
// console's administrator table.
func appRoleWritesConsoleTables(ctx context.Context, db *sql.DB) (bool, error) {
	var writes bool
	err := db.QueryRowContext(ctx, `SELECT to_regclass('public.admin_users') IS NOT NULL
		AND has_table_privilege(current_user, 'public.admin_users', 'INSERT')`).Scan(&writes)
	return writes, err
}

// consoleTablesVerdict decides what the privilege check means. A tenant-plane
// process serves tenants and is the one a SQL injection reaches, so in
// production a role that can write admin_users (or a check that could not
// run) stops the start. Elsewhere it is a loud log line.
func consoleTablesVerdict(plane string, production, writes bool, checkErr error) error {
	if plane == config.PlaneTenant && production {
		if checkErr != nil {
			return fmt.Errorf("could not check the API role's privileges on admin_users: %w", checkErr)
		}
		if writes {
			return errors.New("DB_USER can write admin_users on the tenant plane: a SQL injection could add an " +
				"administrator; run the least-privilege bootstrap with admin_user (the db-roles job)")
		}
	}
	return nil
}

// checkAppRoleConsoleTables runs the check for the tenant plane (always) and
// whenever DB_ADMIN_USER is set (the split only protects anything once the
// least-privilege bootstrap ran with admin_user). It returns an error only
// when the process must not start.
func checkAppRoleConsoleTables(ctx context.Context, db *sql.DB, cfg *config.Config, log *logger.Logger) error {
	tenantPlane := cfg.AdminPlane.Plane == config.PlaneTenant
	if !tenantPlane && cfg.Database.AdminUser == "" {
		return nil
	}
	writes, err := appRoleWritesConsoleTables(ctx, db)
	if verr := consoleTablesVerdict(cfg.AdminPlane.Plane, cfg.IsProduction(), writes, err); verr != nil {
		return verr
	}
	switch {
	case err != nil:
		log.Warn("could not check the API role's privileges on admin_users", "error", err)
	case writes:
		log.Error("DB_USER can still write admin_users: " +
			"rerun the least-privilege bootstrap with admin_user (the db-roles job)")
	}
	return nil
}
