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
// console's administrator table or its second factors (passkeys, recovery
// codes): either lets a SQL injection take over a platform administrator.
func appRoleWritesConsoleTables(ctx context.Context, db *sql.DB) (bool, error) {
	var writes bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM unnest(ARRAY['admin_users', 'admin_webauthn_credentials', 'admin_recovery_codes']) AS t
		WHERE to_regclass('public.' || t) IS NOT NULL
		  AND has_table_privilege(current_user, 'public.' || t, 'INSERT'))`).Scan(&writes)
	return writes, err
}

// consoleTablesVerdict decides what the privilege check means. A tenant-plane
// process serves tenants and is the one a SQL injection reaches, so in
// production a role that can write admin_users or the console's second
// factors (or a check that could not run) stops the start. Elsewhere it is a loud log line.
func consoleTablesVerdict(plane string, production, writes bool, checkErr error) error {
	if plane == config.PlaneTenant && production {
		if checkErr != nil {
			return fmt.Errorf("could not check the API role's privileges on the console identity tables: %w", checkErr)
		}
		if writes {
			return errors.New("DB_USER can write admin_users or the console passkeys/recovery codes on the tenant plane: " +
				"a SQL injection could take over an administrator; run the least-privilege bootstrap of this release " +
				"with admin_user (the db-roles job)")
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
		log.Warn("could not check the API role's privileges on the console identity tables", "error", err)
	case writes:
		log.Error("DB_USER can still write admin_users or the console passkeys/recovery codes: " +
			"rerun the least-privilege bootstrap of this release with admin_user (the db-roles job)")
	}
	return nil
}
