package main

import (
	"fmt"
	"io"

	"github.com/openctemio/openctem/api/internal/config"
)

// reportConfigCheck is `server -check-config`: the configuration preflight an
// operator runs before a deploy (or as an init step). It reports the first
// problem config.Load found, or a summary of the settings that decide which
// checks applied. It never prints secret values.
func reportConfigCheck(stdout, stderr io.Writer, cfg *config.Config, loadErr error) int {
	if loadErr != nil {
		fmt.Fprintf(stderr, "configuration INVALID: %v\n", loadErr)
		return 1
	}
	fmt.Fprintf(stdout, "configuration valid: APP_ENV=%s AUTH_PROVIDER=%s TENANT_CREATION_MODE=%s SCOPE_ACTIVE_PROOF=%s\n",
		cfg.App.Env, cfg.Auth.Provider, cfg.Auth.TenantCreationMode, cfg.Scope.ActiveProof)
	if !cfg.IsProduction() {
		fmt.Fprintf(stdout, "note: APP_ENV=%s skips the production checks (TLS to Postgres and Redis, secret strength, rate limits); "+
			"unset APP_ENV or set APP_ENV=production for a production deployment\n", cfg.App.Env)
	}
	return 0
}
