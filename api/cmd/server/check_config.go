package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/openctemio/openctem/api/internal/config"
)

// reportConfigCheck is `server -check-config`: the configuration preflight an
// operator runs before a deploy (or as an init step). It reports the first
// problem config.Load found, or a summary of the settings that decide which
// checks applied, the API variables set in environ (names only) and the
// warnings Load raised. It never prints values.
func reportConfigCheck(stdout, stderr io.Writer, cfg *config.Config, loadErr error, environ []string) int {
	if loadErr != nil {
		fmt.Fprintf(stderr, "configuration INVALID: %v\n", loadErr)
		return 1
	}
	fmt.Fprintf(stdout, "configuration valid: APP_ENV=%s AUTH_PROVIDER=%s SIGNUP_MODE=%s\n",
		cfg.App.Env, cfg.Auth.Provider, cfg.Auth.SignupMode)
	if set := config.SetAPIVariables(environ); len(set) > 0 {
		fmt.Fprintf(stdout, "set from the environment (%d; every other variable has its default): %s\n", len(set), strings.Join(set, " "))
	}
	for _, w := range cfg.EnvWarnings {
		fmt.Fprintf(stdout, "warning: %s\n", w)
	}
	for _, w := range cfg.WideTrustedProxies() {
		fmt.Fprintf(stdout, "warning: %s trusts every address in a wide range to set the client IP (rate limits, audit, IP allowlists); "+
			"list only the gateway's and the web server's addresses\n", w)
	}
	if !cfg.IsProduction() {
		fmt.Fprintf(stdout, "note: APP_ENV=%s skips the production checks (TLS to Postgres and Redis, secret strength, rate limits); "+
			"unset APP_ENV or set APP_ENV=production for a production deployment\n", cfg.App.Env)
	}
	return 0
}
