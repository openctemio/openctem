package server

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// The public origin of SAML.
//
// The SAML service provider URLs (entity ID, ACS URL, metadata URL, and the
// audience, recipient and destination an assertion must carry) are built on
// one origin, and that origin comes from configuration (APP_URL) only. It is
// never read from a request: a Host or X-Forwarded-Host header would then
// choose the audience the SP checks, and an assertion the IdP issued to
// another service provider could be replayed here.
//
//   - APP_URL set: its origin, in every mode.
//   - APP_URL unset in production: no origin. The SAML routes refuse, and the
//     server refuses to start while an organization has SAML sign-in enabled
//     (requireSAMLPublicURL).
//   - APP_URL unset outside production: http://localhost:<SERVER_PORT>, with
//     a warning, so a development machine works without configuration.

// samlPublicURL returns the URL the SAML handler builds on, or "" when SAML
// must refuse.
func samlPublicURL(cfg *config.Config, log *logger.Logger) string {
	if u := strings.TrimSpace(cfg.App.URL); u != "" {
		return u
	}
	if cfg.IsProduction() {
		log.Warn("saml: APP_URL is not set; SAML sign-in, the assertion consumer service and the service provider metadata are refused until it is. Set APP_URL to the public origin of the API.")
		return ""
	}
	fallback := "http://localhost:" + strconv.Itoa(cfg.Server.Port)
	log.Warn("saml: APP_URL is not set; outside production the SAML service provider URLs use the local fallback. Set APP_URL to the public origin of the API.",
		"fallback", fallback, "env", cfg.App.Env)
	return fallback
}

// samlProviderProbe is the minimum DB surface the start-up check needs.
// *sql.DB satisfies it directly.
type samlProviderProbe interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// requireSAMLPublicURL refuses to start a production server that has SAML
// sign-in enabled for an organization and no APP_URL: every SAML sign-in
// would be refused at request time, and the operator should learn that at
// start-up, with the name of the setting, not from users who cannot sign in.
//
// The read crosses organizations on purpose: it is a platform-level operator
// check, and only a count leaves it. A failed read also refuses the start:
// the check cannot tell that the configuration is safe.
func requireSAMLPublicURL(ctx context.Context, db samlProviderProbe, cfg *config.Config) error {
	if !cfg.IsProduction() || strings.TrimSpace(cfg.App.URL) != "" || db == nil {
		return nil
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM saml_providers WHERE enabled`).Scan(&n); err != nil {
		return fmt.Errorf("APP_URL is not set and the check for organizations with SAML sign-in failed: %w", err)
	}
	if n == 0 {
		return nil
	}
	return fmt.Errorf("APP_URL is required: SAML sign-in is enabled for %d organization(s), and the SAML audience, assertion consumer service URL and metadata are built on APP_URL only (never on a request header). Set APP_URL to the public origin of the API, e.g. https://ctem.example.com", n)
}
