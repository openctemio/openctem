//go:build authtestseam

package auth

import (
	"net/url"
	"os"
	"strings"
)

// providerTestSeamCompiled: this is a TEST build (tag authtestseam); never a
// release.
const providerTestSeamCompiled = true

// testSeamEndpoint maps a provider endpoint to the stand-in named by
// AUTHTESTSEAM_PROVIDER_URL (or, for the browser,
// AUTHTESTSEAM_PROVIDER_BROWSER_URL): <base>/<real host><real path>. Unset or
// unparsable, or APP_ENV not an explicit test value (see SeamEnvAllowed): the
// real URL.
func testSeamEndpoint(real string, browser bool) string {
	if !TestSeamActive() {
		return real
	}
	base := strings.TrimSpace(os.Getenv(EnvTestSeamProviderURL))
	if browser {
		if b := strings.TrimSpace(os.Getenv(EnvTestSeamProviderBrowserURL)); b != "" {
			base = b
		}
	}
	if base == "" {
		return real
	}
	r, err := url.Parse(real)
	if err != nil || r.Host == "" {
		return real
	}
	b, err := url.Parse(base)
	if err != nil || (b.Scheme != "http" && b.Scheme != "https") || b.Host == "" {
		return real
	}
	b.Path = strings.TrimSuffix(b.Path, "/") + "/" + r.Host + r.Path
	b.RawQuery = r.RawQuery
	return b.String()
}

// TestSeamActive reports whether provider endpoints are overridden.
func TestSeamActive() bool {
	return strings.TrimSpace(os.Getenv(EnvTestSeamProviderURL)) != "" &&
		SeamEnvAllowed(os.Getenv("APP_ENV"))
}
