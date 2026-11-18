package auth

import "strings"

// Where the social providers' endpoints (Google, Microsoft, GitHub) are
// reached. A release build always uses the providers' own, fixed URLs: the
// override below is compiled only into a binary built with the build tag
// "authtestseam" (provider_endpoints_testseam.go), which the sign-in test
// suites use to run a sign-in end to end against a stand-in provider. Release
// builds never pass the tag (provider_endpoints_test.go checks the build
// files), and in a build without it the environment variables are not read
// at all. The provider's identity rules do not change: id_tokens still carry
// the provider's real issuer and are verified against the keys served at the
// (overridden) key URL with the configured client id.

const (
	// EnvTestSeamProviderURL is the base URL of the stand-in provider as the
	// API reaches it. Every endpoint becomes <base>/<real host><real path>,
	// for example <base>/oauth2.googleapis.com/token.
	EnvTestSeamProviderURL = "AUTHTESTSEAM_PROVIDER_URL"
	// EnvTestSeamProviderBrowserURL is the same stand-in as the browser
	// reaches it (the authorization endpoint); defaults to
	// EnvTestSeamProviderURL.
	EnvTestSeamProviderBrowserURL = "AUTHTESTSEAM_PROVIDER_BROWSER_URL"
)

// SeamEnvAllowed reports whether APP_ENV names a test environment, the only
// kind in which a binary built with the authtestseam tag honors the
// override: an unset, production, staging or any other value never does, so a
// tagged binary that reaches a real deployment by mistake still talks to the
// real providers.
func SeamEnvAllowed(appEnv string) bool {
	switch strings.ToLower(strings.TrimSpace(appEnv)) {
	case "test", "e2e":
		return true
	}
	return false
}

// providerEndpoint is the URL the API calls for a provider endpoint whose
// real URL is real.
func providerEndpoint(real string) string { return testSeamEndpoint(real, false) }

// providerBrowserEndpoint is the URL the browser is sent to for a provider
// endpoint whose real URL is real.
func providerBrowserEndpoint(real string) string { return testSeamEndpoint(real, true) }
