//go:build !authtestseam

package auth

// providerTestSeamCompiled reports whether this binary carries the test-only
// provider endpoint override. Release builds: never.
const providerTestSeamCompiled = false

// testSeamEndpoint returns the provider's own URL, whatever the environment
// says.
func testSeamEndpoint(real string, _ bool) string { return real }

// TestSeamActive reports whether provider endpoints are overridden (for the
// start-up log). Always false in a release build.
func TestSeamActive() bool { return false }
