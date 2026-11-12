package integration

// Why a connection test or a call to a connected service failed, as one of
// the INTEGRATION_* codes of pkg/apierror and a safe sentence. The cause
// itself (an upstream body, a dial error with an internal address, a Go
// error that names the integration by id) is logged, never stored on the
// integration or returned: the status is read back by everyone with
// integrations:read, and the console words it from the code
// (docs/architecture/error-responses.md).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/internal/infra/scm"
	"github.com/openctemio/openctem/api/pkg/apierror"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	emailpkg "github.com/openctemio/openctem/api/pkg/email"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// ConnFailure is a classified connection failure.
type ConnFailure struct {
	Code    apierror.Code
	Message string
}

func connFailure(code apierror.Code) ConnFailure {
	return ConnFailure{Code: code, Message: apierror.DefaultMessage(code, 0)}
}

// blockedRe matches the egress guard's refusals (pkg/httpsec): a host or an
// address the outbound policy does not allow.
var blockedRe = regexp.MustCompile(`(?i)\bblocked (address|hostname)\b|\bis blocked\b|resolves to (a )?blocked`)

// ClassifyConnFailure maps the error of a connection attempt to a code.
// Order matters: a missing or unreadable credential is known before any
// call; a network failure explains an auth-looking wrapper ("authentication
// failed: dial tcp ..."); an upstream HTTP status is more precise than the
// sentinel a client wrapped it in.
func ClassifyConnFailure(err error) ConnFailure {
	switch {
	case err == nil:
		return ConnFailure{}
	case errors.Is(err, integrationdom.ErrNoCredentials):
		return connFailure(apierror.CodeIntegrationNoCredentials)
	// The domain sentinel, not the service one: ErrCredentialsUnreadable also
	// wraps scm.ErrAuthFailed, and an SCM error matches any error that wraps
	// its code, so errors.Is(authErr, ErrCredentialsUnreadable) is true.
	case errors.Is(err, integrationdom.ErrCredentialsUnreadable):
		return connFailure(apierror.CodeIntegrationCredentialsUnreadable)
	case errors.Is(err, emailpkg.ErrTenantRelayPolicy):
		return connFailure(apierror.CodeIntegrationEmailRelayPolicy)
	case blockedRe.MatchString(err.Error()):
		return connFailure(apierror.CodeIntegrationURLBlocked)
	case isUnreachable(err):
		return connFailure(apierror.CodeIntegrationUnreachable)
	}
	if code, ok := upstreamStatusCode(err); ok {
		return connFailure(code)
	}
	switch {
	case errors.Is(err, scm.ErrAuthFailed), errors.Is(err, integrationdom.ErrCredentialsInvalid):
		return connFailure(apierror.CodeIntegrationAuthFailed)
	case errors.Is(err, scm.ErrPermissionDenied):
		return connFailure(apierror.CodeIntegrationForbidden)
	case errors.Is(err, scm.ErrNotFound):
		return connFailure(apierror.CodeIntegrationNotFound)
	case errors.Is(err, scm.ErrRateLimited):
		return connFailure(apierror.CodeIntegrationRateLimited)
	}
	return connFailure(apierror.CodeIntegrationTestFailed)
}

// isUnreachable reports a failure to reach the service at all: DNS, refused
// or reset connections, timeouts, TLS and certificate errors.
func isUnreachable(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var dnsErr *net.DNSError
	var opErr *net.OpError
	var urlErr *url.Error
	var certErr *tls.CertificateVerificationError
	var unknownAuth x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	if errors.As(err, &dnsErr) || errors.As(err, &opErr) || errors.As(err, &certErr) ||
		errors.As(err, &unknownAuth) || errors.As(err, &hostErr) {
		return true
	}
	if errors.As(err, &urlErr) && (urlErr.Timeout() || urlErr.Err != nil && isUnreachable(urlErr.Err)) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

// upstreamStatusCode maps an upstream HTTP status (httpsec's
// UpstreamStatusError, which never holds the body) to a code.
func upstreamStatusCode(err error) (apierror.Code, bool) {
	var us *httpsec.UpstreamStatusError
	if !errors.As(err, &us) {
		return "", false
	}
	return codeForStatus(us.Status)
}

func codeForStatus(status int) (apierror.Code, bool) {
	switch {
	case status == 401:
		return apierror.CodeIntegrationAuthFailed, true
	case status == 403:
		return apierror.CodeIntegrationForbidden, true
	case status == 404:
		return apierror.CodeIntegrationNotFound, true
	case status == 429:
		return apierror.CodeIntegrationRateLimited, true
	case status >= 500:
		return apierror.CodeIntegrationUpstreamError, true
	}
	return "", false
}

// sendStatusRe finds the upstream status in a notification client's failure
// text ("slack returned status 404: ...").
var sendStatusRe = regexp.MustCompile(`returned status (\d{3})`)

// ClassifySendFailure maps the failure text of a notification test (the
// notifier clients report text, not errors) to a code. The text itself is
// never stored.
func ClassifySendFailure(text string) ConnFailure {
	if m := sendStatusRe.FindStringSubmatch(text); m != nil {
		status, _ := strconv.Atoi(m[1])
		if code, ok := codeForStatus(status); ok {
			return connFailure(code)
		}
	}
	lower := strings.ToLower(text)
	switch {
	case blockedRe.MatchString(text):
		return connFailure(apierror.CodeIntegrationURLBlocked)
	case strings.Contains(lower, "send request failed"), strings.Contains(lower, "timeout"),
		strings.Contains(lower, "no such host"), strings.Contains(lower, "connection refused"):
		return connFailure(apierror.CodeIntegrationUnreachable)
	}
	return connFailure(apierror.CodeIntegrationTestFailed)
}
