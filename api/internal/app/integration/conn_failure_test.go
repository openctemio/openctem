package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/scm"
	"github.com/openctemio/openctem/api/pkg/apierror"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

func TestClassifyConnFailure(t *testing.T) {
	dial := &url.Error{Op: "Get", URL: "https://jira.example.com", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}
	cases := []struct {
		name string
		err  error
		want apierror.Code
	}{
		{"no credentials", fmt.Errorf("resolve: %w", integrationdom.ErrNoCredentials), apierror.CodeIntegrationNoCredentials},
		{"unreadable (service)", ErrCredentialsUnreadable, apierror.CodeIntegrationCredentialsUnreadable},
		{"unreadable (domain)", integrationdom.ErrCredentialsUnreadable, apierror.CodeIntegrationCredentialsUnreadable},
		{"dial beats auth wrapper", errors.Join(scm.ErrAuthFailed, dial), apierror.CodeIntegrationUnreachable},
		{"deadline", context.DeadlineExceeded, apierror.CodeIntegrationUnreachable},
		{"blocked", errors.New(`host "metadata.internal" is blocked`), apierror.CodeIntegrationURLBlocked},
		{"401", &httpsec.UpstreamStatusError{Provider: "jira", Status: 401}, apierror.CodeIntegrationAuthFailed},
		{"404 beats not-found wrapper", errors.Join(scm.ErrNotFound, &httpsec.UpstreamStatusError{Status: 403}), apierror.CodeIntegrationForbidden},
		{"429", &httpsec.UpstreamStatusError{Status: 429}, apierror.CodeIntegrationRateLimited},
		{"503", &httpsec.UpstreamStatusError{Status: 503}, apierror.CodeIntegrationUpstreamError},
		{"scm auth", scm.ErrAuthFailed.Wrap(errors.New("bad credentials")), apierror.CodeIntegrationAuthFailed},
		{"scm rate", scm.ErrRateLimited, apierror.CodeIntegrationRateLimited},
		{"scm not found", scm.ErrNotFound, apierror.CodeIntegrationNotFound},
		{"unknown", errors.New("something odd"), apierror.CodeIntegrationTestFailed},
	}
	for _, c := range cases {
		got := ClassifyConnFailure(c.err)
		if got.Code != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got.Code, c.want)
		}
		if spec, _ := apierror.Lookup(c.want); got.Message != spec.Message {
			t.Errorf("%s: message %q is not the registered sentence", c.name, got.Message)
		}
	}
	if (ClassifyConnFailure(nil) != ConnFailure{}) {
		t.Error("nil error is no failure")
	}
}

func TestClassifySendFailure(t *testing.T) {
	cases := map[string]apierror.Code{
		"slack returned status 404: channel_not_found":           apierror.CodeIntegrationNotFound,
		"webhook returned status 401: {\"error\":\"bad token\"}": apierror.CodeIntegrationAuthFailed,
		"webhook returned status 502: <html>":                    apierror.CodeIntegrationUpstreamError,
		"send request failed: dial tcp 10.0.0.1:443: timeout":    apierror.CodeIntegrationUnreachable,
		"blocked hostname: localhost":                            apierror.CodeIntegrationURLBlocked,
		"telegram said no":                                       apierror.CodeIntegrationTestFailed,
	}
	for text, want := range cases {
		if got := ClassifySendFailure(text); got.Code != want {
			t.Errorf("%q: got %s, want %s", text, got.Code, want)
		}
	}
}
