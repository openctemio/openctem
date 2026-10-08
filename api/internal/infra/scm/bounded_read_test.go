package scm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// An SCM response larger than httpsec.MaxResponseBytes is an error, even when
// it is valid JSON: a hostile or broken provider cannot make the API buffer an
// unbounded body (RFC-049 F-12).
func TestGitHubClient_OversizeResponseIsRefused(t *testing.T) {
	pad := strings.Repeat("a", int(httpsec.MaxResponseBytes))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number": 42, "html_url": "https://github.com/octo/repo/issues/42", "pad": "` + pad + `"}`))
	}))
	defer srv.Close()

	c := newGitHubClientForTest(srv.URL, "tok")
	_, _, err := c.CreateIssue(context.Background(), "octo", "repo", "t", "b", nil)
	if !errors.Is(err, httpsec.ErrBodyTooLarge) {
		t.Fatalf("err = %v, want ErrBodyTooLarge", err)
	}
}
