package scm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newGitHubClientForTest builds a GitHubClient that talks to an arbitrary
// baseURL (e.g. an httptest.Server) using a plain http client. It bypasses the
// httpsec SSRF guards which reject loopback addresses, so it is test-only.
func newGitHubClientForTest(baseURL, token string) *GitHubClient {
	return &GitHubClient{
		config:     Config{Provider: ProviderGitHub, AccessToken: token},
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    strings.TrimSuffix(baseURL, "/"),
	}
}

func TestGitHubClient_CreateIssue_Success(t *testing.T) {
	var gotPath, gotMethod, gotAuth string
	var gotBody struct {
		Title  string   `json:"title"`
		Body   string   `json:"body"`
		Labels []string `json:"labels"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number": 42, "html_url": "https://github.com/octo/repo/issues/42"}`))
	}))
	defer srv.Close()

	c := newGitHubClientForTest(srv.URL, "tok-123")

	num, url, err := c.CreateIssue(context.Background(), "octo", "repo", "a title", "a body", []string{"openctem", "security", "high"})
	if err != nil {
		t.Fatalf("CreateIssue returned error: %v", err)
	}

	if num != 42 {
		t.Errorf("number = %d, want 42", num)
	}
	if url != "https://github.com/octo/repo/issues/42" {
		t.Errorf("html_url = %q, want issue url", url)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/repos/octo/repo/issues" {
		t.Errorf("path = %q, want /repos/octo/repo/issues", gotPath)
	}
	if gotAuth != "Bearer tok-123" {
		t.Errorf("auth = %q, want Bearer tok-123", gotAuth)
	}
	if gotBody.Title != "a title" || gotBody.Body != "a body" {
		t.Errorf("body title/body mismatch: %+v", gotBody)
	}
	if len(gotBody.Labels) != 3 || gotBody.Labels[0] != "openctem" {
		t.Errorf("labels mismatch: %+v", gotBody.Labels)
	}
}

func TestGitHubClient_CreateIssue_PathEscaping(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":1,"html_url":"u"}`))
	}))
	defer srv.Close()

	c := newGitHubClientForTest(srv.URL, "t")
	if _, _, err := c.CreateIssue(context.Background(), "org with space", "re/po", "t", "b", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/repos/org%20with%20space/re%2Fpo/issues" {
		t.Errorf("escaped path = %q, want owner/repo escaped", gotPath)
	}
}

func TestGitHubClient_UpdateIssueState_Success(t *testing.T) {
	var gotPath, gotMethod, gotAuth string
	var gotBody struct {
		State string `json:"state"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"number":7,"state":"closed"}`))
	}))
	defer srv.Close()

	c := newGitHubClientForTest(srv.URL, "tok-xyz")
	if err := c.UpdateIssueState(context.Background(), "octo", "re/po", 7, "closed"); err != nil {
		t.Fatalf("UpdateIssueState returned error: %v", err)
	}

	if gotMethod != http.MethodPatch {
		t.Errorf("method = %q, want PATCH", gotMethod)
	}
	if gotPath != "/repos/octo/re%2Fpo/issues/7" {
		t.Errorf("path = %q, want escaped issue path", gotPath)
	}
	if gotAuth != "Bearer tok-xyz" {
		t.Errorf("auth = %q, want Bearer tok-xyz", gotAuth)
	}
	if gotBody.State != "closed" {
		t.Errorf("state = %q, want closed", gotBody.State)
	}
}

func TestGitHubClient_UpdateIssueState_InvalidStateRejected(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newGitHubClientForTest(srv.URL, "t")
	if err := c.UpdateIssueState(context.Background(), "octo", "repo", 1, "reopened"); err == nil {
		t.Fatal("expected error for invalid state, got nil")
	}
	if called {
		t.Error("invalid state must be rejected before any HTTP request")
	}
}

func TestGitHubClient_UpdateIssueState_NonOKIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"secret-internal-detail"}`))
	}))
	defer srv.Close()

	c := newGitHubClientForTest(srv.URL, "t")
	err := c.UpdateIssueState(context.Background(), "octo", "repo", 99, "open")
	if err == nil {
		t.Fatal("expected error for non-200 response, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error %q should include status code 404", err.Error())
	}
	if strings.Contains(err.Error(), "secret-internal-detail") {
		t.Errorf("error %q must not leak response body", err.Error())
	}
}

func TestGitHubClient_CreateIssue_NonCreatedIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"secret-internal-detail"}`))
	}))
	defer srv.Close()

	c := newGitHubClientForTest(srv.URL, "t")
	_, _, err := c.CreateIssue(context.Background(), "octo", "repo", "t", "b", nil)
	if err == nil {
		t.Fatal("expected error for non-201 response, got nil")
	}
	// Status code must be present, response body must NOT be leaked verbatim.
	if !strings.Contains(err.Error(), "422") {
		t.Errorf("error %q should include status code 422", err.Error())
	}
	if strings.Contains(err.Error(), "secret-internal-detail") {
		t.Errorf("error %q must not leak response body", err.Error())
	}
}
