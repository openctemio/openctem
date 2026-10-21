package scm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// RecentIssues reads the repository's issue list (labeled, all states,
// newest first) and leaves pull requests out.
func TestGitHubClient_RecentIssues(t *testing.T) {
	var path, query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, query = r.URL.EscapedPath(), r.URL.RawQuery
		_, _ = io.WriteString(w, `[
			{"number": 3, "html_url": "https://github.com/o/r/issues/3", "body": "b3"},
			{"number": 2, "html_url": "https://github.com/o/r/pull/2", "body": "pr", "pull_request": {"url": "x"}},
			{"number": 1, "html_url": "https://github.com/o/r/issues/1", "body": null}]`)
	}))
	defer srv.Close()
	c := newGitHubClientForTest(srv.URL, "tok")
	got, err := c.RecentIssues(context.Background(), "o/x", "r", "openctem")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/repos/o%2Fx/r/issues" {
		t.Errorf("path %q: owner must be escaped", path)
	}
	if query != "direction=desc&labels=openctem&per_page=100&sort=created&state=all" {
		t.Errorf("query %q", query)
	}
	if len(got) != 2 || got[0].Number != 3 || got[0].Body != "b3" || got[1].Number != 1 {
		t.Fatalf("issues %+v", got)
	}
}
