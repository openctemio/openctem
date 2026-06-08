package jira

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestClient builds a Client pointed at a test server, bypassing NewClient's
// SSRF validation (which rejects loopback) by constructing the struct directly —
// legal here because the test is in package jira.
func newTestClient(serverURL string, hc *http.Client) *Client {
	return &Client{baseURL: serverURL, email: "e@x.test", apiToken: "tok", httpClient: hc}
}

func TestGetTransitions_Parses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/SEC-1/transitions") {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"transitions":[
			{"id":"11","name":"Start","to":{"name":"In Progress"}},
			{"id":"31","name":"Done","to":{"name":"Done"}}
		]}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, srv.Client())
	ts, err := c.GetTransitions(context.Background(), "SEC-1")
	if err != nil {
		t.Fatalf("GetTransitions: %v", err)
	}
	if len(ts) != 2 || ts[1].ID != "31" || ts[1].ToStatusName != "Done" {
		t.Fatalf("unexpected transitions: %+v", ts)
	}
}

func TestTransitionToStatus_MatchesAndPosts(t *testing.T) {
	var posted map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"transitions":[{"id":"31","name":"Done","to":{"name":"Done"}}]}`)
		case http.MethodPost:
			_ = json.NewDecoder(r.Body).Decode(&posted)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, srv.Client())
	// Case-insensitive match on the resulting status name.
	if err := c.TransitionToStatus(context.Background(), "SEC-1", "done", "moved by openctem"); err != nil {
		t.Fatalf("TransitionToStatus: %v", err)
	}
	tr, _ := posted["transition"].(map[string]any)
	if tr == nil || tr["id"] != "31" {
		t.Fatalf("expected transition id 31 posted, got %+v", posted)
	}
	if _, ok := posted["update"]; !ok {
		t.Errorf("expected comment attached via update, got %+v", posted)
	}
}

func TestTransitionToStatus_NoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"transitions":[{"id":"11","name":"Start","to":{"name":"In Progress"}}]}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, srv.Client())
	err := c.TransitionToStatus(context.Background(), "SEC-1", "Done", "")
	if !errors.Is(err, ErrNoMatchingTransition) {
		t.Fatalf("expected ErrNoMatchingTransition, got %v", err)
	}
}

func TestAddComment_OK(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/SEC-1/comment") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, srv.Client())
	if err := c.AddComment(context.Background(), "SEC-1", "hello"); err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	if got["body"] != "hello" {
		t.Fatalf("comment body = %q", got["body"])
	}
}

func TestDoTransition_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"errorMessages":["bad transition"]}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, srv.Client())
	if err := c.DoTransition(context.Background(), "SEC-1", "999", ""); err == nil {
		t.Fatal("expected error on non-204 transition response")
	}
}
