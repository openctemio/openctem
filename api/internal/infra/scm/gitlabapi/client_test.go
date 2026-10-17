package gitlabapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClient(t *testing.T) {
	var notesPut, notesPost int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "glpat-x" {
			http.Error(w, `{"message":"401 Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/personal_access_tokens/self":
			_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "scopes": []string{"api"}, "user_id": 9})
		case r.URL.Path == "/groups/55/members/9":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 9})
		case r.URL.Path == "/groups/55/members/10":
			http.Error(w, `{"message":"404 Not found"}`, http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/merge_requests/3/notes") && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": 1, "body": "<!-- openctem-gate:p -->", "author": map[string]any{"id": 77}}, // someone else's copy
				{"id": 2, "body": "<!-- openctem-gate:p --> old", "author": map[string]any{"id": 9}},
			})
		case strings.HasSuffix(r.URL.Path, "/notes/2") && r.Method == http.MethodPut:
			notesPut++
		case strings.HasSuffix(r.URL.Path, "/notes") && r.Method == http.MethodPost:
			notesPost++
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := NewWithBase(srv.URL, "glpat-x", srv.Client())
	ctx := context.Background()
	if tok, err := c.Token(ctx); err != nil || !tok.Active || tok.UserID != 9 {
		t.Fatalf("token: %+v %v", tok, err)
	}
	if ok, err := c.GroupMember(ctx, 55, 9); err != nil || !ok {
		t.Fatalf("member: %v %v", ok, err)
	}
	if ok, err := c.GroupMember(ctx, 55, 10); err != nil || ok {
		t.Fatalf("not a member: %v %v", ok, err)
	}
	// Only the token user's own marked note is updated.
	if err := c.UpsertMergeRequestNote(ctx, "acme/api", 3, 9, "<!-- openctem-gate:p -->", "new"); err != nil || notesPut != 1 || notesPost != 0 {
		t.Fatalf("upsert: %v put=%d post=%d", err, notesPut, notesPost)
	}
	if err := c.UpsertMergeRequestNote(ctx, "acme/api", 3, 9, "<!-- openctem-gate:q -->", "new"); err != nil || notesPost != 1 {
		t.Fatalf("new note: %v post=%d", err, notesPost)
	}
	// Errors carry the status, never the token.
	_, err := NewWithBase(srv.URL, "wrong", srv.Client()).Token(ctx)
	if err == nil || strings.Contains(err.Error(), "wrong") || !strings.Contains(err.Error(), "401") {
		t.Fatalf("error = %v", err)
	}
}

func TestNewRefusesBadHosts(t *testing.T) {
	for _, h := range []string{"", "gitlab.com/x", "user@gitlab.com", "a b"} {
		if _, err := New(h, "t", nil); err == nil {
			t.Fatalf("host %q accepted", h)
		}
	}
}

// A merge request's head pipeline is read, and a status attached to a
// pipeline sends its id (a merged results pipeline's status); without one
// no pipeline_id is sent.
func TestMergedResultsPipelineWire(t *testing.T) {
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/merge_requests/3"):
			_ = json.NewEncoder(w).Encode(map[string]any{"iid": 3, "sha": "head",
				"head_pipeline": map[string]any{"id": 501, "sha": "mrc"}})
		case strings.Contains(r.URL.Path, "/statuses/"):
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			bodies = append(bodies, b)
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := NewWithBase(srv.URL, "glpat-x", srv.Client())
	ctx := context.Background()
	mr, err := c.MergeRequest(ctx, "acme/api", 3)
	if err != nil || mr.HeadPipeline == nil || mr.HeadPipeline.ID != 501 || mr.HeadPipeline.SHA != "mrc" {
		t.Fatalf("merge request: %+v %v", mr, err)
	}
	if err := c.SetCommitStatus(ctx, "acme/api", "mrc", "failed", "gate", "https://c", "d", 501); err != nil {
		t.Fatal(err)
	}
	if err := c.SetCommitStatus(ctx, "acme/api", "head", "success", "gate", "https://c", "d", 0); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || bodies[0]["pipeline_id"] != float64(501) {
		t.Fatalf("bodies = %v", bodies)
	}
	if _, ok := bodies[1]["pipeline_id"]; ok {
		t.Fatalf("pipeline_id sent without a pipeline: %v", bodies[1])
	}
}
