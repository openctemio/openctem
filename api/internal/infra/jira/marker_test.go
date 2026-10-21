package jira

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testObject = "0199f3a2-7c1e-7b55-9a3e-2f1d8c4b6a10"

// The marker travels in the create request itself: the issue property and
// the label, next to the caller's labels.
func TestCreateIssue_WritesTheMarker(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"10001","key":"SEC-1"}`)
	}))
	defer srv.Close()
	c := newTestClient(srv.URL, srv.Client())
	m := &IssueMarker{Object: testObject, Kind: "task", Integration: "intg-1"}
	if _, err := c.CreateIssue(context.Background(), CreateIssueInput{ProjectKey: "SEC", Summary: "s", Labels: []string{"openctem"}, Marker: m}); err != nil {
		t.Fatal(err)
	}
	props, _ := body["properties"].([]any)
	if len(props) != 1 {
		t.Fatalf("properties = %v", body["properties"])
	}
	p := props[0].(map[string]any)
	v := p["value"].(map[string]any)
	if p["key"] != MarkerProperty || v["o"] != testObject || v["k"] != "task" || v["i"] != "intg-1" {
		t.Fatalf("property = %v", p)
	}
	labels := body["fields"].(map[string]any)["labels"].([]any)
	if len(labels) != 2 || labels[0] != "openctem" || labels[1] != "openctem-ref-"+testObject {
		t.Fatalf("labels = %v", labels)
	}
}

// A create that sends no labels (a profile without them) gets the property
// only: a create screen without labels must not refuse the issue.
func TestCreateIssueFields_NoLabelsNoMarkerLabel(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"10001","key":"SEC-1"}`)
	}))
	defer srv.Close()
	c := newTestClient(srv.URL, srv.Client())
	if _, err := c.CreateIssueFields(context.Background(), "SEC", "10", map[string]any{"summary": "s"}, &IssueMarker{Object: testObject, Kind: "finding", Integration: "i"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["fields"].(map[string]any)["labels"]; ok {
		t.Fatalf("labels added to a create without labels: %v", body["fields"])
	}
	if body["properties"] == nil {
		t.Fatal("property missing")
	}
}

// The lookup searches the marker label and returns each issue's property;
// an invalid object id is refused before any request (no JQL injection).
func TestFindIssuesByMarker(t *testing.T) {
	var jql, props string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jql, props = r.URL.Query().Get("jql"), r.URL.Query().Get("properties")
		_, _ = io.WriteString(w, `{"issues":[
			{"id":"10001","key":"SEC-1","properties":{"openctem":{"o":"`+testObject+`","k":"task","i":"intg-1"}}},
			{"id":"10002","key":"SEC-2","properties":{}}]}`)
	}))
	defer srv.Close()
	c := newTestClient(srv.URL, srv.Client())
	got, err := c.FindIssuesByMarker(context.Background(), testObject)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jql, `labels = "openctem-ref-`+testObject+`"`) || props != MarkerProperty {
		t.Fatalf("jql %q properties %q", jql, props)
	}
	if len(got) != 2 || got[0].Marker.Object != testObject || got[0].Marker.Integration != "intg-1" || got[1].Marker.Object != "" {
		t.Fatalf("issues %+v", got)
	}
	if _, err := c.FindIssuesByMarker(context.Background(), `x" OR project = HR`); err == nil {
		t.Fatal("an invalid object id reached the search")
	}
}
