package jira

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestListCreateFields_PagesAndBothShapes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/rest/api/2/issue/createmeta/SEC/issuetypes/10001") {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("startAt") == "0" {
			// Data Center shape: "values".
			_, _ = w.Write([]byte(`{"startAt":0,"maxResults":1,"total":2,"isLast":false,"values":[
				{"fieldId":"priority","name":"Priority","required":false,"schema":{"type":"priority","system":"priority"},
				 "allowedValues":[{"id":"1","name":"Highest"},{"id":"2","name":"High"}]}]}`))
			return
		}
		// Cloud shape: "fields", option values carry "value".
		_, _ = w.Write([]byte(`{"startAt":1,"maxResults":1,"total":2,"fields":[
			{"fieldId":"customfield_10050","name":"Team","required":true,"hasDefaultValue":false,
			 "schema":{"type":"option","custom":"com.atlassian.jira.plugin.system.customfieldtypes:select"},
			 "allowedValues":[{"id":"70","value":"Payments"}]}]}`))
	}))
	defer srv.Close()
	c := newTestClient(srv.URL, srv.Client())
	got, err := c.ListCreateFields(context.Background(), "SEC", "10001")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "priority" || got[0].AllowedValues[1].Name != "High" ||
		got[1].ID != "customfield_10050" || !got[1].Required || got[1].AllowedValues[0].Name != "Payments" {
		t.Fatalf("fields: %+v", got)
	}
}

func TestListProjectStatuses_FiltersIssueType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"id":"10001","statuses":[{"id":"1","name":"To Do","statusCategory":{"key":"new"}},{"id":"10","name":"Done","statusCategory":{"key":"done"}}]},
			{"id":"10002","statuses":[{"id":"99","name":"Other","statusCategory":{"key":"new"}}]}]`))
	}))
	defer srv.Close()
	got, err := newTestClient(srv.URL, srv.Client()).ListProjectStatuses(context.Background(), "SEC", "10001")
	if err != nil || len(got) != 2 || got[1].Category != "done" {
		t.Fatalf("statuses: %v %+v", err, got)
	}
}

func TestListWorkflowTransitions_ResolvesReferences(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/rest/api/3/workflows" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"workflows":[{"transitions":[
			{"id":"11","name":"Start","type":"DIRECTIONAL","toStatusReference":"r3","links":[{"fromStatusReference":"r1"}]},
			{"id":"91","name":"Any to Done","type":"GLOBAL","toStatusReference":"r10","links":[]},
			{"id":"1","name":"Create","type":"INITIAL","toStatusReference":"r1","links":[]}]}],
			"statuses":[{"id":"1","statusReference":"r1"},{"id":"3","statusReference":"r3"},{"id":"10","statusReference":"r10"}]}`))
	}))
	defer srv.Close()
	got, err := newTestClient(srv.URL, srv.Client()).ListWorkflowTransitions(context.Background(), "100", "10001")
	if err != nil || len(got) != 2 || got[0].To != "3" || got[0].From[0] != "1" || got[1].From != nil {
		t.Fatalf("transitions: %v %+v", err, got)
	}
	// A site without the API (404) is "unknown", not an error.
	srv404 := httptest.NewServer(http.NotFoundHandler())
	defer srv404.Close()
	if tr, err := newTestClient(srv404.URL, srv404.Client()).ListWorkflowTransitions(context.Background(), "100", "1"); err != nil || tr != nil {
		t.Fatalf("404: %v %v", tr, err)
	}
}

func TestDoJSON_RateLimitCarriesRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "17")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	_, err := newTestClient(srv.URL, srv.Client()).ListResolutions(context.Background())
	var rl *RateLimitedError
	if !errors.As(err, &rl) || rl.RetryAfter != 17*time.Second {
		t.Fatalf("want RateLimitedError 17s, got %v", err)
	}
}

func TestDisplayValue(t *testing.T) {
	for in, want := range map[string]string{
		`"2027-01-01"`:                   "2027-01-01",
		`{"accountId":"acc-7"}`:          "acc-7",
		`{"value":"Payments","id":"70"}`: "Payments",
		`9.5`:                            "9.5",
		`null`:                           "",
	} {
		if got := displayValue([]byte(in)); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}
