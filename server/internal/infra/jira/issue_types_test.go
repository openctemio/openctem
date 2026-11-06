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

	appjira "github.com/openctemio/openctem/api/internal/app/jira"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
)

// fakeJira serves the create metadata of project SEC: Security Finding
// (10042, Team required), Remediation Task (10043, nothing extra required),
// Sub-task (10044) and Initiative (10045, Epic Name required).
func fakeJira(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/rest/api/2/issue/createmeta/SEC/issuetypes":
			_, _ = io.WriteString(w, `{"isLast":true,"values":[
				{"id":"10042","name":"Security Finding"},{"id":"10043","name":"Remediation Task"},
				{"id":"10044","name":"Sub-task","subtask":true},{"id":"10045","name":"Initiative"}]}`)
		case r.URL.Path == "/rest/api/2/issue/createmeta/SEC/issuetypes/10042":
			_, _ = io.WriteString(w, `{"isLast":true,"values":[
				{"fieldId":"summary","name":"Summary","required":true},
				{"fieldId":"reporter","name":"Reporter","required":true},
				{"fieldId":"customfield_10050","name":"Team","required":true,"hasDefaultValue":false},
				{"fieldId":"customfield_10060","name":"Squad","required":true,"hasDefaultValue":true}]}`)
		case r.URL.Path == "/rest/api/2/issue/createmeta/SEC/issuetypes/10043":
			_, _ = io.WriteString(w, `{"isLast":true,"values":[{"fieldId":"summary","name":"Summary","required":true}]}`)
		case r.URL.Path == "/rest/api/2/issue/createmeta/SEC/issuetypes/10045":
			_, _ = io.WriteString(w, `{"isLast":true,"values":[{"fieldId":"customfield_10011","name":"Epic Name","required":true}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

func checkerFor(t *testing.T, srv *httptest.Server, covered map[string]bool) *IntegrationClientResolver {
	t.Helper()
	r := newResolver(nil)
	r.newClient = func(string, string, string) (*Client, error) { return newTestClient(srv.URL, srv.Client()), nil }
	if covered != nil {
		r.SetProfileCoverage(func(_ context.Context, _, _ shared.ID, kind ticketmap.ObjectKind, project, typeID string) (bool, error) {
			return covered[string(kind)+"/"+project+"/"+typeID], nil
		})
	}
	return r
}

func ticketingIntegration(t *testing.T, ticketing map[string]any) *integration.Integration {
	t.Helper()
	return newJiraIntegration(t, integration.StatusConnected, "https://acme.atlassian.net",
		`{"email":"bot@example.com","api_token":"tok"}`, map[string]any{"ticketing": ticketing})
}

func types(entries map[string]string) map[string]any {
	out := map[string]any{}
	for kind, id := range entries {
		out[kind] = map[string]any{"id": id, "name": "n"}
	}
	return out
}

func TestCheckTicketingIssueTypes(t *testing.T) {
	srv := fakeJira(t)
	defer srv.Close()
	ctx := context.Background()

	cases := []struct {
		name    string
		cfg     map[string]any
		covered map[string]bool
		want    string // "" = accepted; else a fragment of the refusal
	}{
		{"task type with nothing extra required", map[string]any{"project_key": "SEC", "issue_types": types(map[string]string{"task": "10043"})}, nil, ""},
		{"required custom field without a profile", map[string]any{"project_key": "SEC", "issue_types": types(map[string]string{"finding": "10042"})}, nil, "Team"},
		{"required custom field covered by a published profile", map[string]any{"project_key": "SEC", "issue_types": types(map[string]string{"finding": "10042"})},
			map[string]bool{"finding/SEC/10042": true}, ""},
		{"a task profile does not cover the finding kind", map[string]any{"project_key": "SEC", "issue_types": types(map[string]string{"finding": "10042"})},
			map[string]bool{"task/SEC/10042": true}, "publish a ticket field mapping"},
		{"unknown id", map[string]any{"project_key": "SEC", "issue_types": types(map[string]string{"task": "99999"})}, nil, "does not exist in project SEC"},
		{"sub-task type", map[string]any{"project_key": "SEC", "issue_types": types(map[string]string{"task": "10044"})}, nil, "sub-task"},
		{"epic with a required field (no epic profiles)", map[string]any{"project_key": "SEC", "issue_types": types(map[string]string{"epic": "10045"})},
			map[string]bool{"epic/SEC/10045": true}, "Epic Name"},
		{"no default project", map[string]any{"issue_types": types(map[string]string{"task": "10043"})}, nil, "default project"},
		{"names only are not checked", map[string]any{"project_key": "SEC", "issue_types": map[string]any{"task": map[string]any{"name": "Task"}}}, nil, ""},
		{"project without the metadata (Jira refuses)", map[string]any{"project_key": "HR", "issue_types": types(map[string]string{"task": "10043"})}, nil, "could not be read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkerFor(t, srv, tc.covered).CheckTicketingIssueTypes(ctx, ticketingIntegration(t, tc.cfg))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a validation error with %q, got %v", tc.want, err)
			}
		})
	}
}

func TestCheckTicketingIssueTypes_UnreachableJiraRefuses(t *testing.T) {
	srv := fakeJira(t)
	srv.Close() // nothing answers
	err := checkerFor(t, srv, nil).CheckTicketingIssueTypes(context.Background(),
		ticketingIntegration(t, map[string]any{"project_key": "SEC", "issue_types": types(map[string]string{"task": "10043"})}))
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an unverifiable choice must be refused, got %v", err)
	}
}

func TestCheckTicketingIssueTypes_UsesTheIntegrationsOwnTenantForCoverage(t *testing.T) {
	srv := fakeJira(t)
	defer srv.Close()
	intg := ticketingIntegration(t, map[string]any{"project_key": "SEC", "issue_types": types(map[string]string{"finding": "10042"})})
	r := checkerFor(t, srv, nil)
	var gotTenant, gotIntg shared.ID
	r.SetProfileCoverage(func(_ context.Context, tenantID, integrationID shared.ID, _ ticketmap.ObjectKind, _, _ string) (bool, error) {
		gotTenant, gotIntg = tenantID, integrationID
		return false, nil
	})
	_ = r.CheckTicketingIssueTypes(context.Background(), intg)
	if gotTenant != intg.TenantID() || gotIntg != intg.ID() {
		t.Fatal("coverage must be asked for the integration's own tenant and id")
	}
}

func TestCreateIssue_SendsTheTypeByIDAndKeepsFieldRefusals(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"errorMessages":[],"errors":{"customfield_10050":"Team is required.","issuetype":"<script>x</script>","bad key!":"x"}}`)
	}))
	defer srv.Close()
	a := clientAdapter{c: newTestClient(srv.URL, srv.Client()), integrationID: shared.NewID()}
	_, err := a.CreateIssue(context.Background(), appjira.CreateIssueInput{ProjectKey: "SEC", Summary: "s", IssueType: "Security Finding", IssueTypeID: "10042"})

	it, _ := body["fields"].(map[string]any)["issuetype"].(map[string]any)
	if it["id"] != "10042" || it["name"] != nil {
		t.Fatalf("issuetype sent as %v, want by id only", it)
	}
	var fr *appjira.FieldRejectedError
	if !errors.As(err, &fr) || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want a field refusal, got %v", err)
	}
	if strings.Join(fr.Fields, ",") != "customfield_10050,issuetype" {
		t.Fatalf("fields %v: only well-formed ids are kept", fr.Fields)
	}
	if strings.Contains(err.Error(), "script") || strings.Contains(err.Error(), "required.") {
		t.Fatalf("the tracker's messages must not be echoed: %v", err)
	}
}

func TestCreateIssueFields_FieldRefusalIsMapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"errors":{"customfield_10070":"Option removed"}}`)
	}))
	defer srv.Close()
	a := clientAdapter{c: newTestClient(srv.URL, srv.Client()), integrationID: shared.NewID()}
	_, err := a.CreateIssueFields(context.Background(), "SEC", "10042", map[string]any{"summary": "s"}, nil)
	var fr *appjira.FieldRejectedError
	if !errors.As(err, &fr) || fr.Fields[0] != "customfield_10070" {
		t.Fatalf("got %v", err)
	}
	var perm interface{ Permanent() bool }
	if !errors.As(err, &perm) || !perm.Permanent() {
		t.Fatal("a field refusal is permanent")
	}

	// A 400 without field errors stays a plain permanent refusal.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"errorMessages":["nope"]}`)
	}))
	defer srv2.Close()
	a.c = newTestClient(srv2.URL, srv2.Client())
	_, err = a.CreateIssueFields(context.Background(), "SEC", "10042", map[string]any{"summary": "s"}, nil)
	if errors.As(err, &fr) {
		t.Fatalf("no field errors: %v", err)
	}
}

func TestIssueTypeOf(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/2/issue/SEC-7" || r.URL.Query().Get("fields") != "issuetype" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"fields":{"issuetype":{"id":"10043","name":"Remediation Task"}}}`)
	}))
	defer srv.Close()
	a := clientAdapter{c: newTestClient(srv.URL, srv.Client())}
	if id, err := a.IssueTypeOf(context.Background(), "SEC-7"); err != nil || id != "10043" {
		t.Fatalf("%q %v", id, err)
	}
}

type healthRepo struct {
	kind    string
	problem any
	calls   int
}

func (h *healthRepo) RecordTicketingHealth(_ context.Context, _, _ shared.ID, kind string, problem any) error {
	h.kind, h.problem = kind, problem
	h.calls++
	return nil
}

func TestIssueTypeHealthStore(t *testing.T) {
	repo := &healthRepo{}
	st := IssueTypeHealthStore{Repo: repo}
	if err := st.RecordIssueTypeProblem(context.Background(), shared.NewID(), shared.NewID(), "task",
		&appjira.IssueTypeProblem{IssueType: "Remediation\nTask", Fields: []string{"customfield_1"}}); err != nil {
		t.Fatal(err)
	}
	e, ok := repo.problem.(healthEntry)
	if !ok || repo.kind != "task" || strings.Contains(e.IssueType, "\n") || e.At.IsZero() {
		t.Fatalf("stored %+v", repo.problem)
	}
	_ = st.RecordIssueTypeProblem(context.Background(), shared.NewID(), shared.NewID(), "task", nil)
	if repo.problem != nil {
		t.Fatal("nil clears")
	}
}
