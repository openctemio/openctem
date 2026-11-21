package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/user"
)

func bulkDismissRequest(ctx context.Context, body string) *http.Request {
	return httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/findings/bulk-dismissals", strings.NewReader(body))
}

// Who may decide alone in a bulk dismiss comes from the request's
// authentication only: a person's own session holding findings:approve. An
// API key or an MCP access token never decides alone, even with the
// permission; the body cannot claim either.
func TestParseBulkDismiss_AuthorityFromAuthentication(t *testing.T) {
	h := &VulnerabilityHandler{}
	tid, uid := shared.NewID().String(), shared.NewID().String()
	base := context.WithValue(context.WithValue(context.Background(), middleware.TenantIDKey, tid), middleware.UserIDKey, uid)
	approve := context.WithValue(base, middleware.FetchedPermissionsKey,
		[]string{permission.FindingsApprove.String(), permission.FindingsWrite.String(), permission.FindingsBulkUpdate.String()})
	body := `{"finding_ids":["` + shared.NewID().String() + `"],"closure_reason":"detection_error","idempotency_key":"k"}`
	cases := []struct {
		name               string
		ctx                context.Context
		canApprove, byAuto bool
	}{
		{"session with findings:approve", approve, true, false},
		{"session without findings:approve", context.WithValue(base, middleware.FetchedPermissionsKey, []string{permission.FindingsWrite.String()}), false, false},
		{"API key with findings:approve", context.WithValue(approve, middleware.AuthProviderKey, middleware.AuthProviderAPIKey), false, true},
		{"MCP token with findings:approve", context.WithValue(approve, middleware.AuthProviderKey, middleware.AuthProviderMCPOAuth), false, true},
	}
	for _, c := range cases {
		in, ok := h.parseBulkDismiss(httptest.NewRecorder(), bulkDismissRequest(c.ctx, body), "test")
		if !ok {
			t.Fatalf("%s: refused", c.name)
		}
		if in.CanApprove != c.canApprove || in.ByAutomation != c.byAuto {
			t.Errorf("%s: can_approve %v by_automation %v, want %v %v", c.name, in.CanApprove, in.ByAutomation, c.canApprove, c.byAuto)
		}
		if in.TenantID.String() != tid || in.UserID.String() != uid {
			t.Errorf("%s: tenant or user not taken from the authentication", c.name)
		}
	}
	// The body cannot carry them (unknown fields are refused).
	for _, extra := range []string{`"can_approve":true`, `"tenant_id":"` + shared.NewID().String() + `"`} {
		w := httptest.NewRecorder()
		if _, ok := h.parseBulkDismiss(w, bulkDismissRequest(approve, `{"finding_ids":["`+shared.NewID().String()+`"],`+extra+`}`), "test"); ok || w.Code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d", extra, w.Code)
		}
	}
}

// 501 ids are refused before anything is read (400 BULK_DISMISS_TOO_LARGE
// with the count); ids and a filter together, or neither, are refused; the
// request hash ignores id order and changes with the note.
func TestParseBulkDismiss_Limits(t *testing.T) {
	h := &VulnerabilityHandler{}
	ctx := context.WithValue(context.WithValue(context.Background(), middleware.TenantIDKey, shared.NewID().String()),
		middleware.UserIDKey, shared.NewID().String())
	ids := make([]string, 501)
	for i := range ids {
		ids[i] = `"` + shared.NewID().String() + `"`
	}
	w := httptest.NewRecorder()
	if _, ok := h.parseBulkDismiss(w, bulkDismissRequest(ctx, `{"finding_ids":[`+strings.Join(ids, ",")+`],"closure_reason":"detection_error"}`), "test"); ok {
		t.Fatal("501 ids accepted")
	}
	var e struct {
		Code    string         `json:"code"`
		Details map[string]int `json:"details"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	if w.Code != http.StatusBadRequest || e.Code != "BULK_DISMISS_TOO_LARGE" || e.Details["count"] != 501 || e.Details["max"] != 500 {
		t.Fatalf("501 ids: %d %s", w.Code, w.Body.String())
	}
	for _, body := range []string{
		`{"closure_reason":"detection_error"}`,
		`{"finding_ids":[` + ids[0] + `],"filter":{},"expected_count":1,"closure_reason":"detection_error"}`,
		`{"finding_ids":["not-an-id"],"closure_reason":"detection_error"}`,
	} {
		w := httptest.NewRecorder()
		if _, ok := h.parseBulkDismiss(w, bulkDismissRequest(ctx, body), "test"); ok || w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%s: %d, want 422", body, w.Code)
		}
	}
	a := bulkDismissHash(BulkDismissRequest{FindingIDs: []string{"b", "a"}, ClosureReason: "detection_error", Note: "x"})
	b := bulkDismissHash(BulkDismissRequest{FindingIDs: []string{"a", "b"}, ClosureReason: "detection_error", Note: "x"})
	c := bulkDismissHash(BulkDismissRequest{FindingIDs: []string{"a", "b"}, ClosureReason: "detection_error", Note: "y"})
	if a != b || a == c {
		t.Fatal("the request hash depends on id order, or ignores the note")
	}
}

// The requester of a bulk is recorded by the id every approve, reject and
// leave-out path compares with (GetUserID), also when the synced local user
// has another id (OIDC: the identity provider's subject).
func TestParseBulkDismiss_RequesterIsTheComparedID(t *testing.T) {
	h := &VulnerabilityHandler{}
	tid, sub := shared.NewID().String(), shared.NewID().String()
	local, err := user.NewLocalUserWithID(shared.NewID(), "local@example.com", "Local")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.WithValue(context.WithValue(context.Background(),
		middleware.TenantIDKey, tid), middleware.UserIDKey, sub), middleware.LocalUserKey, local)
	body := `{"finding_ids":["` + shared.NewID().String() + `"],"closure_reason":"detection_error","idempotency_key":"k"}`
	in, ok := h.parseBulkDismiss(httptest.NewRecorder(), bulkDismissRequest(ctx, body), "test")
	if !ok {
		t.Fatal("refused")
	}
	if in.UserID.String() != sub || in.UserID == local.ID() {
		t.Fatalf("requester %s, want the authenticated subject %s (local %s)", in.UserID, sub, local.ID())
	}
	if got := bulkActorID(bulkDismissRequest(ctx, body)); got != sub {
		t.Fatalf("bulkActorID %s, want %s", got, sub)
	}
}
