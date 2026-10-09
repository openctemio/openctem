package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type fakeConfirmer struct {
	approved map[string]string // id -> digest
	requests int
}

func (f *fakeConfirmer) RequestConfirmation(_ context.Context, _ *mcpoauthapp.Principal, _, digest, summary string, _ mcpoauthapp.Actor) (*mcpoauthapp.PendingConfirmation, error) {
	f.requests++
	if !strings.Contains(summary, "triage note") {
		return nil, mcpoauth.ErrConfirmationRequired
	}
	return &mcpoauthapp.PendingConfirmation{ID: "c1", URL: "https://openctem.example/mcp/confirm/c1"}, nil
}

func (f *fakeConfirmer) UseConfirmation(_ context.Context, _ *mcpoauthapp.Principal, id, _, digest string) error {
	if d, ok := f.approved[id]; ok && d == digest {
		delete(f.approved, id)
		return nil
	}
	return mcpoauth.ErrConfirmationRequired
}

type fakeCommenter struct {
	added []finding.AddFindingCommentInput
}

func (f *fakeCommenter) AddFindingCommentWithInput(_ context.Context, in finding.AddFindingCommentInput) (*vulnerability.FindingComment, error) {
	f.added = append(f.added, in)
	return vulnerability.NewFindingComment(shared.MustIDFromString(in.TenantID), shared.MustIDFromString(in.FindingID), shared.MustIDFromString(in.AuthorID), in.Content)
}

const (
	wtTenant  = "11111111-1111-1111-1111-111111111111"
	wtUser    = "22222222-2222-2222-2222-222222222222"
	wtFinding = "33333333-3333-3333-3333-333333333333"
)

func wtRequest(t *testing.T, h *MCPHandler, principal bool, perms []string, body string) map[string]any {
	t.Helper()
	ctx := context.WithValue(context.Background(), middleware.TenantIDKey, wtTenant)
	ctx = context.WithValue(ctx, middleware.UserIDKey, wtUser)
	ctx = context.WithValue(ctx, middleware.PermissionsKey, perms)
	ctx = context.WithValue(ctx, middleware.IsAdminKey, false)
	if principal {
		ctx = context.WithValue(ctx, middleware.MCPPrincipalKey, &mcpoauthapp.Principal{GrantID: "g1", TenantID: wtTenant, UserID: wtUser, Permissions: perms})
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewBufferString(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body %s: %v", rec.Body.String(), err)
	}
	return out
}

func toolNames(resp map[string]any) map[string]bool {
	names := map[string]bool{}
	tools, _ := resp["result"].(map[string]any)["tools"].([]any)
	for _, tl := range tools {
		names[tl.(map[string]any)["name"].(string)] = true
	}
	return names
}

func resultText(resp map[string]any) (string, bool) {
	res := resp["result"].(map[string]any)
	content := res["content"].([]any)[0].(map[string]any)
	return content["text"].(string), res["isError"].(bool)
}

func TestWriteToolNeedsAPersonAndConfirmation(t *testing.T) {
	findings := &fakeFindingReader{finding: makePentestFinding(t)}
	h := newTestMCP(findings)
	conf := &fakeConfirmer{approved: map[string]string{}}
	comments := &fakeCommenter{}
	h.SetWriteTools(conf, comments)
	perms := []string{"findings:read", "findings:write"}
	list := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

	// Listed for a person's connection holding the permission; never for an API key.
	if !toolNames(wtRequest(t, h, true, perms, list))["add_finding_comment"] {
		t.Fatal("write tool not listed for an OAuth connection with findings:write")
	}
	if toolNames(wtRequest(t, h, false, perms, list))["add_finding_comment"] {
		t.Fatal("write tool listed for an API key")
	}
	if toolNames(wtRequest(t, h, true, []string{"findings:read"}, list))["add_finding_comment"] {
		t.Fatal("write tool listed without findings:write")
	}

	call := func(principal bool, args string) (string, bool) {
		return resultText(wtRequest(t, h, principal, perms,
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add_finding_comment","arguments":`+args+`}}`))
	}
	args := `{"finding_id":"` + wtFinding + `","content":"triage note"}`

	// API key: refused, nothing written.
	if text, isErr := call(false, args); !isErr || !strings.Contains(text, "API keys cannot change data") {
		t.Fatalf("api key call: %v %s", isErr, text)
	}
	// First call: a confirmation link, nothing written.
	text, isErr := call(true, args)
	if isErr || !strings.Contains(text, `"status":"confirmation_required"`) || !strings.Contains(text, "/mcp/confirm/c1") || len(comments.added) != 0 {
		t.Fatalf("first call: %v %s (written %d)", isErr, text, len(comments.added))
	}
	// Second call before approval: refused.
	withID := `{"finding_id":"` + wtFinding + `","content":"triage note","confirmation_id":"c1"}`
	if text, isErr := call(true, withID); !isErr || !strings.Contains(text, "not confirmed") || len(comments.added) != 0 {
		t.Fatalf("unapproved call: %v %s", isErr, text)
	}
	// Approved for these exact arguments: runs once, as an internal comment by the user.
	var a map[string]any
	_ = json.Unmarshal([]byte(withID), &a)
	conf.approved["c1"] = mcpoauthapp.ArgsDigest("add_finding_comment", a)
	if text, isErr := call(true, `{"finding_id":"`+wtFinding+`","content":"changed text","confirmation_id":"c1"}`); !isErr || len(comments.added) != 0 {
		t.Fatalf("changed arguments ran: %v %s", isErr, text)
	}
	if text, isErr := call(true, withID); isErr || !strings.Contains(text, `"status":"done"`) || len(comments.added) != 1 {
		t.Fatalf("approved call: %v %s", isErr, text)
	}
	if got := comments.added[0]; !got.IsInternal || got.AuthorID != wtUser || got.TenantID != wtTenant || got.Content != "triage note" {
		t.Fatalf("comment written as %+v", got)
	}
	if _, isErr := call(true, withID); !isErr || len(comments.added) != 1 {
		t.Fatal("approved action ran twice")
	}
	// Bad input never reaches the confirmation step.
	before := conf.requests
	for _, bad := range []string{`{"finding_id":"x","content":"a"}`, `{"finding_id":"` + wtFinding + `","content":"   "}`,
		`{"finding_id":"` + wtFinding + `","content":"` + strings.Repeat("a", maxMCPCommentLen+1) + `"}`} {
		if _, isErr := call(true, bad); !isErr {
			t.Errorf("bad input accepted: %s", bad[:40])
		}
	}
	if conf.requests != before {
		t.Fatal("bad input created a confirmation")
	}
}
