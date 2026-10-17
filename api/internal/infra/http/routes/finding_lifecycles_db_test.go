package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	entitlementapp "github.com/openctemio/openctem/api/internal/app/entitlement"
	lcapp "github.com/openctemio/openctem/api/internal/app/findinglifecycle"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func newLifecycleHarness(t *testing.T) *authzPolicyHarness {
	t.Helper()
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		entitlement := entitlementapp.NewService(postgres.NewLimitsRepository(db), nil, log)
		svc := lcapp.NewService(postgres.NewLifecycleSubStatusRepository(db), postgres.NewLifecycleSchemeRepository(db),
			entitlement, auditapp.NewAuditService(postgres.NewAuditRepository(db), log), log)
		hs.FindingLifecycle = handler.NewFindingLifecycleHandler(svc, log)
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	return newChangeAuditHarness(t)
}

func lifecycleJSON(t *testing.T, body string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return out
}

// putDraft sends a draft spec with an If-Match header.
func (h *authzPolicyHarness) putDraft(u policyUser, path, ifMatch, body string) (int, string) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+u.token)
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// The lifecycle catalog and schemes through the real routes (RFC-110): a
// member reads but changes nothing; an admin builds sub-statuses and a
// scheme, edits the draft with If-Match, cannot publish an invalid one,
// publishes a valid one and rolls back; another organization sees and
// changes none of it; the category of a sub-status never changes; a sub-status
// used by a published version cannot be archived; an organization with limits
// is held to them; every change is audited.
func TestFindingLifecycles_Routes_DB(t *testing.T) {
	h := newLifecycleHarness(t)
	org, other := h.tenant(), h.tenant()
	admin, member := h.member(org, "admin"), h.member(org, "member")
	otherAdmin := h.member(other, "admin")
	const subs = "/api/v1/lifecycle-sub-statuses"
	const schemes = "/api/v1/lifecycles"

	// Members read, never write.
	h.expect(member, http.MethodGet, subs, "", http.StatusOK)
	h.expect(member, http.MethodPost, subs, `{"key":"in_dev","canonical_status":"in_progress","name":"In development","color":"blue"}`, http.StatusForbidden)
	h.expect(member, http.MethodPost, schemes, `{"key":"default","name":"Default"}`, http.StatusForbidden)

	mkSub := func(body string) string {
		t.Helper()
		return lifecycleJSON(t, h.expect(admin, http.MethodPost, subs, body, http.StatusCreated))["id"].(string)
	}
	inDev := mkSub(`{"key":"in_dev","canonical_status":"in_progress","name":"In development","color":"blue","labels":{"vi":"Đang phát triển"}}`)
	inReview := mkSub(`{"key":"in_review","canonical_status":"in_progress","name":"In review","color":"violet"}`)
	bounty := mkSub(`{"key":"bounty_paid","canonical_status":"resolved","closure_reason":"fixed","name":"Bounty paid","color":"green"}`)
	h.expect(admin, http.MethodPost, subs, `{"key":"in_dev","canonical_status":"confirmed","name":"Dup","color":"red"}`, http.StatusConflict)
	h.expect(admin, http.MethodPost, subs, `{"key":"wont","canonical_status":"resolved","closure_reason":"wont_fix","name":"Won't fix","color":"red"}`, http.StatusBadRequest)
	h.expect(admin, http.MethodPost, subs, `{"key":"x_css","canonical_status":"new","name":"x","color":"#ff0000"}`, http.StatusBadRequest)
	// The category never changes.
	h.expect(admin, http.MethodPatch, subs+"/"+inDev, `{"canonical_status":"confirmed"}`, http.StatusBadRequest)
	h.expect(admin, http.MethodPatch, subs+"/"+inDev, `{"name":"Development"}`, http.StatusOK)

	// Another organization sees none of it and changes none of it.
	if list := lifecycleJSON(t, h.expect(otherAdmin, http.MethodGet, subs, "", http.StatusOK)); len(list["data"].([]any)) != 0 {
		t.Fatalf("another organization lists %v", list["data"])
	}
	h.expect(otherAdmin, http.MethodPatch, subs+"/"+inDev, `{"name":"hijack"}`, http.StatusNotFound)
	h.expect(otherAdmin, http.MethodDelete, subs+"/"+inDev, "", http.StatusNotFound)

	// A default scheme with an empty first draft; one default only.
	sc := lifecycleJSON(t, h.expect(admin, http.MethodPost, schemes, `{"key":"default","name":"Default lifecycle"}`, http.StatusCreated))
	id := sc["id"].(string)
	draft := sc["draft"].(map[string]any)
	if sc["default"] != true || draft["version"].(float64) != 1 || draft["state"] != "draft" {
		t.Fatalf("new scheme: %v", sc)
	}
	h.expect(admin, http.MethodPost, schemes, `{"key":"second","name":"Second"}`, http.StatusConflict)
	h.expect(admin, http.MethodPost, schemes, `{"key":"kev","name":"KEV","priority":10,"context":[{"field":"is_kev","op":"eq","value":true}]}`, http.StatusCreated)
	h.expect(admin, http.MethodPost, schemes, `{"key":"bad_ctx","name":"Bad","context":[{"field":"email","op":"eq","value":"x"}]}`, http.StatusBadRequest)
	h.expect(otherAdmin, http.MethodGet, schemes+"/"+id, "", http.StatusNotFound)

	// Editing a draft needs If-Match; a stale hash is refused.
	v1 := schemes + "/" + id + "/versions/1"
	spec := fmt.Sprintf(`{"spec":{"sub_statuses":[%q,%q,%q],"transitions":[{"id":"to_review","name":"Send to review","from":[%q],"to":%q,"guards":[{"kind":"require_note","min_len":10}]}]}}`,
		inDev, inReview, bounty, inDev, inReview)
	if code, body := h.putDraft(admin, v1, "", spec); code != http.StatusBadRequest {
		t.Fatalf("draft without If-Match: %d %s", code, body)
	}
	if code, body := h.putDraft(admin, v1, "stale", spec); code != http.StatusConflict {
		t.Fatalf("stale draft: %d %s", code, body)
	}
	code, body := h.putDraft(admin, v1, draft["spec_hash"].(string), spec)
	if code != http.StatusOK || lifecycleJSON(t, body)["valid"] != true {
		t.Fatalf("draft update: %d %s", code, body)
	}
	hash := lifecycleJSON(t, body)["version"].(map[string]any)["spec_hash"].(string)
	if code, body := h.putDraft(otherAdmin, v1, hash, spec); code != http.StatusNotFound {
		t.Fatalf("another organization edited the draft: %d %s", code, body)
	}

	// An invalid draft cannot be published: an edge the lifecycle lacks.
	bad := fmt.Sprintf(`{"spec":{"sub_statuses":[%q],"transitions":[{"id":"skip","name":"Skip","from":["status:new"],"to":"status:resolved"},{"id":"x","name":"X","from":[%q],"to":"status:new"}]}}`, inDev, inDev)
	code, body = h.putDraft(admin, v1, hash, bad)
	if code != http.StatusOK || lifecycleJSON(t, body)["valid"] != false {
		t.Fatalf("invalid draft saved as valid: %d %s", code, body)
	}
	hash = lifecycleJSON(t, body)["version"].(map[string]any)["spec_hash"].(string)
	h.expect(admin, http.MethodPost, v1+"/publish", `{"note":"try"}`, http.StatusUnprocessableEntity)
	code, body = h.putDraft(admin, v1, hash, spec)
	if code != http.StatusOK {
		t.Fatalf("restore draft: %d %s", code, body)
	}

	// Members cannot validate or publish; the admin publishes.
	h.expect(member, http.MethodPost, v1+"/publish", "", http.StatusForbidden)
	h.expect(otherAdmin, http.MethodPost, v1+"/publish", "", http.StatusNotFound)
	if r := lifecycleJSON(t, h.expect(admin, http.MethodPost, v1+"/test", "", http.StatusOK)); r["valid"] != true {
		t.Fatalf("validate: %v", r)
	}
	pub := lifecycleJSON(t, h.expect(admin, http.MethodPost, v1+"/publish", `{"note":"first"}`, http.StatusOK))
	if pub["state"] != "published" || pub["note"] != "first" {
		t.Fatalf("publish: %v", pub)
	}
	h.expect(admin, http.MethodPost, v1+"/publish", "", http.StatusConflict) // already in force
	code, body = h.putDraft(admin, v1, hash, spec)
	if code != http.StatusConflict {
		t.Fatalf("edit a published version: %d %s", code, body)
	}

	// A published version uses in_review: it cannot be archived.
	h.expect(admin, http.MethodDelete, subs+"/"+inReview, "", http.StatusConflict)

	// v2 without in_review; then roll back to v1 (published again as v3).
	d2 := lifecycleJSON(t, h.expect(admin, http.MethodPost, schemes+"/"+id+"/versions", "", http.StatusCreated))
	h.expect(admin, http.MethodPost, schemes+"/"+id+"/versions", "", http.StatusConflict) // one draft
	v2 := schemes + "/" + id + "/versions/2"
	code, body = h.putDraft(admin, v2, d2["spec_hash"].(string), fmt.Sprintf(`{"spec":{"sub_statuses":[%q,%q]}}`, inDev, bounty))
	if code != http.StatusOK {
		t.Fatalf("v2 draft: %d %s", code, body)
	}
	h.expect(admin, http.MethodPost, v2+"/publish", "", http.StatusOK)
	h.expect(admin, http.MethodDelete, subs+"/"+inReview, "", http.StatusOK) // no longer published
	// Rolling back to v1 needs in_review, now archived: refused, v1 stays history.
	h.expect(admin, http.MethodPost, v1+"/publish", "", http.StatusUnprocessableEntity)
	h.expect(admin, http.MethodPost, subs+"/"+inReview+"/reactivate", "", http.StatusOK)
	// The refused roll back left a draft (v3 copied from v1): publishing it
	// now works.
	h.expect(admin, http.MethodPost, schemes+"/"+id+"/versions/3/publish", `{"note":"roll back"}`, http.StatusOK)
	versions := lifecycleJSON(t, h.expect(member, http.MethodGet, schemes+"/"+id+"/versions", "", http.StatusOK))["data"].([]any)
	states := []string{}
	for _, v := range versions {
		states = append(states, v.(map[string]any)["state"].(string))
	}
	if strings.Join(states, ",") != "published,superseded,superseded" {
		t.Fatalf("version states newest first = %v", states)
	}

	// Every change is audited; the publish is high severity.
	var publishes int
	if err := h.db.QueryRow(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'lifecycle.published' AND severity = 'high'`, org).Scan(&publishes); err != nil {
		t.Fatal(err)
	}
	if publishes != 3 {
		t.Errorf("publish audit rows = %d, want 3", publishes)
	}

	// An organization with limits: three labels, no scheme.
	free := h.tenant()
	freeAdmin := h.member(free, "admin")
	for key, value := range map[string]int{"lifecycle_sub_statuses": 3, "lifecycle_schemes": 0} {
		h.exec(`INSERT INTO tenant_limits (tenant_id, limit_key, value, reason, set_at, origin)
			VALUES ($1, $2, $3, 'test', now(), 'operator')`, free, key, value)
	}
	for i := range 3 {
		h.expect(freeAdmin, http.MethodPost, subs, fmt.Sprintf(`{"key":"label_%d","canonical_status":"new","name":"Label %d","color":"gray"}`, i, i), http.StatusCreated)
	}
	code, body = h.do(freeAdmin, http.MethodPost, subs, `{"key":"label_4","canonical_status":"new","name":"Label 4","color":"gray"}`)
	if code != http.StatusForbidden || !jsonHas(body, "code", "LIMIT_REACHED") {
		t.Fatalf("fourth sub-status over the limit: %d %s", code, body)
	}
	code, body = h.do(freeAdmin, http.MethodPost, schemes, `{"key":"default","name":"Default"}`)
	if code != http.StatusForbidden || !jsonHas(body, "code", "LIMIT_REACHED") {
		t.Fatalf("lifecycle scheme over a limit of 0: %d %s", code, body)
	}
}
