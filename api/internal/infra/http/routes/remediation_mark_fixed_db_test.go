package routes

// "Resolve" on a remediation group is a "mark fixed", over the real route,
// handler, services and a migrated database: every open, in-scope finding of
// the group takes the legal steps to fix_applied (new → confirmed →
// in_progress → fix_applied), with the note, only for the caller's own
// findings; a proof-of-fix re-check is queued per finding; a finding already
// fix_applied is skipped, not rewritten; and every finding that is not
// updated comes back with the reason. Nothing is ever closed.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type markFixedBody struct {
	Updated           int `json:"updated"`
	Skipped           int `json:"skipped"`
	Failed            int `json:"failed"`
	ValidationsQueued int `json:"validations_queued"`
	Rows              []struct {
		FindingID string `json:"finding_id"`
		Outcome   string `json:"outcome"`
		Reason    string `json:"reason"`
	} `json:"rows"`
}

// addFindingOnA inserts an extra sast finding on A1 (memberA's asset, so the
// claim is theirs) with the status given, in the group key.
func (h *gsHarness) addFindingOnA(status, key string) shared.ID {
	h.t.Helper()
	id := shared.NewID()
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 'ds-tool', 'mark fixed member', 'high', $1::text, $4)`,
		id.String(), h.tenant.String(), h.assetA.String(), status)
	h.exec(`INSERT INTO finding_remediation_keys (finding_id, tenant_id, remediation_key, title) VALUES ($1, $2, $3, 'Upgrade lib')`,
		id.String(), h.tenant.String(), key)
	return id
}

func (h *gsHarness) findingRow(id shared.ID) (status, resolution, by string) {
	h.t.Helper()
	var res, b *string
	if err := h.db.QueryRow(`SELECT status, resolution, resolved_by::text FROM findings WHERE id = $1`, id.String()).
		Scan(&status, &res, &b); err != nil {
		h.t.Fatal(err)
	}
	if res != nil {
		resolution = *res
	}
	if b != nil {
		by = *b
	}
	return status, resolution, by
}

func TestRemediationGroupMarkFixed_LegalStepsReasonsAndProofOfFix(t *testing.T) {
	h := newGroupScopeHarness(t)
	const key = "upgrade:npm/mark-fixed-lib:2.0.0"
	var queued []shared.ID
	h.vuln.SetProofOfFixQueuer(func(_ context.Context, tenantID shared.ID, ids []shared.ID) int {
		if tenantID != h.tenant {
			t.Errorf("proof-of-fix queued for tenant %s", tenantID)
		}
		queued = append(queued, ids...)
		return len(ids)
	})

	fNew := h.addFindingOnA("new", key)
	fConfirmed := h.addFindingOnA("confirmed", key)
	fInProgress := h.addFindingOnA("in_progress", key)
	fClaimed := h.addFindingOnA("fix_applied", key)
	fValidated := h.addFindingOnA("validated_fixed", key)
	h.exec(`UPDATE findings SET resolution = 'earlier claim' WHERE id = $1`, fClaimed.String())

	path := "/api/v1/findings/remediation-groups/" + url.PathEscape(key) + "/resolve"

	// No note: refused, nothing changes.
	if status, body := h.doPerms(h.memberA, rgMemberPerms, http.MethodPost, path, map[string]any{}); status != http.StatusBadRequest {
		t.Errorf("mark fixed without a note = %d %.300s, want 400", status, body)
	}
	// No findings:fix_apply: refused.
	noFixApply := []string{"findings:read", "findings:write", "findings:status", "findings:bulk_update"}
	if status, body := h.doPerms(h.memberA, noFixApply, http.MethodPost, path, map[string]any{"resolution": "patched"}); status != http.StatusForbidden {
		t.Errorf("mark fixed without findings:fix_apply = %d %.300s, want 403", status, body)
	}
	if st, _, _ := h.findingRow(fNew); st != "new" {
		t.Fatalf("a refused request changed a finding to %s", st)
	}

	// Someone whose findings these are not (a full-data reader holding the
	// member grant): every finding comes back failed with the reason.
	status, body := h.doPerms(h.memberFull, rgMemberPerms, http.MethodPost, path, map[string]any{"resolution": "patched"})
	var stranger markFixedBody
	if status != http.StatusOK || json.Unmarshal([]byte(body), &stranger) != nil {
		t.Fatalf("stranger mark fixed = %d %.300s", status, body)
	}
	if stranger.Updated != 0 || len(stranger.Rows) == 0 {
		t.Errorf("stranger mark fixed = %+v, want nothing updated and a reason per finding", stranger)
	}
	for _, r := range stranger.Rows {
		if r.Reason == "" {
			t.Errorf("row %+v has no reason", r)
		}
	}
	if st, _, _ := h.findingRow(fNew); st != "new" {
		t.Fatalf("a stranger's claim moved a finding to %s", st)
	}

	// The owner of A1 (memberA): new, confirmed and in_progress reach
	// fix_applied with the note; fix_applied is skipped; validated_fixed is
	// refused with the reason.
	status, body = h.doPerms(h.memberA, rgMemberPerms, http.MethodPost, path, map[string]any{"resolution": "bumped lib to 2.0.0"})
	var got markFixedBody
	if status != http.StatusOK || json.Unmarshal([]byte(body), &got) != nil {
		t.Fatalf("mark fixed = %d %.300s", status, body)
	}
	if got.Updated != 3 || got.Skipped != 1 || got.Failed != 1 || got.ValidationsQueued != 3 {
		t.Errorf("mark fixed = %+v, want 3 updated, 1 skipped, 1 failed, 3 re-checks queued", got)
	}
	reasons := map[string]string{}
	for _, r := range got.Rows {
		reasons[r.FindingID] = r.Outcome + ": " + r.Reason
	}
	if reasons[fClaimed.String()] == "" || reasons[fValidated.String()] == "" || len(reasons) != 2 {
		t.Errorf("rows = %v, want the skipped fix_applied and the refused validated_fixed finding, each with a reason", reasons)
	}
	for _, id := range []shared.ID{fNew, fConfirmed, fInProgress} {
		st, res, by := h.findingRow(id)
		if st != "fix_applied" || res != "bumped lib to 2.0.0" || by != h.memberA.String() {
			t.Errorf("%s: status=%s resolution=%q by=%q, want fix_applied with the note by memberA", id, st, res, by)
		}
	}
	if st, res, _ := h.findingRow(fClaimed); st != "fix_applied" || res != "earlier claim" {
		t.Errorf("an earlier claim was rewritten: status=%s resolution=%q", st, res)
	}
	if st, _, _ := h.findingRow(fValidated); st != "validated_fixed" {
		t.Errorf("validated_fixed finding moved to %s", st)
	}
	want := []string{fNew.String(), fConfirmed.String(), fInProgress.String()}
	gotQueued := make([]string, 0, len(queued))
	for _, id := range queued {
		gotQueued = append(gotQueued, id.String())
	}
	sort.Strings(want)
	sort.Strings(gotQueued)
	if len(gotQueued) != 3 || gotQueued[0] != want[0] || gotQueued[1] != want[1] || gotQueued[2] != want[2] {
		t.Errorf("proof-of-fix queued for %v, want %v", gotQueued, want)
	}

	// Nothing is ever closed by a group resolve.
	var closed int
	if err := h.db.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND status = 'resolved'`, h.tenant.String()).Scan(&closed); err != nil {
		t.Fatal(err)
	}
	if closed != 0 {
		t.Errorf("%d findings closed by a group resolve", closed)
	}
}
