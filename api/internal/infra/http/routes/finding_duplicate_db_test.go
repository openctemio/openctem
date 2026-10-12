package routes

// POST /api/v1/findings/{id}/duplicates over the real routes, handler,
// service, repository and a migrated database: the permission gate, tenant
// and data-scope isolation, the same-asset and approval rules, and the merge
// itself (comments and retests move, the duplicate stays as a tombstone, an
// activity and an audit event record who did it).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// dupFinding inserts a finding on asset in the harness tenant.
func (h *dsHarness) dupFinding(asset shared.ID, source, status string) shared.ID {
	h.t.Helper()
	id := shared.NewID()
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, $4, 'dup-tool', 'dup finding', 'high', $1::text, $5)`,
		id.String(), h.tenant.String(), asset.String(), source, status)
	return id
}

// markDup marks dup a duplicate of of, as user with perms (nil = the harness
// default).
func (h *dsHarness) markDup(user shared.ID, admin bool, perms []string, dup, of shared.ID) (int, string) {
	h.t.Helper()
	b, _ := json.Marshal(map[string]string{"finding_id": dup.String()})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		h.srv.URL+"/api/v1/findings/"+of.String()+"/duplicates", bytes.NewReader(b))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User", user.String())
	if admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	if perms != nil {
		req.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (h *dsHarness) dupState(id shared.ID) (status, duplicateOf string) {
	h.t.Helper()
	var d sql.NullString
	if err := h.db.QueryRow(`SELECT status, duplicate_of::text FROM findings WHERE id = $1`, id.String()).Scan(&status, &d); err != nil {
		h.t.Fatal(err)
	}
	return status, d.String
}

func (h *dsHarness) countRows(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(q, args...).Scan(&n); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestMarkDuplicate_MergesAndRecordsWho(t *testing.T) {
	h := newDSHarness(t)
	canonical := h.findingA
	dup := h.dupFinding(h.assetA, "dast", "new")
	h.exec(`INSERT INTO finding_comments (finding_id, author_id, content, tenant_id) VALUES ($1, $2, 'on the duplicate', $3)`,
		dup.String(), h.owner.String(), h.tenant.String())
	h.exec(`INSERT INTO finding_retests (id, tenant_id, finding_id, trigger, status, outcome, completed_at,
			prior_status, template_id, target, deadline_at) VALUES ($1,$2,$3,'manual','completed','not_reproduced',NOW(),
			'new','tpl','https://a.example',NOW()-interval '1 hour')`, shared.NewID().String(), h.tenant.String(), dup.String())

	// memberA's scope is asset A: both findings are in it.
	status, body := h.markDup(h.memberA, false, nil, dup, canonical)
	if status != http.StatusOK || !strings.Contains(body, canonical.String()) {
		t.Fatalf("mark duplicate = %d %.300s", status, body)
	}
	if st, of := h.dupState(dup); st != "duplicate" || of != canonical.String() {
		t.Fatalf("duplicate is %s of %q, want a tombstone of the canonical finding", st, of)
	}
	if st, _ := h.dupState(canonical); st != "confirmed" {
		t.Fatalf("canonical finding status %s, want its own (confirmed, stronger than new)", st)
	}
	if n := h.countRows(`SELECT count(*) FROM finding_comments WHERE finding_id = $1 AND content = 'on the duplicate'`, canonical.String()); n != 1 {
		t.Fatalf("comment not moved to the canonical finding (%d)", n)
	}
	if n := h.countRows(`SELECT count(*) FROM finding_retests WHERE finding_id = $1`, canonical.String()); n != 1 {
		t.Fatalf("retest not moved to the canonical finding (%d)", n)
	}
	if n := h.countRows(`SELECT count(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'duplicate_marked'
			AND actor_type = 'user' AND actor_id = $2 AND source = 'manual'`, dup.String(), h.memberA.String()); n != 1 {
		t.Fatalf("no user activity on the duplicate (%d)", n)
	}
	if n := h.countRows(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.duplicate_marked'
			AND resource_id = $2 AND actor_id = $3`, h.tenant.String(), dup.String(), h.memberA.String()); n != 1 {
		t.Fatalf("no audit event (%d)", n)
	}

	// The tombstone cannot be folded again, or be the target of a fold.
	other := h.dupFinding(h.assetA, "dast", "new")
	if status, body := h.markDup(h.owner, true, nil, dup, other); status != http.StatusConflict {
		t.Fatalf("re-marking a tombstone = %d %.200s, want 409", status, body)
	}
	if status, body := h.markDup(h.owner, true, nil, other, dup); status != http.StatusConflict {
		t.Fatalf("folding into a tombstone = %d %.200s, want 409", status, body)
	}
}

func TestMarkDuplicate_IsolationAndRules(t *testing.T) {
	h := newDSHarness(t)
	a2 := h.dupFinding(h.assetA, "sast", "new")
	unchanged := func(ids ...shared.ID) {
		t.Helper()
		for _, id := range ids {
			if st, of := h.dupState(id); st == "duplicate" || of != "" {
				t.Fatalf("finding %s changed: %s %s", id, st, of)
			}
		}
	}

	t.Run("without findings:triage", func(t *testing.T) {
		perms := []string{permission.FindingsRead.String(), permission.FindingsWrite.String(), permission.FindingsStatus.String()}
		if status, _ := h.markDup(h.memberA, false, perms, a2, h.findingA); status != http.StatusForbidden {
			t.Fatalf("status %d, want 403", status)
		}
		unchanged(a2, h.findingA)
	})

	t.Run("target outside the data scope is not found", func(t *testing.T) {
		// Same asset rule aside, finding B is outside memberA's scope: 404,
		// never a hint that it exists.
		if status, _ := h.markDup(h.memberA, false, nil, h.findingA, h.findingB); status != http.StatusNotFound {
			t.Fatalf("status %d, want 404", status)
		}
		if status, _ := h.markDup(h.memberA, false, nil, h.findingB, h.findingA); status != http.StatusNotFound {
			t.Fatalf("status %d, want 404", status)
		}
		unchanged(h.findingA, h.findingB)
	})

	t.Run("another tenant's finding is not found", func(t *testing.T) {
		other, asset, foreign := shared.NewID(), shared.NewID(), shared.NewID()
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "dup-other-"+other.String())
		t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'dup-other.example.com', 'domain')`, asset.String(), other.String())
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'sast', 'dup-tool', 'foreign', 'high', $1::text, 'accepted')`, foreign.String(), other.String(), asset.String())
		for _, pair := range [][2]shared.ID{{a2, foreign}, {foreign, a2}} {
			if status, _ := h.markDup(h.owner, true, nil, pair[0], pair[1]); status != http.StatusNotFound {
				t.Fatalf("%s -> %s: status %d, want 404", pair[0], pair[1], status)
			}
		}
		unchanged(a2, foreign)
	})

	t.Run("different assets", func(t *testing.T) {
		if status, _ := h.markDup(h.owner, true, nil, h.findingA, h.findingB); status != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", status)
		}
		unchanged(h.findingA, h.findingB)
	})

	t.Run("itself", func(t *testing.T) {
		if status, _ := h.markDup(h.owner, true, nil, a2, a2); status != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", status)
		}
	})

	t.Run("pentest", func(t *testing.T) {
		p := h.dupFinding(h.assetA, "pentest", "new")
		if status, _ := h.markDup(h.owner, true, nil, p, a2); status != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", status)
		}
		unchanged(p, a2)
	})

	t.Run("risk acceptance needs findings:approve", func(t *testing.T) {
		accepted := h.dupFinding(h.assetA, "sast", "accepted")
		open := h.dupFinding(h.assetA, "sast", "new")
		// The harness member holds triage but not approve.
		if status, body := h.markDup(h.memberA, false, nil, open, accepted); status != http.StatusForbidden {
			t.Fatalf("closing an open finding under a risk acceptance = %d %.200s, want 403", status, body)
		}
		if status, _ := h.markDup(h.memberA, false, nil, accepted, open); status != http.StatusForbidden {
			t.Fatalf("carrying a risk acceptance onto an open finding = %d, want 403", status)
		}
		unchanged(open, accepted)
		perms := append(append([]string{}, dsMemberPerms...), permission.FindingsApprove.String())
		if status, body := h.markDup(h.memberA, false, perms, open, accepted); status != http.StatusOK {
			t.Fatalf("with findings:approve = %d %.200s", status, body)
		}
	})
}
