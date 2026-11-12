package routes

// GET /attack-surface/certificates: a certificate is visible exactly when its
// asset is. Another tenant's certificates, certificates outside the caller's
// data scope, soft-deleted ones and assets of other types never appear, in the
// list, the counts or a search; a member with no scope row sees nothing.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	certMarkerA     = "cert-a.dsa.example"
	certMarkerB     = "cert-b-SECRET.dsb.example"
	certMarkerOther = "cert-other-tenant.example"
	certMarkerGone  = "cert-deleted.dsa.example"
)

type certSeed struct{ a, b, other shared.ID }

func (h *dsHarness) seedCertificates() certSeed {
	h.t.Helper()
	s := certSeed{a: shared.NewID(), b: shared.NewID(), other: shared.NewID()}
	t := h.tenant.String()
	ins := `INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality, properties)
		VALUES ($1, $2, $3, $4, 'public', 'low', $5::jsonb)`
	props := func(cn, notAfter, fp string) string {
		b, _ := json.Marshal(map[string]any{"subject_cn": cn, "issuer_cn": "Test CA", "issuer_org": "Test Org",
			"not_before": "2025-01-01T00:00:00Z", "not_after": notAfter, "fingerprint_sha256": fp})
		return string(b)
	}
	past := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	soon := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	h.exec(ins, s.a.String(), t, certMarkerA, "certificate", props(certMarkerA, past, "aa11"))
	h.exec(ins, s.b.String(), t, certMarkerB, "certificate", props(certMarkerB, soon, "bb22"))
	// Same tenant and scope as A, but soft-deleted and not a certificate.
	gone := shared.NewID()
	h.exec(ins, gone.String(), t, certMarkerGone, "certificate", props(certMarkerGone, past, "cc33"))
	h.exec(`UPDATE assets SET deleted_at = now() WHERE id = $1`, gone.String())
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.memberA.String(), t, s.a.String())
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.memberA.String(), t, gone.String())

	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "cert-other-"+other.String())
	h.t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	h.exec(ins, s.other.String(), other.String(), certMarkerOther, "certificate", props(certMarkerOther, past, "dd44"))
	return s
}

func certTotal(t *testing.T, body string) int {
	t.Helper()
	var r struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return r.Total
}

func TestCertificates_DataScopeAndTenant_DB(t *testing.T) {
	h := newDSHarness(t)
	h.seedCertificates()
	const list = "/api/v1/attack-surface/certificates"

	// The scoped member sees only the certificate in scope, never B's
	// fingerprint, subject or counts, nor a deleted one.
	st, body := h.do(h.memberA, false, http.MethodGet, list, nil)
	if st != http.StatusOK || certTotal(t, body) != 1 || !strings.Contains(body, certMarkerA) ||
		!strings.Contains(body, `"status":"expired"`) || strings.Contains(body, "SECRET") || strings.Contains(body, "bb22") ||
		strings.Contains(body, certMarkerGone) {
		t.Fatalf("memberA list = %d %s", st, body)
	}
	st, body = h.do(h.memberA, false, http.MethodGet, list+"/stats", nil)
	if st != http.StatusOK || !strings.Contains(body, `"total":1`) || !strings.Contains(body, `"expired":1`) || !strings.Contains(body, `"expiring_soon":0`) {
		t.Fatalf("memberA stats = %d %s", st, body)
	}
	// A search and a filter on B's values find nothing for the member.
	for _, q := range []string{"?q=SECRET", "?fingerprint=bb22", "?subject_cn_contains=SECRET", "?status=expiring_soon"} {
		if st, body := h.do(h.memberA, false, http.MethodGet, list+q, nil); st != http.StatusOK || certTotal(t, body) != 0 || strings.Contains(body, "SECRET") {
			t.Errorf("memberA %s = %d %s, want empty", q, st, body)
		}
	}
	// A member with no scope row sees nothing.
	if st, body := h.do(h.memberStrict, false, http.MethodGet, list, nil); st != http.StatusOK || certTotal(t, body) != 0 {
		t.Errorf("member without scope list = %d %s", st, body)
	}
	if st, body := h.do(h.memberStrict, false, http.MethodGet, list+"/stats", nil); st != http.StatusOK || !strings.Contains(body, `"total":0`) {
		t.Errorf("member without scope stats = %d %s", st, body)
	}

	// The owner sees the tenant's two live certificates, never another
	// tenant's or the deleted one; the status filter and counts agree.
	st, body = h.do(h.owner, true, http.MethodGet, list, nil)
	if st != http.StatusOK || certTotal(t, body) != 2 || strings.Contains(body, certMarkerOther) || strings.Contains(body, "dd44") || strings.Contains(body, certMarkerGone) {
		t.Fatalf("owner list = %d %s", st, body)
	}
	if st, body := h.do(h.owner, true, http.MethodGet, list+"?status=expiring_soon", nil); st != http.StatusOK || certTotal(t, body) != 1 || !strings.Contains(body, certMarkerB) {
		t.Errorf("owner expiring_soon = %d %s", st, body)
	}
	if st, body := h.do(h.owner, true, http.MethodGet, list+"/stats", nil); st != http.StatusOK ||
		!strings.Contains(body, `"total":2`) || !strings.Contains(body, `"expired":1`) || !strings.Contains(body, `"expiring_soon":1`) {
		t.Errorf("owner stats = %d %s", st, body)
	}
	if st, body := h.do(h.owner, true, http.MethodGet, list+"?not_after_lte=2000-01-01", nil); st != http.StatusOK || certTotal(t, body) != 0 {
		t.Errorf("expiry range filter = %d %s", st, body)
	}
	if st, _ := h.do(h.owner, true, http.MethodGet, list+"?nonsense=1", nil); st != http.StatusBadRequest {
		t.Errorf("unknown param = %d, want 400", st)
	}
}
