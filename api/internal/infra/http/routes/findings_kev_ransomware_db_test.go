package routes

// The findings list says when a KEV finding is used in known ransomware
// campaigns (kev_ransomware, read from the global KEV catalog for the page's
// KEV findings), and the kev_ransomware filter matches the same rule. Both
// stay inside the caller's data scope: the catalog is public, the findings
// are not.

import (
	"encoding/json"
	"strings"
	"testing"
)

type krResponse struct {
	Data []struct {
		ID            string `json:"id"`
		KEVRansomware bool   `json:"kev_ransomware"`
	} `json:"data"`
}

func TestFindingsList_KEVRansomware(t *testing.T) {
	h := newGroupScopeHarness(t)
	// FA (in memberA's scope) and FB (out of it): both KEV; only FA's CVE is
	// used in ransomware campaigns.
	h.exec(`INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added, known_ransomware_campaign_use)
		VALUES ($1, 'IT', CURRENT_DATE, 'Known'), ($2, 'IT', CURRENT_DATE, 'Unknown')`, h.cveA, h.cveB)
	t.Cleanup(func() { h.exec(`DELETE FROM kev_catalog WHERE cve_id = ANY(ARRAY[$1, $2])`, h.cveA, h.cveB) })
	h.exec(`UPDATE findings SET is_in_kev = true WHERE id = ANY(ARRAY[$1::uuid, $2::uuid])`, h.findingA.String(), h.findingB.String())

	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}
	fa, fb := h.findingA.String(), h.findingB.String()

	if ids, _, _ := h.listIDs(t, admin, "kev_ransomware=true"); strings.Join(ids, ",") != fa {
		t.Errorf("owner kev_ransomware=true = %v, want [FA]", ids)
	}
	if ids, _, _ := h.listIDs(t, admin, "kev_ransomware=false&is_in_kev=true"); strings.Join(ids, ",") != fb {
		t.Errorf("owner kev_ransomware=false&is_in_kev=true = %v, want [FB]", ids)
	}
	if ids, _, _ := h.listIDs(t, memberA, "kev_ransomware=true"); strings.Join(ids, ",") != fa {
		t.Errorf("memberA kev_ransomware=true = %v, want [FA]", ids)
	}
	// Out of scope stays out of scope under the filter.
	if ids, _, body := h.listIDs(t, memberA, "kev_ransomware=false&is_in_kev=true"); len(ids) != 0 || strings.Contains(body, fb) {
		t.Errorf("memberA kev_ransomware=false&is_in_kev=true = %v, want none", ids)
	}

	// The list rows carry the flag.
	_, _, body := h.listIDs(t, admin, "is_in_kev=true")
	var out krResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, d := range out.Data {
		got[d.ID] = d.KEVRansomware
	}
	if v, ok := got[fa]; !ok || !v {
		t.Errorf("FA kev_ransomware = %v (listed %v), want true", v, ok)
	}
	if v, ok := got[fb]; !ok || v {
		t.Errorf("FB kev_ransomware = %v (listed %v), want false", v, ok)
	}
}
