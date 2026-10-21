package routes

// An asset whose exposure is public is internet-exposed even when its
// is_internet_accessible flag was never set (most public assets): under the
// high_and_above level a false positive on it still needs a second person,
// exactly as on an asset flagged internet-accessible. A private asset with
// the flag off stays a single-person decision.

import (
	"testing"
)

func TestFindingFPPolicy_PublicExposureNeedsSecondApprover_DB(t *testing.T) {
	h := newFPPolicyHarness(t)
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	admin := h.member(org, "admin")
	setFPLevel(h, org, `{"fp_approval":"high_and_above"}`)

	for _, c := range []struct {
		name, setAsset string
		wantSingle     bool
	}{
		{"public exposure, flag unset", `UPDATE assets SET exposure = 'public', is_internet_accessible = false WHERE id = $1`, false},
		{"flag set, exposure private", `UPDATE assets SET exposure = 'private', is_internet_accessible = true WHERE id = $1`, false},
		{"private, flag unset", `UPDATE assets SET exposure = 'private', is_internet_accessible = false WHERE id = $1`, true},
	} {
		f, asset := h.scopedFinding(org)
		h.exec(`UPDATE findings SET severity = 'low', status = 'confirmed' WHERE id = $1`, f)
		h.exec(c.setAsset, asset)
		status, single, _ := requestFP(h, admin, f)
		if single != c.wantSingle || (c.wantSingle && status != "approved") || (!c.wantSingle && status != "pending") {
			t.Fatalf("%s: status %s single %v, want single %v", c.name, status, single, c.wantSingle)
		}
		if !c.wantSingle && findingStatusOf(h, f) == "false_positive" {
			t.Fatalf("%s: the finding was closed by one person", c.name)
		}
	}

	// Another organization's public asset says nothing about this one.
	f, asset := h.scopedFinding(org)
	h.exec(`UPDATE findings SET severity = 'low', status = 'confirmed' WHERE id = $1`, f)
	h.exec(`UPDATE assets SET exposure = 'private', is_internet_accessible = false WHERE id = $1`, asset)
	_, otherAsset := h.scopedFinding(other)
	h.exec(`UPDATE assets SET exposure = 'public' WHERE id = $1`, otherAsset)
	if status, single, _ := requestFP(h, admin, f); !single || status != "approved" {
		t.Fatalf("a public asset of another organization changed this decision: %s %v", status, single)
	}
}
