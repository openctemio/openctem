package routes

// "How we found this" over the real routes, services and a migrated
// database (docs/architecture/exploration.md): read exactly as the subject,
// never across the tenant, and a step outside the caller's data scope or
// permissions is hidden and counted, never named.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

type storyBody struct {
	Subject struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"subject"`
	Steps []struct {
		Kind   string `json:"kind"`
		Hidden bool   `json:"hidden"`
		Asset  *struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Via  string `json:"via"`
		} `json:"asset"`
		Scan *struct {
			RunID    string `json:"run_id"`
			ScanName string `json:"scan_name"`
			StepName string `json:"step_name"`
		} `json:"scan"`
		Report *struct {
			Channel string `json:"channel"`
			Tool    string `json:"tool"`
		} `json:"report"`
		Finding *struct {
			ID string `json:"id"`
		} `json:"finding"`
	} `json:"steps"`
	Hidden int `json:"hidden"`
}

const storyScanMarker = "story-SECRET-scan"

// seedStorySighting records that findingA was reported by a scan run (with a
// named scan and step).
func (h *dsHarness) seedStorySighting() {
	h.t.Helper()
	t := h.tenant.String()
	scan, run, step := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name) VALUES ($1, $2, $3, 'single', 'nuclei')`,
		scan.String(), t, storyScanMarker)
	h.exec(`INSERT INTO scan_runs (id, tenant_id, scan_id, trigger_type, status, kind) VALUES ($1, $2, $3, 'manual', 'completed', 'system')`,
		run.String(), t, scan.String())
	h.exec(`INSERT INTO scan_run_steps (id, scan_run_id, step_key, step_order, status, step_name) VALUES ($1, $2, 's', 1, 'completed', 'Probe web')`,
		step.String(), run.String())
	h.exec(`INSERT INTO finding_sightings (tenant_id, finding_id, channel, tool, scan_id, first_seen_at, last_seen_at, last_run_id, last_step_run_id)
		VALUES ($1, $2, 'scan', 'nuclei', $3, now(), now(), $4, $5)`, t, h.findingA.String(), scan.String(), run.String(), step.String())
}

func (h *dsHarness) story(user shared.ID, admin bool, perms, path string) (int, string, storyBody) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+path, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("X-Test-User", user.String())
	if admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	if perms != "" {
		req.Header.Set("X-Test-Perms", perms)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var raw strings.Builder
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		raw.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	var b storyBody
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(raw.String()), &b); err != nil {
			h.t.Fatalf("story body: %v: %.300s", err, raw.String())
		}
	}
	return resp.StatusCode, raw.String(), b
}

func storyKinds(b storyBody) string {
	out := make([]string, 0, len(b.Steps))
	for _, s := range b.Steps {
		k := s.Kind
		if s.Hidden {
			k += "(hidden)"
		}
		out = append(out, k)
	}
	return strings.Join(out, " > ")
}

func TestFindingStory_ChainAndRedaction_DB(t *testing.T) {
	h := newDSHarness(t)
	f := h.seedLineage()
	h.seedStorySighting()
	path := "/api/v1/findings/" + h.findingA.String() + "/story"

	// The owner sees the whole chain: root, mid, the asset, the run, the
	// report and the finding.
	code, body, got := h.story(h.owner, true, "", path)
	if code != http.StatusOK {
		t.Fatalf("owner: %d %s", code, body)
	}
	if k := storyKinds(got); k != "asset > asset > asset > scan > report > finding" || got.Hidden != 0 {
		t.Fatalf("owner chain: %s (hidden %d)", k, got.Hidden)
	}
	if got.Steps[1].Asset.ID != f.mid.String() || got.Steps[3].Scan.ScanName != storyScanMarker ||
		got.Steps[3].Scan.StepName != "Probe web" || got.Steps[5].Finding.ID != h.findingA.String() {
		t.Fatalf("owner steps: %s", body)
	}

	// memberA sees assetA and root, not mid: mid is hidden and counted.
	code, body, got = h.story(h.memberA, false, "", path)
	if code != http.StatusOK {
		t.Fatalf("member: %d %s", code, body)
	}
	if k := storyKinds(got); k != "asset > asset(hidden) > asset > scan > report > finding" || got.Hidden != 1 {
		t.Fatalf("member chain: %s (hidden %d)", k, got.Hidden)
	}
	if strings.Contains(body, linMidMarker) || strings.Contains(body, f.mid.String()) || strings.Contains(body, "dnsx") {
		t.Fatalf("member learned an out-of-scope ancestor: %s", body)
	}

	// Without scans:read the run is a hidden step: no scan name, no step.
	perms := permission.FindingsRead.String() + "," + permission.AssetsRead.String()
	code, body, got = h.story(h.memberA, false, perms, path)
	if code != http.StatusOK {
		t.Fatalf("member without scans:read: %d %s", code, body)
	}
	if k := storyKinds(got); k != "asset > asset(hidden) > asset > scan(hidden) > report > finding" || got.Hidden != 2 {
		t.Fatalf("no scans:read chain: %s (hidden %d)", k, got.Hidden)
	}
	if strings.Contains(body, storyScanMarker) || strings.Contains(body, "Probe web") {
		t.Fatalf("run read without scans:read: %s", body)
	}

	// The gate is the finding's: without findings:read, refused.
	if code, body, _ := h.story(h.memberA, false, permission.AssetsRead.String(), path); code != http.StatusForbidden {
		t.Fatalf("without findings:read: %d %s", code, body)
	}
}

func TestFindingStory_ScopeAndTenantRefusals_DB(t *testing.T) {
	h := newDSHarness(t)
	h.seedLineage()

	// findingB is on assetB, outside memberA's scope: not found.
	pathB := "/api/v1/findings/" + h.findingB.String() + "/story"
	if code, body, _ := h.story(h.memberA, false, "", pathB); code != http.StatusNotFound {
		t.Fatalf("out-of-scope finding: %d %s", code, body)
	}
	// A member with no scope row sees nothing.
	if code, body, _ := h.story(h.memberFree, false, "", "/api/v1/findings/"+h.findingA.String()+"/story"); code != http.StatusNotFound {
		t.Fatalf("member with no scope: %d %s", code, body)
	}

	// Assigned to memberA, findingB is readable, but its asset is not: one
	// hidden step, never its name or id.
	h.exec(`UPDATE findings SET assigned_to = $1 WHERE tenant_id = $2 AND id = $3`,
		h.memberA.String(), h.tenant.String(), h.findingB.String())
	code, body, got := h.story(h.memberA, false, "", pathB)
	if code != http.StatusOK {
		t.Fatalf("assigned finding: %d %s", code, body)
	}
	if k := storyKinds(got); k != "asset(hidden) > finding" || got.Hidden != 1 {
		t.Fatalf("assigned finding chain: %s", k)
	}
	if strings.Contains(body, dsMarkerAssetB) || strings.Contains(body, h.assetB.String()) {
		t.Fatalf("assignee learned the out-of-scope asset: %s", body)
	}

	// Another tenant's finding and asset are not found, even for an owner.
	other, foreignAsset, foreignFinding := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "storyx-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'storyX-FOREIGN.example.com', 'domain', 'public', 'high')`,
		foreignAsset.String(), other.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 't', 'storyX-FOREIGN', 'high', $1::text, 'confirmed')`,
		foreignFinding.String(), other.String(), foreignAsset.String())
	for _, p := range []string{"/api/v1/findings/" + foreignFinding.String() + "/story", "/api/v1/assets/" + foreignAsset.String() + "/story"} {
		if code, body, _ := h.story(h.owner, true, "", p); code != http.StatusNotFound || strings.Contains(body, "storyX-FOREIGN") {
			t.Fatalf("foreign %s: %d %s", p, code, body)
		}
	}
}

func TestAssetStory_ChainAndRefusals_DB(t *testing.T) {
	h := newDSHarness(t)
	f := h.seedLineage()

	code, body, got := h.story(h.memberA, false, "", "/api/v1/assets/"+h.assetA.String()+"/story")
	if code != http.StatusOK {
		t.Fatalf("member: %d %s", code, body)
	}
	if k := storyKinds(got); k != "asset > asset(hidden) > asset" || got.Hidden != 1 || got.Subject.Kind != "asset" {
		t.Fatalf("member chain: %s", k)
	}
	if strings.Contains(body, linMidMarker) || strings.Contains(body, f.mid.String()) {
		t.Fatalf("member learned an out-of-scope ancestor: %s", body)
	}
	if code, body, _ := h.story(h.memberA, false, "", "/api/v1/assets/"+h.assetB.String()+"/story"); code != http.StatusNotFound {
		t.Fatalf("out-of-scope asset: %d %s", code, body)
	}
	if code, body, _ := h.story(h.memberA, false, permission.FindingsRead.String(), "/api/v1/assets/"+h.assetA.String()+"/story"); code != http.StatusForbidden {
		t.Fatalf("without assets:read: %d %s", code, body)
	}
}
