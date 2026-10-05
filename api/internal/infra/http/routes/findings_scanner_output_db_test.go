package routes

// Scanner output (research 24 P0-2, owner decision C9) over the real routes
// and a migrated database: stored byte for byte by fingerprint within the
// tenant, shown only on the finding detail, never in the list or the export,
// hidden from a member whose scope does not cover the finding, and cleared
// 365 days after the finding was closed.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

const soHostile = "Server: <script>alert('so')</script>\x1b[31mSO-MARKER\x1b[0m \u202etxt.exe\r\nline2"

type soDetail struct {
	CVSSv2Vector  string `json:"cvss_v2_vector"`
	CVSSv3Vector  string `json:"cvss_v3_vector"`
	ScannerOutput *struct {
		Text      string     `json:"text"`
		UpdatedAt *time.Time `json:"updated_at"`
		Truncated bool       `json:"truncated"`
	} `json:"scanner_output"`
}

func TestFindingScannerOutput_StoredAndShownOnlyOnTheDetail(t *testing.T) {
	h := newGroupScopeHarness(t)
	ctx := context.Background()
	repo := postgres.NewFindingRepository(&postgres.DB{DB: h.db})

	// Another tenant has a finding with the same fingerprint as FA (the seed
	// uses the id as fingerprint): the update must not reach it.
	other, otherAsset, otherFinding := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "so-"+other.String())
	t.Cleanup(func() { _, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, other.String()) })
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'so-other', 'domain')`, otherAsset.String(), other.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sast', 'so', 'other tenant', 'high', $4, 'new')`,
		otherFinding.String(), other.String(), otherAsset.String(), h.findingA.String())

	v2 := "AV:N/AC:L/Au:N/C:P/I:P/A:P"
	v3 := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	n, err := repo.UpdateScannerEvidenceBatch(ctx, h.tenant, []vulnerability.ScannerEvidenceUpdate{
		{Fingerprint: h.findingA.String(), Output: soHostile + "\x00", CVSSv2Vector: v2, CVSSv3Vector: v3},
		{Fingerprint: h.findingB.String(), Output: "SO-B-OUTPUT"},
		{Fingerprint: "no-such-fingerprint", Output: "x"},
	})
	if err != nil || n != 2 {
		t.Fatalf("update = %d, %v; want 2 rows", n, err)
	}
	var otherOut *string
	if err := h.db.QueryRowContext(ctx, `SELECT scanner_output FROM findings WHERE id = $1`, otherFinding.String()).Scan(&otherOut); err != nil || otherOut != nil {
		t.Fatalf("another tenant's finding with the same fingerprint was written: %v %v", otherOut, err)
	}

	// The detail shows the output byte for byte (NUL dropped) and both vectors.
	status, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/findings/"+h.findingA.String(), nil)
	if status != http.StatusOK {
		t.Fatalf("detail = %d %.200s", status, body)
	}
	var d soDetail
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatal(err)
	}
	if d.ScannerOutput == nil || d.ScannerOutput.Text != soHostile || d.ScannerOutput.UpdatedAt == nil || d.ScannerOutput.Truncated {
		t.Fatalf("scanner_output = %+v, want the stored text byte for byte", d.ScannerOutput)
	}
	if d.CVSSv2Vector != v2 || d.CVSSv3Vector != v3 {
		t.Fatalf("vectors = %q %q", d.CVSSv2Vector, d.CVSSv3Vector)
	}

	// A re-sighting without output keeps the stored one.
	if _, err := repo.UpdateScannerEvidenceBatch(ctx, h.tenant, []vulnerability.ScannerEvidenceUpdate{
		{Fingerprint: h.findingA.String(), CVSSv3Vector: v3},
	}); err != nil {
		t.Fatal(err)
	}
	if ev, err := repo.GetScannerEvidence(ctx, h.tenant, h.findingA); err != nil || ev.Output != soHostile {
		t.Fatalf("output after an empty re-sighting = %+v, %v", ev, err)
	}

	// Out of scope: memberA cannot read FB's detail, and so not its output.
	if status, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/findings/"+h.findingB.String(), nil); status != http.StatusNotFound || strings.Contains(body, "SO-B-OUTPUT") {
		t.Errorf("memberA detail of out-of-scope FB = %d, leaks output: %v", status, strings.Contains(body, "SO-B-OUTPUT"))
	}
	if status, body := h.do(h.owner, true, http.MethodGet, "/api/v1/findings/"+h.findingB.String(), nil); status != http.StatusOK || !strings.Contains(body, "SO-B-OUTPUT") {
		t.Errorf("owner detail of FB = %d, output missing", status)
	}

	// Never in the list or the export.
	admin := flCaller{"owner", h.owner, true}
	if _, _, list := h.listIDs(t, admin, ""); strings.Contains(list, "SO-MARKER") || strings.Contains(list, "SO-B-OUTPUT") || strings.Contains(list, "scanner_output") {
		t.Error("the findings list carries scanner output")
	}
	exportPerms := strings.Join(append(append([]string{}, dsMemberPerms...), permission.FindingsExport.String()), ",")
	for _, format := range []string{"", "format=ndjson"} {
		resp, exp := h.export(t, admin, http.MethodGet, format, nil, exportPerms)
		if resp.StatusCode != http.StatusOK || strings.Contains(exp, "SO-MARKER") || strings.Contains(exp, "SO-B-OUTPUT") {
			t.Errorf("export %q = %d, carries scanner output: %v", format, resp.StatusCode, strings.Contains(exp, "SO-MARKER"))
		}
	}
}

func TestFindingScannerOutput_RetentionClearsOnlyLongClosed(t *testing.T) {
	h := newGroupScopeHarness(t)
	ctx := context.Background()
	repo := postgres.NewFindingRepository(&postgres.DB{DB: h.db})
	// FA: closed 400 days ago. FB: closed 30 days ago. FB2: open, old.
	h.exec(`UPDATE findings SET status = 'resolved', resolved_at = now() - interval '400 days', scanner_output = 'old' WHERE id = $1`, h.findingA.String())
	h.exec(`UPDATE findings SET status = 'false_positive', resolved_at = now() - interval '30 days', scanner_output = 'recent' WHERE id = $1`, h.findingB.String())
	h.exec(`UPDATE findings SET status = 'confirmed', resolved_at = now() - interval '500 days', scanner_output = 'open' WHERE id = $1`, h.findingB2.String())

	c := controller.NewScannerOutputRetentionController(repo, &controller.ScannerOutputRetentionConfig{BatchSize: 1, MaxBatches: 1000})
	if _, err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[shared.ID]string{h.findingA: "", h.findingB: "recent", h.findingB2: "open"} {
		var out *string
		if err := h.db.QueryRowContext(ctx, `SELECT scanner_output FROM findings WHERE id = $1`, id.String()).Scan(&out); err != nil {
			t.Fatal(err)
		}
		got := ""
		if out != nil {
			got = *out
		}
		if got != want {
			t.Errorf("finding %s output = %q, want %q", id, got, want)
		}
	}
	// The finding itself is kept.
	var n int
	_ = h.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE id = $1`, h.findingA.String()).Scan(&n)
	if n != 1 {
		t.Error("retention deleted the finding")
	}
}
