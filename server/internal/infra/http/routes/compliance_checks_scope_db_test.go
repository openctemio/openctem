package routes

// The compliance check reads (docs/architecture/compliance-checks.md,
// "Reads") run in the caller's tenant and data scope: a scoped member sees
// only the posture, controls and assets of their own assets, a member with
// no scope row sees nothing, and nobody sees another tenant's checks.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/compliancecheck"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func ccObs(asset shared.ID, control string, r compliancecheck.Result, fp string) compliancecheck.Observation {
	return compliancecheck.Observation{AssetID: asset, Fingerprint: fp, BenchmarkKey: "cis-example-linux",
		BenchmarkName: "CIS Example Linux", ControlID: control, ControlName: "Ensure " + control, Result: r,
		Evidence: compliancecheck.Evidence{Actual: "password=hunter2-not-real", Expected: "1"}, ToolName: "nessus",
		ObservedAt: time.Now().UTC().Truncate(time.Second)}
}

func TestComplianceChecks_ReadsWithinScope_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	ctx := context.Background()
	repo := postgres.NewComplianceCheckRepository(&postgres.DB{DB: h.db})
	// Asset A fails 1.1 (with its finding) and passes 1.2; asset B fails both.
	h.exec(`UPDATE findings SET finding_type = 'compliance', compliance_result = 'fail', fingerprint = 'cc-fa' WHERE id = $1`, h.findingA.String())
	if _, err := repo.Record(ctx, h.tenant, compliancecheck.SourceIngest, []compliancecheck.Observation{
		ccObs(h.assetA, "1.1", compliancecheck.ResultFail, "cc-fa"),
		ccObs(h.assetA, "1.2", compliancecheck.ResultPass, ""),
		ccObs(h.assetB, "1.1", compliancecheck.ResultFail, ""),
		ccObs(h.assetB, "1.2", compliancecheck.ResultFail, ""),
	}); err != nil {
		t.Fatal(err)
	}
	// Another tenant's benchmark of the same key.
	other, otherAsset := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "cc-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'cc-other.example.com', 'host')`, otherAsset.String(), other.String())
	if _, err := repo.Record(ctx, other, compliancecheck.SourceIngest, []compliancecheck.Observation{
		ccObs(otherAsset, "9.9", compliancecheck.ResultFail, "")}); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecomputePosture(ctx, h.tenant, []shared.ID{h.assetA, h.assetB}); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecomputePosture(ctx, other, []shared.ID{otherAsset}); err != nil {
		t.Fatal(err)
	}

	owner := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}
	free := flCaller{"memberFree", h.memberFree, false}
	get := func(c flCaller, path string, out any) int {
		t.Helper()
		status, _, body := h.listFindingsPath(t, c, path)
		if status == http.StatusOK && out != nil {
			if err := json.Unmarshal([]byte(body), out); err != nil {
				t.Fatalf("%s: %v (%s)", path, err, body)
			}
		}
		return status
	}
	type bench struct {
		Key    string `json:"key"`
		Assets int    `json:"assets"`
		Counts struct {
			Pass, Fail int
		} `json:"counts"`
		PassRate *float64 `json:"pass_rate"`
	}
	var benches struct{ Data []bench }
	if s := get(owner, "/api/v1/findings/compliance/benchmarks", &benches); s != 200 || len(benches.Data) != 1 ||
		benches.Data[0].Assets != 2 || benches.Data[0].Counts.Pass != 1 || benches.Data[0].Counts.Fail != 3 {
		t.Fatalf("owner benchmarks = %d %+v", s, benches)
	}
	if r := benches.Data[0].PassRate; r == nil || *r != 0.25 {
		t.Fatalf("owner pass rate = %v, want 0.25", r)
	}
	benches.Data = nil
	if s := get(memberA, "/api/v1/findings/compliance/benchmarks", &benches); s != 200 || len(benches.Data) != 1 ||
		benches.Data[0].Assets != 1 || benches.Data[0].Counts.Pass != 1 || benches.Data[0].Counts.Fail != 1 {
		t.Fatalf("memberA benchmarks = %d %+v", s, benches)
	}
	benches.Data = nil
	if s := get(memberA, "/api/v1/findings/compliance/benchmarks?asset_id="+h.assetB.String(), &benches); s != 200 || len(benches.Data) != 0 {
		t.Fatalf("memberA reading asset B's posture = %d %+v", s, benches)
	}
	benches.Data = nil
	if s := get(free, "/api/v1/findings/compliance/benchmarks", &benches); s != 200 || len(benches.Data) != 0 {
		t.Fatalf("member without scope = %d %+v", s, benches)
	}

	type control struct {
		ControlID string `json:"control_id"`
		Counts    struct{ Pass, Fail int }
	}
	var controls struct {
		Data  []control
		Total int
	}
	if s := get(owner, "/api/v1/findings/compliance/benchmarks/cis-example-linux/controls", &controls); s != 200 || controls.Total != 2 ||
		controls.Data[0].ControlID != "1.1" || controls.Data[0].Counts.Fail != 2 {
		t.Fatalf("owner controls = %d %+v", s, controls)
	}
	controls.Data = nil
	if s := get(memberA, "/api/v1/findings/compliance/benchmarks/cis-example-linux/controls?result=fail", &controls); s != 200 ||
		controls.Total != 1 || controls.Data[0].ControlID != "1.1" || controls.Data[0].Counts.Fail != 1 {
		t.Fatalf("memberA failing controls = %d %+v", s, controls)
	}
	// Another tenant's control never shows.
	controls.Data = nil
	if s := get(owner, "/api/v1/findings/compliance/benchmarks/cis-example-linux/controls?q=9.9", &controls); s != 200 || controls.Total != 0 {
		t.Fatalf("another tenant's control = %d %+v", s, controls)
	}

	type casset struct {
		AssetID  string `json:"asset_id"`
		Result   string `json:"result"`
		Evidence struct {
			Actual string `json:"actual"`
		} `json:"evidence"`
		FindingID string `json:"finding_id"`
	}
	var assets struct {
		Data  []casset
		Total int
	}
	if s := get(owner, "/api/v1/findings/compliance/benchmarks/cis-example-linux/assets?control=1.1", &assets); s != 200 || assets.Total != 2 {
		t.Fatalf("owner control assets = %d %+v", s, assets)
	}
	for _, a := range assets.Data {
		if a.Evidence.Actual == "password=hunter2-not-real" {
			t.Fatalf("evidence not redacted: %+v", a)
		}
	}
	assets.Data = nil
	if s := get(memberA, "/api/v1/findings/compliance/benchmarks/cis-example-linux/assets?control=1.1", &assets); s != 200 ||
		assets.Total != 1 || assets.Data[0].AssetID != h.assetA.String() || assets.Data[0].FindingID != h.findingA.String() {
		t.Fatalf("memberA control assets = %d %+v", s, assets)
	}
	if s := get(owner, "/api/v1/findings/compliance/benchmarks/Bad%20Key/controls", nil); s != 400 {
		t.Fatalf("malformed benchmark key = %d, want 400", s)
	}
	if s := get(owner, "/api/v1/findings/compliance/benchmarks/cis-example-linux/assets", nil); s != 400 {
		t.Fatalf("missing control = %d, want 400", s)
	}
	if s := get(owner, "/api/v1/findings/compliance/benchmarks/cis-example-linux/controls?result=bogus", nil); s != 400 {
		t.Fatalf("unknown result = %d, want 400", s)
	}

	// A finding's control history: the owner and memberA (asset A) read it;
	// memberA gets 404 for asset B's finding; a member without scope 404.
	var hist struct {
		Control *struct {
			ControlID string `json:"control_id"`
			Result    string `json:"result"`
		} `json:"control"`
		Data []struct {
			Result string `json:"result"`
		} `json:"data"`
	}
	if s := get(memberA, "/api/v1/findings/"+h.findingA.String()+"/compliance-history", &hist); s != 200 || hist.Control == nil ||
		hist.Control.ControlID != "1.1" || len(hist.Data) != 1 || hist.Data[0].Result != "fail" {
		t.Fatalf("memberA history = %d %+v", s, hist)
	}
	if s := get(memberA, "/api/v1/findings/"+h.findingB.String()+"/compliance-history", nil); s != 404 {
		t.Fatalf("memberA history of asset B's finding = %d, want 404", s)
	}
	if s := get(free, "/api/v1/findings/"+h.findingA.String()+"/compliance-history", nil); s != 404 {
		t.Fatalf("member without scope = %d, want 404", s)
	}
	hist.Control, hist.Data = nil, nil
	if s := get(owner, "/api/v1/findings/"+h.findingB.String()+"/compliance-history", &hist); s != 200 || hist.Control != nil || len(hist.Data) != 0 {
		t.Fatalf("finding without a check state = %d %+v", s, hist)
	}
}
