package integration

// Every finding a producer sends is accounted for on its receipt (research
// 436; docs/architecture/ingest-receipts.md, "Outcomes"): received + split =
// created + still detected + reopened + suppressed + failed + skipped + the
// other outcomes. A repeat within a segment and a repeat in another segment
// of the same command are merged, never counted as new.

import (
	"context"
	"encoding/json"
	"testing"
)

func TestReceiptOutcomes_EveryFindingReconciles(t *testing.T) {
	r, _ := newBindingV2Rig(t)
	tn := r.newTenant("semgrep")
	other := r.newTenant("semgrep")
	cmd := r.runCommand(tn, "semgrep", "", "running", 0)

	seg0 := tn.segment("semgrep", true,
		v2Finding{rule: "a", assetRef: "repo"},
		v2Finding{rule: "a", assetRef: "repo"}, // the same finding twice: merged
		v2Finding{rule: "b", assetRef: "repo"},
	)
	seg1 := tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}) // a repeat from another segment
	rep := r.openAs(tn, reportID(60), "worker", &cmd, seg0)
	r.put(tn, rep, 0, seg0)
	r.process(rep, 0)
	r.put(tn, rep, 1, seg1)
	r.process(rep, 1)

	var (
		received, created, still, reopened, suppressed, failed, skipped int
		raw                                                             []byte
	)
	if err := r.db.QueryRowContext(context.Background(), `
		SELECT findings_received, findings_created, findings_updated, findings_reopened, findings_suppressed,
			findings_failed, skipped, outcomes
		FROM ingest_receipts WHERE tenant_id = $1 AND source_ref = $2`, tn.tenant.String(), cmd.String()).
		Scan(&received, &created, &still, &reopened, &suppressed, &failed, &skipped, &raw); err != nil {
		t.Fatalf("receipt: %v", err)
	}
	outcomes := map[string]int{}
	if err := json.Unmarshal(raw, &outcomes); err != nil {
		t.Fatal(err)
	}
	if received != 4 {
		t.Fatalf("received %d, want the 4 findings the sensor sent", received)
	}
	if created != 2 || outcomes["merged"] != 2 {
		t.Fatalf("created %d, outcomes %v", created, outcomes)
	}
	other0 := 0
	for k, v := range outcomes {
		if k != "split" {
			other0 += v
		}
	}
	if received+outcomes["split"] != created+still+reopened+suppressed+failed+skipped+other0 {
		t.Fatalf("receipt does not reconcile: received %d + split %d != created %d + still %d + reopened %d + suppressed %d + failed %d + skipped %d + outcomes %v",
			received, outcomes["split"], created, still, reopened, suppressed, failed, skipped, outcomes)
	}

	// The tool row carries the same outcomes, and another tenant has none.
	var toolRaw []byte
	if err := r.db.QueryRowContext(context.Background(), `SELECT t.outcomes FROM ingest_receipt_tools t
		JOIN ingest_receipts r ON r.id = t.receipt_id WHERE r.tenant_id = $1 AND r.source_ref = $2`,
		tn.tenant.String(), cmd.String()).Scan(&toolRaw); err != nil {
		t.Fatal(err)
	}
	toolOutcomes := map[string]int{}
	_ = json.Unmarshal(toolRaw, &toolOutcomes)
	if toolOutcomes["merged"] != 2 {
		t.Fatalf("tool row outcomes %v", toolOutcomes)
	}
	var n int
	if err := r.db.QueryRowContext(context.Background(), `SELECT count(*) FROM ingest_receipts WHERE tenant_id = $1`,
		other.tenant.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("another tenant got %d receipts (%v)", n, err)
	}
}
