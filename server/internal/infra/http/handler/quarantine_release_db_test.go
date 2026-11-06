package handler

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// The queries behind the automatic release of out-of-contract holds are
// scoped by tenant and sensor, list only pending out_of_contract items, and a
// release by the platform leaves reviewed_by empty.
func TestQuarantineRelease_QueriesAreScopedAndSystemReviewHasNoReviewer(t *testing.T) {
	r := newBindingRig(t, "")
	ctx := context.Background()
	hold := func(sensorName string, reason sensorresult.Reason) *sensorresult.Item {
		it := &sensorresult.Item{TenantID: r.tenant, SensorID: r.ids[sensorName], SensorType: "worker",
			Protocol: sensorresult.ProtocolV2, Route: "ctis", ReportID: shared.NewID().String(), ToolName: "nuclei",
			Reason: reason, Payload: []byte(`{}`), AssetsCount: 1}
		if err := r.results.Create(ctx, it, sensorresult.DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		return it
	}
	mine := hold("worker", sensorresult.ReasonOutOfContract)
	hold("worker", sensorresult.ReasonNoCommand)
	other := hold("other-worker", sensorresult.ReasonOutOfContract)
	notBefore := time.Now().Add(-time.Hour)

	sensorID := r.ids["worker"]
	groups, err := r.results.PendingOutOfContractGroups(ctx, notBefore, &r.tenant, &sensorID, 100)
	if err != nil || len(groups) != 1 || groups[0].SensorID != sensorID || groups[0].TenantID != r.tenant {
		t.Fatalf("groups = %+v, %v", groups, err)
	}
	// Another tenant sees nothing of this tenant's items.
	foreign := shared.NewID()
	if g, err := r.results.PendingOutOfContractGroups(ctx, notBefore, &foreign, nil, 100); err != nil || len(g) != 0 {
		t.Fatalf("foreign tenant groups = %+v, %v", g, err)
	}
	refs, err := r.results.PendingInGroup(ctx, groups[0], notBefore, time.Time{}, shared.ID{}, 10)
	if err != nil || len(refs) != 1 || refs[0].ID != mine.ID {
		t.Fatalf("refs = %+v, %v (other %v)", refs, err, other.ID)
	}
	if refs, _ := r.results.PendingInGroup(ctx, groups[0], notBefore, refs[0].CreatedAt, refs[0].ID, 10); len(refs) != 0 {
		t.Fatalf("the cursor did not advance: %+v", refs)
	}

	if err := r.results.Review(ctx, r.tenant, mine.ID, sensorresult.StatusAccepted, nil); err != nil {
		t.Fatal(err)
	}
	var by sql.NullString
	var status string
	if err := r.db.QueryRowContext(ctx, `SELECT status, reviewed_by FROM sensor_result_quarantine WHERE id = $1`, mine.ID.String()).Scan(&status, &by); err != nil {
		t.Fatal(err)
	}
	if status != "accepted" || by.Valid {
		t.Fatalf("status %q reviewed_by %v", status, by)
	}
	if g, _ := r.results.PendingOutOfContractGroups(ctx, notBefore, &r.tenant, &sensorID, 100); len(g) != 0 {
		t.Fatalf("an accepted item still lists: %+v", g)
	}
}
