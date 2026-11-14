package finding

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

type heldSet map[shared.ID]bool

func (h heldSet) IsHeld(_ context.Context, _ shared.ID, id shared.ID) (bool, error) {
	return h[id], nil
}

// A held finding announces no escalation; the same escalation of a finding
// that is not held does.
func TestOutboxPublisher_HeldFindingNotAnnounced(t *testing.T) {
	p, q := newOutboxPub()
	held, open := shared.NewID(), shared.NewID()
	p.SetHeldReader(heldSet{held: true})
	for _, id := range []shared.ID{held, open} {
		if err := p.Publish(context.Background(), PriorityChangeEvent{
			TenantID: shared.NewID(), FindingID: id,
			PreviousClass: classPtr(vulnerability.PriorityP3), NewClass: vulnerability.PriorityP0,
			Source: "sweep", At: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(q.calls) != 1 || q.calls[0].AggregateID == nil || q.calls[0].AggregateID.String() != open.String() {
		t.Fatalf("enqueued %+v, want only the finding that is not held", q.calls)
	}
}
