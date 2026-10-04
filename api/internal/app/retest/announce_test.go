package retest

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type oneFinding struct{ f *vulnerability.Finding }

func (o oneFinding) GetByID(context.Context, shared.ID, shared.ID) (*vulnerability.Finding, error) {
	return o.f, nil
}

type commentCapture struct{ bodies []string }

func (c *commentCapture) CommentOnFinding(_ context.Context, _, _ shared.ID, body string) error {
	c.bodies = append(c.bodies, body)
	return nil
}

type outboxCapture struct{ params []outbox.EnqueueParams }

func (o *outboxCapture) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	o.params = append(o.params, p)
	return nil
}

func newFinding(t *testing.T) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceDAST, "nuclei",
		vulnerability.SeverityHigh, "Exposed admin panel")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestChangeAnnouncer_FixAndRegressionReachTicketAndNotifications(t *testing.T) {
	f := newFinding(t)
	tickets, notes := &commentCapture{}, &outboxCapture{}
	a := NewChangeAnnouncer(oneFinding{f}, tickets, notes, logger.NewNop())

	a.Announce(context.Background(), Change{TenantID: f.TenantID(), FindingID: f.ID(), Kind: ChangeFixed, Source: "retest", Detail: "template did not match"})
	a.Announce(context.Background(), Change{TenantID: f.TenantID(), FindingID: f.ID(), Kind: ChangeRegression, Source: "scan", Detail: strings.Repeat("x", 1000)})
	a.Announce(context.Background(), Change{TenantID: f.TenantID(), FindingID: f.ID(), Kind: ChangeFixRejected, Source: "retest"})

	if len(tickets.bodies) != 3 || !strings.HasPrefix(tickets.bodies[0], "Fixed:") || !strings.HasPrefix(tickets.bodies[1], "Regression:") {
		t.Fatalf("ticket comments = %q", tickets.bodies)
	}
	want := []string{"finding_fixed", "finding_reopened", "finding_reopened"}
	for i, p := range notes.params {
		if p.EventType != want[i] || p.AggregateType != "finding" || p.TenantID != f.TenantID() {
			t.Errorf("notification %d = %+v", i, p)
		}
	}
	if len(notes.params) != 3 {
		t.Fatalf("notifications = %d", len(notes.params))
	}
	// Free text is bounded: a long sensor reason never floods a ticket.
	if len(notes.params[1].Body) > maxDetail+4 {
		t.Errorf("detail not truncated: %d bytes", len(notes.params[1].Body))
	}
}

type countingAnnouncer struct {
	mu sync.Mutex
	n  int
}

func (c *countingAnnouncer) Announce(context.Context, Change) { c.mu.Lock(); c.n++; c.mu.Unlock() }

type countingSLA struct{ ids int }

func (c *countingSLA) RestartForRegression(_ context.Context, _ shared.ID, ids []shared.ID, _ string) (int, error) {
	c.ids += len(ids)
	return len(ids), nil
}

// A scan that reopens hundreds of findings pages no one hundreds of times: the
// SLA restart covers all of them, announcements stop at the cap.
func TestScanRegressions_CapsAnnouncementsNotSLA(t *testing.T) {
	ann, sla := &countingAnnouncer{}, &countingSLA{}
	reopened := make([]vulnerability.ReopenedFinding, 0, 120)
	for i := 0; i < 120; i++ {
		reopened = append(reopened, vulnerability.ReopenedFinding{ID: shared.NewID(), PreviousStatus: vulnerability.FindingStatusResolved})
	}
	NewScanRegressions(sla, ann, logger.NewNop()).HandleRegressions(context.Background(), shared.NewID(), reopened, "nuclei")
	if sla.ids != 120 {
		t.Errorf("SLA restarted for %d, want 120", sla.ids)
	}
	if ann.n != maxAnnouncedPerScan {
		t.Errorf("announced %d, want the cap %d", ann.n, maxAnnouncedPerScan)
	}
}

func TestCleanDetail_FlattensAndBounds(t *testing.T) {
	got := cleanDetail("line one\n\x1b[31mred\x1b[0m\r\nline\ttwo  ")
	if strings.ContainsAny(got, "\n\r\t\x1b") || got != "line one [31mred [0m line two" {
		t.Fatalf("cleanDetail = %q", got)
	}
	if n := len([]rune(cleanDetail(strings.Repeat("é", 1000)))); n != maxDetail+1 {
		t.Fatalf("length = %d, want %d (cap + ellipsis)", n, maxDetail+1)
	}
}
