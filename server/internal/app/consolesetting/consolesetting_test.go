package consolesetting_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	cst "github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
)

func TestCheckReason(t *testing.T) {
	if r, err := consolesetting.CheckReason("  rotate the key  "); err != nil || r != "rotate the key" {
		t.Fatalf("%q %v", r, err)
	}
	for _, bad := range []string{"", "   ", "line\nbreak", strings.Repeat("x", consolesetting.MaxReasonRunes+1)} {
		if _, err := consolesetting.CheckReason(bad); !errors.Is(err, consolesetting.ErrReasonRequired) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

type value struct {
	N int `json:"n"`
}

// Writes are compare-and-swap: a stale version is refused.
func TestStoreCompareAndSwap(t *testing.T) {
	s := consolesetting.NewStore[value](cst.NewRepo(), "k")
	ctx := context.Background()
	if _, m, err := s.Get(ctx); err != nil || m.Stored {
		t.Fatalf("empty: %+v %v", m, err)
	}
	by := cst.SuperAdmin(t).ID()
	if _, err := s.Put(ctx, value{1}, 0, by); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, value{2}, 0, by); !errors.Is(err, platformsetting.ErrVersionConflict) {
		t.Fatalf("second create: %v", err)
	}
	if m, err := s.Put(ctx, value{3}, 1, by); err != nil || m.Version != 2 {
		t.Fatalf("update: %+v %v", m, err)
	}
	v, m, _ := s.Fresh(ctx)
	if v.N != 3 || m.UpdatedBy == nil || *m.UpdatedBy != by {
		t.Fatalf("got %+v %+v", v, m)
	}
}

// The notice escapes what the administrator typed.
func TestRecorderEscapesNotice(t *testing.T) {
	audit, n := &cst.Audit{}, &cst.Notifier{}
	r := cst.Recorder(audit, n)
	r.Record(context.Background(), cst.SuperAdmin(t), consolesetting.Change{
		Action: "platform.x_changed", Key: "x", Title: "X", Reason: "<script>alert(1)</script>", Critical: true, Notify: true,
	}, "203.0.113.5", "ua")
	if strings.Contains(n.All(), "<script>") || len(audit.Entries) != 1 {
		t.Fatalf("notice = %s", n.All())
	}
}
