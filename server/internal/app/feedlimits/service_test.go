package feedlimits

import (
	"context"
	"errors"
	"testing"
	"time"

	cst "github.com/openctemio/openctem/server/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/server/internal/app/feedstatus"
	"github.com/openctemio/openctem/server/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Without a stored value the defaults apply: 12 hours for the bundle and
// KEV, 36 for EPSS.
func TestDefaults(t *testing.T) {
	svc := NewService(cst.NewRepo(), nil, logger.NewNop())
	got, err := svc.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != SourceDefault || got.BundleHours != 12 || got.EPSSHours != 36 {
		t.Fatalf("got %+v", got)
	}
	l := svc.Limits(context.Background())
	if l.StaleAfter(feedstatus.SourceKEV) != 12*time.Hour || l.StaleAfter(feedstatus.SourceEPSS) != 36*time.Hour {
		t.Fatalf("limits %+v", l)
	}
}

// An offline site raises the limit: it applies at once to the bundle, KEV
// (never lower than the bundle) and EPSS (a day more); the change is
// audited and every administrator is told.
func TestUpdateRaisesEveryLimit(t *testing.T) {
	audit, n := &cst.Audit{}, &cst.Notifier{}
	svc := NewService(cst.NewRepo(), cst.Recorder(audit, n), logger.NewNop())
	ctx := context.Background()
	got, err := svc.Update(ctx, cst.SuperAdmin(t), 48, 0, "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != SourceConsole || got.BundleHours != 48 || got.EPSSHours != 72 || got.Version != 1 {
		t.Fatalf("got %+v", got)
	}
	l := svc.Limits(ctx)
	if l.StaleAfter(feedstatus.SourceVulnfeed) != 48*time.Hour || l.StaleAfter(feedstatus.SourceKEV) != 48*time.Hour ||
		l.StaleAfter(feedstatus.SourceEPSS) != 72*time.Hour {
		t.Fatalf("limits %+v", l)
	}
	if len(audit.Entries) != 1 || audit.Entries[0].Action != ActionChanged {
		t.Fatalf("audit %d", len(audit.Entries))
	}
	if n.Count() != 1 {
		t.Fatalf("administrators not told: %v", n.Subjects)
	}
	// A stale version is a conflict, not a silent overwrite.
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), 24, 0, "", ""); !errors.Is(err, platformsetting.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
}

// The limit stays within its bounds: under 6 hours the banner would come
// and go between releases, above 7 days a release is refused anyway.
func TestUpdateBounds(t *testing.T) {
	svc := NewService(cst.NewRepo(), nil, logger.NewNop())
	for _, h := range []int{0, 5, 169, -1} {
		if _, err := svc.Update(context.Background(), cst.SuperAdmin(t), h, 0, "", ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%d hours: %v", h, err)
		}
	}
	for _, h := range []int{6, 168} {
		svc := NewService(cst.NewRepo(), nil, logger.NewNop())
		if _, err := svc.Update(context.Background(), cst.SuperAdmin(t), h, 0, "", ""); err != nil {
			t.Errorf("%d hours refused: %v", h, err)
		}
	}
	if _, err := svc.Update(context.Background(), nil, 24, 0, "", ""); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
}
