package threatsource

import (
	"context"
	"errors"
	"testing"

	cst "github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
)

// Nothing stored: the direct fetch is the supplier and is allowed, as before
// the release carried KEV and EPSS.
func TestDefaults(t *testing.T) {
	svc := NewService(cst.NewRepo(), cst.Recorder(&cst.Audit{}, &cst.Notifier{}))
	p, err := svc.Policy(context.Background())
	if err != nil || p.PreferBundle || !p.DirectAllowed {
		t.Fatalf("%+v %v", p, err)
	}
	g, _ := svc.Get(context.Background())
	if g.Stored || g.Source != SourceDirect || g.DirectFetch != FetchAuto {
		t.Fatalf("%+v", g)
	}
}

func TestUpdateAppliesAuditsAndGuardsVersion(t *testing.T) {
	audit := &cst.Audit{}
	svc := NewService(cst.NewRepo(), cst.Recorder(audit, &cst.Notifier{}))
	ctx := context.Background()
	actor := cst.SuperAdmin(t)

	g, err := svc.Update(ctx, actor, SourceBundle, FetchOff, 0, "", "")
	if err != nil || g.Version != 1 || !g.Stored {
		t.Fatalf("%+v %v", g, err)
	}
	p, _ := svc.Policy(ctx)
	if !p.PreferBundle || p.DirectAllowed {
		t.Fatalf("%+v", p)
	}
	if len(audit.Entries) != 1 {
		t.Fatalf("audit rows %d", len(audit.Entries))
	}
	// A stale form is refused, never merged.
	if _, err := svc.Update(ctx, actor, SourceDirect, FetchAuto, 0, "", ""); !errors.Is(err, platformsetting.ErrVersionConflict) {
		t.Fatalf("want a version conflict, got %v", err)
	}
	if _, err := svc.Update(ctx, actor, SourceDirect, FetchAuto, 1, "", ""); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRefusesInvalidValuesAndNoActor(t *testing.T) {
	svc := NewService(cst.NewRepo(), cst.Recorder(&cst.Audit{}, &cst.Notifier{}))
	ctx := context.Background()
	for _, c := range [][2]string{{"both", FetchAuto}, {SourceDirect, "maybe"}, {"", ""}} {
		if _, err := svc.Update(ctx, cst.SuperAdmin(t), c[0], c[1], 0, "", ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%v: %v", c, err)
		}
	}
	if _, err := svc.Update(ctx, nil, SourceDirect, FetchAuto, 0, "", ""); !errors.Is(err, ErrNoActor) {
		t.Fatal(err)
	}
}
