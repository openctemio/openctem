package storagequota

import (
	"context"
	"errors"
	"testing"

	cst "github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type orgLimits map[shared.ID]int

func (o orgLimits) Limit(_ context.Context, id shared.ID, k limits.Key) (int, error) {
	if k != limits.StorageMB {
		return 0, errors.New("unexpected key")
	}
	if v, ok := o[id]; ok {
		return v, nil
	}
	return limits.Unlimited, nil
}

// The organization's own limit wins; otherwise the console default, else
// the environment default; 0 means no quota; a change applies at once.
func TestQuotaResolution(t *testing.T) {
	limited, open := shared.NewID(), shared.NewID()
	audit := &cst.Audit{}
	svc := NewService(cst.NewRepo(), orgLimits{limited: 5}, cst.Recorder(audit, &cst.Notifier{}), 20480)
	ctx := context.Background()

	if b, unlimited, err := svc.QuotaBytes(ctx, limited); err != nil || unlimited || b != 5<<20 {
		t.Fatalf("own limit: %d %v %v", b, unlimited, err)
	}
	if b, unlimited, _ := svc.QuotaBytes(ctx, open); unlimited || b != 20480<<20 {
		t.Fatalf("environment default: %d %v", b, unlimited)
	}
	got, _ := svc.Get(ctx)
	if got.Source != SourceEnvironment || got.DefaultMB != 20480 {
		t.Fatalf("got %+v", got)
	}

	if _, err := svc.Update(ctx, cst.SuperAdmin(t), 100, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if b, _, _ := svc.QuotaBytes(ctx, open); b != 100<<20 {
		t.Fatalf("console default must apply at once: %d", b)
	}
	if b, _, _ := svc.QuotaBytes(ctx, limited); b != 5<<20 {
		t.Fatal("the organization's own limit still wins")
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), 0, 1, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, unlimited, _ := svc.QuotaBytes(ctx, open); !unlimited {
		t.Fatal("0 means no quota")
	}
	if len(audit.Entries) != 2 || audit.Entries[0].Action != ActionChanged {
		t.Fatalf("audit = %d", len(audit.Entries))
	}
}

// An organization limit of 0 refuses every upload (it is not "no quota").
func TestZeroOrganizationLimitIsAQuota(t *testing.T) {
	id := shared.NewID()
	svc := NewService(cst.NewRepo(), orgLimits{id: 0}, cst.Recorder(&cst.Audit{}, &cst.Notifier{}), 0)
	if b, unlimited, _ := svc.QuotaBytes(context.Background(), id); unlimited || b != 0 {
		t.Fatalf("got %d %v", b, unlimited)
	}
}

// The default is bounded.
func TestRange(t *testing.T) {
	svc := NewService(cst.NewRepo(), nil, cst.Recorder(&cst.Audit{}, &cst.Notifier{}), 0)
	for _, mb := range []int64{-1, MaxMB + 1} {
		if _, err := svc.Update(context.Background(), cst.SuperAdmin(t), mb, 0, "", ""); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%d: %v", mb, err)
		}
	}
}
