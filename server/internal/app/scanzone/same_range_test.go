package scanzone

import (
	"context"
	"testing"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	zonedom "github.com/openctemio/openctem/server/pkg/domain/scanzone"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// listRepo lists the zones of the asked tenant only, as the SQL does.
type listRepo struct{ *memRepo }

func (l listRepo) List(_ context.Context, tenantID shared.ID) ([]*zonedom.Zone, error) {
	var out []*zonedom.Zone
	for _, z := range l.zones {
		if z.TenantID == tenantID {
			out = append(out, z)
		}
	}
	return out, nil
}

// Saving a zone that holds another zone's range exactly names that zone
// (the overlap warning, research 466 D9); another tenant's zone never.
func TestService_SameRangeZones(t *testing.T) {
	repo := listRepo{&memRepo{zones: map[shared.ID]*zonedom.Zone{}}}
	svc := NewService(repo, nil, logger.NewNop())
	ctx := context.Background()
	tenant, other := shared.NewID(), shared.NewID()
	create := func(tid shared.ID, name string, ranges ...string) *zonedom.Zone {
		t.Helper()
		z, err := svc.CreateZone(ctx, CreateInput{TenantID: tid.String(), Name: name, Ranges: ranges}, auditapp.AuditContext{TenantID: tid.String()})
		if err != nil {
			t.Fatal(err)
		}
		return z
	}
	office := create(tenant, "office", "10.0.0.0/16")
	create(other, "theirs", "10.0.0.0/16")
	create(tenant, "corp", "10.0.0.0/8")
	cloud := create(tenant, "cloud", "10.0.0.0/16", "192.168.5.0/24")

	same, err := svc.SameRangeZones(ctx, cloud)
	if err != nil {
		t.Fatal(err)
	}
	if len(same) != 1 || same[0].ID != office.ID {
		t.Fatalf("same range zones = %+v, want office only", same)
	}
}
