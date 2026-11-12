package vulnmatch

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/domain/vulncatalog"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// unavailableCatalogStore answers ranges the way the disabled or unreachable
// vulnerability catalog does.
type unavailableCatalogStore struct{ *fakeStore }

func (unavailableCatalogStore) RangesForProduct(context.Context, shared.ID) ([]softwarematch.AffectedRange, error) {
	return nil, fmt.Errorf("product ranges: %w", vulncatalog.ErrUnavailable)
}

// An unreadable catalog is "unknown", never "no ranges": the run stops before
// any version result is replaced and before any tenant is reconciled, so no
// finding is closed.
func TestRun_CatalogUnavailableClosesNothing(t *testing.T) {
	asset, product, version := shared.NewID(), shared.NewID(), shared.NewID()
	tenantID := shared.NewID()
	fs := newFakeStore()
	fs.pending = []softwarematch.Version{{ID: version, ProductID: product, Raw: "1.0"}}
	fs.dequeueIDs = []shared.ID{tenantID}
	fs.existing = []softwarematch.MatcherFinding{{ID: shared.NewID(), AssetID: asset, CVEID: "CVE-1", Fingerprint: "gone",
		Status: "new", ProductID: &product, VersionID: &version, Location: "tcp/443"}}
	fs.links[softwarematch.LinkKey{AssetID: asset, ProductID: product, VersionID: version, Location: "tcp/443"}] =
		softwarematch.LinkInfo{State: softwarematch.LinkCurrent, VersionEvaluated: true}

	w := &fakeWriter{}
	svc := NewService(unavailableCatalogStore{fs}, fakePolicy{tenant.VulnMatchingSettings{Enabled: true}}, w, logger.NewNop())
	svc.SetClosureSettings(fixedClosing{Mode: tenant.ClosingModeAuto})

	_, err := svc.Run(context.Background(), time.Minute)
	if !errors.Is(err, vulncatalog.ErrUnavailable) {
		t.Fatalf("Run err = %v, want ErrUnavailable", err)
	}
	if len(fs.replaced) != 0 {
		t.Fatalf("version results replaced with an unreadable catalog: %v", fs.replaced)
	}
	for kind, ids := range fs.closed {
		if len(ids) > 0 {
			t.Fatalf("closed %d findings (%s) with an unreadable catalog", len(ids), kind)
		}
	}
	if fs.dequeueIDs == nil {
		t.Fatal("a tenant was dequeued for reconcile with an unreadable catalog")
	}
}
