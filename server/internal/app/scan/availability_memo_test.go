package scan

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/tool"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// viewReads counts the repository reads of the real tool service.
type viewReads struct {
	tooldom.TenantToolConfigRepository
	n atomic.Int32
}

func (v *viewReads) ListToolsWithConfig(context.Context, shared.ID, tooldom.ToolFilter, pagination.Pagination) (pagination.Result[*tooldom.ToolWithConfig], error) {
	v.n.Add(1)
	return pagination.Result[*tooldom.ToolWithConfig]{}, nil
}
func (v *viewReads) ListAllSensors(context.Context, string) ([]*sensor.Sensor, error) {
	v.n.Add(1)
	return nil, nil
}

type viewZones struct{ v *viewReads }

func (z viewZones) List(context.Context, shared.ID) ([]*scanzone.Zone, error) {
	z.v.n.Add(1)
	return nil, nil
}
func (v *viewReads) ListByTenant(context.Context, shared.ID) (map[shared.ID]*sensor.Grant, error) {
	v.n.Add(1)
	return nil, nil
}
func (v *viewReads) CurrentManifestsByTenant(context.Context, shared.ID) (map[shared.ID]*sensor.ManifestVersion, error) {
	v.n.Add(1)
	return nil, nil
}

// CoverageReadiness for several tools reads the tenant view once, not once
// per tool: 3 tools were 15 repository reads (about 18 queries), now 5 (6).
func TestCoverageReadiness_ComputesAvailabilityOnce(t *testing.T) {
	src := &viewReads{}
	tools := tool.NewService(nil, src, logger.NewNop())
	tools.SetAvailabilitySources(src, viewZones{src}, src)
	tools.SetManifestSource(src)
	s := &Service{logger: logger.NewNop(), toolAvailability: tools}

	caps := []string{"probe.http", "enumerate.subdomains", "crawl.web"}
	distinct := map[string]bool{}
	for _, c := range caps {
		distinct[toolOf(t, c)] = true
	}
	_ = s.CoverageReadiness(context.Background(), shared.NewID(), caps)
	got := src.n.Load()
	t.Logf("tools=%d repository reads: before=%d after=%d", len(distinct), 5*len(distinct), got)
	if got != 5 {
		t.Fatalf("repository reads = %d, want 5 (one tenant view)", got)
	}
}
