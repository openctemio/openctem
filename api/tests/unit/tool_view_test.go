package unit

// The tenant's view of the tool catalog (internal/app/tool/view.go):
// loading is per request, never per row (include= cost control),
// filters and sort, and settings that never take a secret.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/tool"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// viewCatalogRepo serves a fixed catalog of n tools and counts the reads.
type viewCatalogRepo struct {
	*toolSvcMockConfigRepo
	tools []*tooldom.ToolWithConfig
	reads int
}

func (m *viewCatalogRepo) ListToolsWithConfig(_ context.Context, _ shared.ID, _ tooldom.ToolFilter, page pagination.Pagination) (pagination.Result[*tooldom.ToolWithConfig], error) {
	m.reads++
	start := page.Offset()
	if start > len(m.tools) {
		start = len(m.tools)
	}
	end := start + page.Limit()
	if end > len(m.tools) {
		end = len(m.tools)
	}
	return pagination.NewResult(m.tools[start:end], int64(len(m.tools)), page), nil
}

type viewStatsRepo struct {
	*toolSvcMockExecutionRepo
	reads int
}

func (m *viewStatsRepo) GetTenantStats(_ context.Context, tenantID shared.ID, _ int) (*tooldom.TenantToolStats, error) {
	m.reads++
	return &tooldom.TenantToolStats{TenantID: tenantID}, nil
}

type viewSensors struct{ reads int }

func (s *viewSensors) ListAllSensors(_ context.Context, _ string) ([]*sensor.Sensor, error) {
	s.reads++
	return nil, nil
}

func newViewService(n int) (*tool.Service, *viewCatalogRepo, *viewStatsRepo, *viewSensors) {
	catalog := &viewCatalogRepo{toolSvcMockConfigRepo: newToolSvcMockConfigRepo()}
	for i := 0; i < n; i++ {
		t, _ := tooldom.NewTool(fmt.Sprintf("tool-%03d", i), fmt.Sprintf("Tool %03d", n-i), nil, tooldom.InstallBinary)
		if i%2 == 1 {
			tid := shared.NewID()
			t.TenantID = &tid
		}
		catalog.tools = append(catalog.tools, &tooldom.ToolWithConfig{Tool: t, IsEnabled: i%3 != 0})
	}
	stats := &viewStatsRepo{toolSvcMockExecutionRepo: newToolSvcMockExecutionRepo()}
	sensors := &viewSensors{}
	svc := tool.NewService(newToolSvcMockToolRepo(), catalog, stats, logger.NewNop())
	svc.SetAvailabilitySources(sensors, nil, nil)
	return svc, catalog, stats, sensors
}

// The reads behind a page do not grow with the page size: one catalog read
// per 100 tools, one availability computation, one statistics query.
func TestToolView_QueryCountIndependentOfPageSize(t *testing.T) {
	counts := map[int][3]int{}
	for _, perPage := range []int{1, 50} {
		svc, catalog, stats, sensors := newViewService(150)
		res, err := svc.ListToolView(context.Background(), tool.ListToolViewInput{
			TenantID: shared.NewID().String(), Page: 1, PerPage: perPage,
			ToolViewOptions: tool.ToolViewOptions{Availability: true, Stats: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Data) != perPage || res.Total != 150 {
			t.Fatalf("per_page %d: %d items of %d", perPage, len(res.Data), res.Total)
		}
		for _, v := range res.Data {
			if v.Stats == nil || v.Availability == nil {
				t.Fatalf("per_page %d: %s lacks stats or availability", perPage, v.Tool.Name)
			}
		}
		counts[perPage] = [3]int{catalog.reads, stats.reads, sensors.reads}
	}
	if counts[1] != counts[50] || counts[1][1] != 1 || counts[1][2] != 1 {
		t.Fatalf("reads (catalog, stats, sensors) per_page=1 %v, per_page=50 %v; want equal, one stats and one sensor read", counts[1], counts[50])
	}
}

func TestToolView_FiltersSortAndValidation(t *testing.T) {
	svc, _, _, _ := newViewService(12)
	ctx := context.Background()
	tenant := shared.NewID().String()

	custom, err := svc.ListToolView(ctx, tool.ListToolViewInput{TenantID: tenant, Source: tool.SourceCustom, PerPage: 100})
	if err != nil || custom.Total != 6 {
		t.Fatalf("source=custom: %d, %v", custom.Total, err)
	}
	for _, v := range custom.Data {
		if v.Tool.IsPlatformTool() {
			t.Fatalf("source=custom lists platform tool %s", v.Tool.Name)
		}
	}
	off := false
	disabled, _ := svc.ListToolView(ctx, tool.ListToolViewInput{TenantID: tenant, Enabled: &off, PerPage: 100})
	if disabled.Total != 4 {
		t.Fatalf("enabled=false: %d, want 4", disabled.Total)
	}
	sorted, _ := svc.ListToolView(ctx, tool.ListToolViewInput{TenantID: tenant, Sort: "-name", PerPage: 100})
	if sorted.Data[0].Tool.DisplayName != "Tool 012" || sorted.Data[11].Tool.DisplayName != "Tool 001" {
		t.Fatalf("sort=-name: first %s last %s", sorted.Data[0].Tool.DisplayName, sorted.Data[11].Tool.DisplayName)
	}
	for _, in := range []tool.ListToolViewInput{
		{TenantID: tenant, Source: "everyone"},
		{TenantID: tenant, Sort: "install_cmd"},
		{TenantID: "not-a-tenant"},
	} {
		if _, err := svc.ListToolView(ctx, in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%+v: %v, want ErrValidation", in, err)
		}
	}
}

// Settings never hold a secret: refused at write, by key and by value.
func TestToolView_UpdateSettingsRefusesSecrets(t *testing.T) {
	svc, toolRepo, _, _ := newToolSvcTestService()
	tenant := shared.NewID()
	tl := createPlatformTool("view-secret-tool", tooldom.InstallBinary)
	toolRepo.tools[tl.ID.String()] = tl

	for _, cfg := range []map[string]any{
		{"api_key": "fake-key-Zq8vT3mP0wX7rL2kN9sB4yH6"},
		{"notes": "sk-Zq8vT3mP0wX7rL2kN9sB4yH6aaaa"},
		{"nested": map[string]any{"password": "hunter2-hunter2"}},
	} {
		_, err := svc.UpdateToolSettings(context.Background(), tool.UpdateToolSettingsInput{
			TenantID: tenant.String(), ToolID: tl.ID.String(), Config: cfg,
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("config %v: %v, want ErrValidation", cfg, err)
		}
	}
	on := false
	got, err := svc.UpdateToolSettings(context.Background(), tool.UpdateToolSettingsInput{
		TenantID: tenant.String(), ToolID: tl.ID.String(), IsEnabled: &on, Config: map[string]any{"rate_limit": 5},
	})
	if err != nil || got.IsEnabled || got.Config["rate_limit"] != 5 {
		t.Fatalf("plain config: %+v %v", got, err)
	}
	if _, err := svc.UpdateToolSettings(context.Background(), tool.UpdateToolSettingsInput{
		TenantID: tenant.String(), ToolID: tl.ID.String(),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty change: %v, want ErrValidation", err)
	}
}
