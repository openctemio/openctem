package handler

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
)

// Only platform sensors are counted, and stale or erroring ones count as
// offline: the overview is about the shared fleet the operator runs.
func TestBuildAdminOverviewPlatformSensors(t *testing.T) {
	ops := postgres.OpsSnapshot{Sensors: []postgres.OpsSensorCount{
		{Platform: true, Health: "online", Count: 3},
		{Platform: true, Health: "offline", Count: 1},
		{Platform: true, Health: "stale", Count: 1},
		{Platform: true, Health: "late", Count: 2},
		{Platform: false, Health: "offline", Count: 9},
	}, SchemaVersion: 10, SchemaKnown: true}
	got := buildAdminOverview(postgres.AdminOverviewCounts{}, ops, 0, 12, time.Now())
	s := got.Platform.PlatformSensors
	if s.Total != 7 || s.Online != 3 || s.Offline != 2 {
		t.Fatalf("platform sensors = %+v, want total 7 online 3 offline 2", s)
	}
	if got.Platform.SchemaShipped != 12 || got.Platform.SchemaVersion != 10 {
		t.Fatalf("schema = %+v", got.Platform)
	}
	if got.Organizations.WithoutOwnerSample == nil {
		t.Fatal("sample must encode as [] not null")
	}
}
