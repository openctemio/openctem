package programtarget

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/internal/app/bountyprogram"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The report of a program's targets is a valid CTIS 2.0 document with no
// tenant or program id: the program binds through the caller.
func TestReport_IsValidCTISWithoutTenantOrProgramID(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	programID := shared.NewID()
	src := bountyprogram.TargetSource{Name: "hackerone", Run: "sync-7", ObservedAt: now.Add(48 * time.Hour)}
	assets := []bp.TargetAsset{
		{Key: "k1", Type: bp.TargetAssetDomain, Value: "Example.com"},
		{Key: "k2", Type: bp.TargetAssetNetwork, Value: "203.0.113.0/24"},
		{Key: "k3", Type: bp.TargetAssetIP, Value: "203.0.113.5"},
		{Key: "k4", Type: bp.TargetAssetRepo, Value: "github.com/Acme/App"},
		{Key: "k5", Type: bp.TargetAssetDomain, Value: "*.bad"}, // no canonical form: dropped
	}
	r, keys := Report(programID, src, assets, now)

	if err := r.Validate(); err != nil {
		t.Fatalf("program target report does not validate: %v", err)
	}
	if !ctis.IsReportID(r.Metadata.ID) || r.Metadata.Channel != ctis.ChannelIntegration || r.Metadata.CoverageType != ctis.CoveragePartial {
		t.Fatalf("metadata = %+v", r.Metadata)
	}
	if !r.Metadata.GeneratedAt.Equal(now) {
		t.Fatalf("generated_at %v, want the observation capped at now", r.Metadata.GeneratedAt)
	}
	if len(r.Metadata.SourceRefs) != 1 || r.Metadata.SourceRefs[0] != (ctis.SourceRef{System: "hackerone", ID: "sync-7"}) {
		t.Fatalf("source_refs = %+v", r.Metadata.SourceRefs)
	}
	if len(r.Assets) != 4 || len(keys) != 4 || keys["t0"] != "k1" || r.Assets[0].Value != "example.com" || r.Assets[0].Type != ctis.AssetTypeDomainName {
		t.Fatalf("assets %+v keys %v", r.Assets, keys)
	}
	if r.Assets[1].Type != ctis.AssetTypeIPRange {
		t.Fatalf("network target is %s, want ip_range", r.Assets[1].Type)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), programID.String()) {
		t.Fatal("the report carries the program id")
	}
}
