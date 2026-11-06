package scope

import (
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
)

// A batch's expiry and tier reach every item's CreateTarget input, so the
// per-item policy checks (one-off limit, intrusive tier rules) decide them.
func TestBulkItemInputCarriesBatchSettings(t *testing.T) {
	days := 7
	in := BulkTargetsInput{TenantID: "t", Reason: "r", ExpiresInDays: &days, MaxTier: "t1"}
	got := bulkItemInput(in, BulkTargetItem{TargetType: " domain ", Pattern: " *.example.com "}, scopedom.OriginImport)
	if got.ExpiresInDays == nil || *got.ExpiresInDays != 7 {
		t.Fatalf("expiry not carried: %v", got.ExpiresInDays)
	}
	if got.MaxTier != "t1" || got.Reason != "r" || !got.batch {
		t.Fatalf("batch settings lost: %+v", got)
	}
	if got.TargetType != "domain" || got.Pattern != "*.example.com" {
		t.Fatalf("item not trimmed: %q %q", got.TargetType, got.Pattern)
	}
	perm := bulkItemInput(BulkTargetsInput{}, BulkTargetItem{TargetType: "domain", Pattern: "a.com"}, scopedom.OriginImport)
	if perm.ExpiresInDays != nil {
		t.Fatal("default must stay permanent")
	}
}
