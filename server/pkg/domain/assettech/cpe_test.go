package assettech

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestWithCPE(t *testing.T) {
	base, ok := Observation(shared.NewID(), "nginx", "1.18.0", nil, 0, "httpx", time.Now())
	if !ok {
		t.Fatal("observation refused")
	}
	got := base.WithCPE("  CPE:2.3:a:F5:nginx:1.18.0:*:*:*:*:*:*:*  ")
	if got.Vendor != "f5" || got.CPE != "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*" {
		t.Fatalf("WithCPE = vendor %q cpe %q", got.Vendor, got.CPE)
	}
	for _, bad := range []string{
		"", "nginx", "cpe:/a:f5:nginx:1.18.0", "cpe:2.3:a:*:nginx:1.18.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*\x1b", "cpe:2.3:a",
	} {
		if got := base.WithCPE(bad); got.Vendor != "" || got.CPE != "" {
			t.Errorf("WithCPE(%q) kept vendor %q cpe %q, want none", bad, got.Vendor, got.CPE)
		}
	}
}
