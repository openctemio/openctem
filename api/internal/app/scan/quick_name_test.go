package scan

import (
	"regexp"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// 22c B8: two quick scans started in the same second get different names
// (the name is unique per tenant; the second one used to fail with 409).
func TestQuickScanName_UniqueWithinASecond(t *testing.T) {
	now := time.Date(2026, 10, 5, 10, 15, 30, 0, time.UTC)
	seen := map[string]bool{}
	for range 1000 {
		n := quickScanName(now, shared.NewID())
		if seen[n] {
			t.Fatalf("duplicate quick scan name %q", n)
		}
		seen[n] = true
		if !regexp.MustCompile(`^Quick Scan - 20261005-101530-[0-9a-f]{8}$`).MatchString(n) {
			t.Fatalf("name %q", n)
		}
	}
}
