package threatintel

import (
	"testing"
	"time"
)

// A score whose rank the feed's curve does not have reads as unknown, never
// as the 0th percentile ("EPSS 97.6%, 0th percentile" on a finding).
func TestEPSSPercentileUnknownIsNil(t *testing.T) {
	s := ReconstituteEPSSScore("CVE-2021-44228", 0.976, 0, "v", time.Now(), time.Now(), time.Now())
	if p := s.PercentilePtr(); p == nil || *p != 0 {
		t.Fatalf("known percentile 0 = %v, want 0", p)
	}
	s.MarkPercentileUnknown()
	if p := s.PercentilePtr(); p != nil {
		t.Fatalf("unknown percentile = %v, want nil", *p)
	}
	if p := NewEPSSScore("CVE-1", 0.5, 88.2, "v", time.Now()).PercentilePtr(); p == nil || *p != 88.2 {
		t.Fatalf("new score percentile = %v", p)
	}
}
