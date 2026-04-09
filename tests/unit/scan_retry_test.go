package unit

import (
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/shared"
)

// TestScanRetryConfig validates retry configuration bounds enforcement.
// Run with: go test -v ./tests/unit -run TestScanRetryConfig
func TestScanRetryConfig(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	newScan := func(t *testing.T) *scan.Scan {
		t.Helper()
		s, err := scan.NewScan(tenantID, "test", groupID, scan.ScanTypeSingle)
		if err != nil {
			t.Fatalf("create scan: %v", err)
		}
		return s
	}

	t.Run("DefaultsAreSet", func(t *testing.T) {
		s := newScan(t)
		if s.MaxRetries != 0 {
			t.Errorf("expected default MaxRetries=0 (no retry), got %d", s.MaxRetries)
		}
		if s.RetryBackoffSeconds != scan.DefaultRetryBackoffSeconds {
			t.Errorf("expected default RetryBackoffSeconds=%d, got %d",
				scan.DefaultRetryBackoffSeconds, s.RetryBackoffSeconds)
		}
	})

	t.Run("SetRetryConfig_ValidValues", func(t *testing.T) {
		s := newScan(t)
		s.SetRetryConfig(3, 120)
		if s.MaxRetries != 3 {
			t.Errorf("expected MaxRetries=3, got %d", s.MaxRetries)
		}
		if s.RetryBackoffSeconds != 120 {
			t.Errorf("expected RetryBackoffSeconds=120, got %d", s.RetryBackoffSeconds)
		}
	})

	t.Run("SetRetryConfig_NegativeMaxRetries_ClampedToZero", func(t *testing.T) {
		s := newScan(t)
		s.SetRetryConfig(-5, 60)
		if s.MaxRetries != 0 {
			t.Errorf("expected MaxRetries=0 after negative input, got %d", s.MaxRetries)
		}
	})

	t.Run("SetRetryConfig_AboveMax_ClampedToMax", func(t *testing.T) {
		s := newScan(t)
		s.SetRetryConfig(50, 60)
		if s.MaxRetries != scan.MaxRetryCount {
			t.Errorf("expected MaxRetries=%d after over-max input, got %d",
				scan.MaxRetryCount, s.MaxRetries)
		}
	})

	t.Run("SetRetryConfig_ZeroBackoff_DefaultsToDefault", func(t *testing.T) {
		s := newScan(t)
		s.SetRetryConfig(3, 0)
		if s.RetryBackoffSeconds != scan.DefaultRetryBackoffSeconds {
			t.Errorf("expected RetryBackoffSeconds=%d, got %d",
				scan.DefaultRetryBackoffSeconds, s.RetryBackoffSeconds)
		}
	})

	t.Run("SetRetryConfig_BelowMinBackoff_ClampedToMin", func(t *testing.T) {
		s := newScan(t)
		s.SetRetryConfig(3, 5)
		if s.RetryBackoffSeconds != scan.MinRetryBackoffSeconds {
			t.Errorf("expected RetryBackoffSeconds=%d, got %d",
				scan.MinRetryBackoffSeconds, s.RetryBackoffSeconds)
		}
	})

	t.Run("SetRetryConfig_AboveMaxBackoff_ClampedToMax", func(t *testing.T) {
		s := newScan(t)
		s.SetRetryConfig(3, 999999)
		if s.RetryBackoffSeconds != scan.MaxRetryBackoffSeconds {
			t.Errorf("expected RetryBackoffSeconds=%d, got %d",
				scan.MaxRetryBackoffSeconds, s.RetryBackoffSeconds)
		}
	})

	t.Run("SetRetryConfig_BoundaryValues", func(t *testing.T) {
		s := newScan(t)
		// Min backoff
		s.SetRetryConfig(1, scan.MinRetryBackoffSeconds)
		if s.RetryBackoffSeconds != scan.MinRetryBackoffSeconds {
			t.Errorf("min boundary failed: got %d", s.RetryBackoffSeconds)
		}
		// Max backoff
		s.SetRetryConfig(1, scan.MaxRetryBackoffSeconds)
		if s.RetryBackoffSeconds != scan.MaxRetryBackoffSeconds {
			t.Errorf("max boundary failed: got %d", s.RetryBackoffSeconds)
		}
		// Max retries
		s.SetRetryConfig(scan.MaxRetryCount, 60)
		if s.MaxRetries != scan.MaxRetryCount {
			t.Errorf("max retries boundary failed: got %d", s.MaxRetries)
		}
	})

	t.Run("SetRetryConfig_UpdatesUpdatedAt", func(t *testing.T) {
		s := newScan(t)
		before := s.UpdatedAt
		time.Sleep(time.Millisecond)
		s.SetRetryConfig(2, 30)
		if !s.UpdatedAt.After(before) {
			t.Error("expected UpdatedAt to advance after SetRetryConfig")
		}
	})
}

// TestScanCalculateRetryDelay validates exponential backoff calculation.
// Run with: go test -v ./tests/unit -run TestScanCalculateRetryDelay
func TestScanCalculateRetryDelay(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	newScanWithBackoff := func(t *testing.T, backoff int) *scan.Scan {
		t.Helper()
		s, err := scan.NewScan(tenantID, "test", groupID, scan.ScanTypeSingle)
		if err != nil {
			t.Fatalf("create scan: %v", err)
		}
		s.RetryBackoffSeconds = backoff
		return s
	}

	t.Run("FirstRetry_BaseBackoff", func(t *testing.T) {
		s := newScanWithBackoff(t, 60)
		got := s.CalculateRetryDelay(0)
		want := 60 * time.Second
		if got != want {
			t.Errorf("attempt 0: expected %v, got %v", want, got)
		}
	})

	t.Run("SecondRetry_DoubleBackoff", func(t *testing.T) {
		s := newScanWithBackoff(t, 60)
		got := s.CalculateRetryDelay(1)
		want := 120 * time.Second
		if got != want {
			t.Errorf("attempt 1: expected %v, got %v", want, got)
		}
	})

	t.Run("ThirdRetry_QuadrupleBackoff", func(t *testing.T) {
		s := newScanWithBackoff(t, 60)
		got := s.CalculateRetryDelay(2)
		want := 240 * time.Second
		if got != want {
			t.Errorf("attempt 2: expected %v, got %v", want, got)
		}
	})

	t.Run("ExponentialGrowth", func(t *testing.T) {
		s := newScanWithBackoff(t, 10)
		// 10 -> 20 -> 40 -> 80 -> 160 -> 320 -> 640 -> 1280 -> 2560 -> 5120
		expected := []time.Duration{
			10 * time.Second,
			20 * time.Second,
			40 * time.Second,
			80 * time.Second,
			160 * time.Second,
			320 * time.Second,
			640 * time.Second,
			1280 * time.Second,
			2560 * time.Second,
			5120 * time.Second,
		}
		for i, want := range expected {
			got := s.CalculateRetryDelay(i)
			if got != want {
				t.Errorf("attempt %d: expected %v, got %v", i, want, got)
			}
		}
	})

	t.Run("CapAtMaxBackoff", func(t *testing.T) {
		s := newScanWithBackoff(t, scan.MaxRetryBackoffSeconds)
		// Even attempt 0 already at cap; doubling stops here
		got := s.CalculateRetryDelay(5)
		want := time.Duration(scan.MaxRetryBackoffSeconds) * time.Second
		if got != want {
			t.Errorf("expected cap %v, got %v", want, got)
		}
	})

	t.Run("ZeroBackoff_DefaultsToDefault", func(t *testing.T) {
		s := newScanWithBackoff(t, 0)
		got := s.CalculateRetryDelay(0)
		want := time.Duration(scan.DefaultRetryBackoffSeconds) * time.Second
		if got != want {
			t.Errorf("expected %v, got %v", want, got)
		}
	})
}

// TestScanShouldRetry validates retry budget check.
// Run with: go test -v ./tests/unit -run TestScanShouldRetry
func TestScanShouldRetry(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	newScanWithMax := func(t *testing.T, maxRetries int) *scan.Scan {
		t.Helper()
		s, err := scan.NewScan(tenantID, "test", groupID, scan.ScanTypeSingle)
		if err != nil {
			t.Fatalf("create scan: %v", err)
		}
		s.MaxRetries = maxRetries
		return s
	}

	t.Run("MaxRetriesZero_NeverRetries", func(t *testing.T) {
		s := newScanWithMax(t, 0)
		if s.ShouldRetry(0) {
			t.Error("ShouldRetry(0) with MaxRetries=0 should be false")
		}
	})

	t.Run("FirstAttemptFails_RetryAllowed", func(t *testing.T) {
		s := newScanWithMax(t, 3)
		if !s.ShouldRetry(0) {
			t.Error("ShouldRetry(0) with MaxRetries=3 should be true")
		}
	})

	t.Run("SecondAttemptFails_RetryAllowed", func(t *testing.T) {
		s := newScanWithMax(t, 3)
		if !s.ShouldRetry(1) {
			t.Error("ShouldRetry(1) with MaxRetries=3 should be true")
		}
	})

	t.Run("ThirdAttemptFails_RetryAllowed", func(t *testing.T) {
		s := newScanWithMax(t, 3)
		if !s.ShouldRetry(2) {
			t.Error("ShouldRetry(2) with MaxRetries=3 should be true (last allowed retry)")
		}
	})

	t.Run("FourthAttemptFails_NoMoreRetries", func(t *testing.T) {
		s := newScanWithMax(t, 3)
		if s.ShouldRetry(3) {
			t.Error("ShouldRetry(3) with MaxRetries=3 should be false (budget exhausted)")
		}
	})

	t.Run("MaxRetriesAtCap_TenAttempts", func(t *testing.T) {
		s := newScanWithMax(t, scan.MaxRetryCount)
		for i := 0; i < scan.MaxRetryCount; i++ {
			if !s.ShouldRetry(i) {
				t.Errorf("ShouldRetry(%d) with MaxRetries=%d should be true", i, scan.MaxRetryCount)
			}
		}
		if s.ShouldRetry(scan.MaxRetryCount) {
			t.Errorf("ShouldRetry(%d) with MaxRetries=%d should be false (boundary)",
				scan.MaxRetryCount, scan.MaxRetryCount)
		}
	})
}

// TestScanRetryClone ensures Clone preserves retry config.
// Run with: go test -v ./tests/unit -run TestScanRetryClone
func TestScanRetryClone(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	original, err := scan.NewScan(tenantID, "Original", groupID, scan.ScanTypeSingle)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	original.ScannerName = "nuclei"
	original.SetRetryConfig(5, 90)

	clone := original.Clone("Cloned")

	if clone.MaxRetries != 5 {
		t.Errorf("clone MaxRetries: expected 5, got %d", clone.MaxRetries)
	}
	if clone.RetryBackoffSeconds != 90 {
		t.Errorf("clone RetryBackoffSeconds: expected 90, got %d", clone.RetryBackoffSeconds)
	}

	// Verify clone is independent
	original.SetRetryConfig(1, 30)
	if clone.MaxRetries != 5 {
		t.Error("clone MaxRetries should be independent of original")
	}
}
