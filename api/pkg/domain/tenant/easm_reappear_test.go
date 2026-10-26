package tenant

import (
	"testing"
	"time"
)

func TestEASMSettings_ReappearAfter(t *testing.T) {
	day := 24 * time.Hour
	for days, want := range map[int]time.Duration{0: 30 * day, 7: 7 * day, 365: 365 * day} {
		if got := (EASMSettings{ReappearAfterDays: days}).ReappearAfter(); got != want {
			t.Errorf("ReappearAfterDays=%d: got %v, want %v", days, got, want)
		}
		if err := (EASMSettings{ReappearAfterDays: days}).Validate(); err != nil {
			t.Errorf("ReappearAfterDays=%d refused: %v", days, err)
		}
	}
	for _, days := range []int{-1, 1, 6, 366, 10000} {
		if err := (EASMSettings{ReappearAfterDays: days}).Validate(); err == nil {
			t.Errorf("ReappearAfterDays=%d accepted", days)
		}
	}
}
