package tenant

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestAPIKeySettings(t *testing.T) {
	cases := map[int]int{0: DefaultAPIKeyMaxLifetimeDays, 1: 1, 30: 30, APIKeyLifetimeCeilingDays: APIKeyLifetimeCeilingDays}
	for in, want := range cases {
		if got := (APIKeySettings{MaxLifetimeDays: in}).EffectiveMaxLifetimeDays(); got != want {
			t.Errorf("max %d: effective %d, want %d", in, got, want)
		}
	}
	for _, bad := range []int{-1, APIKeyLifetimeCeilingDays + 1} {
		if err := (APIKeySettings{MaxLifetimeDays: bad}).Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("max %d: err = %v, want validation", bad, err)
		}
	}
	// A stored value above the ceiling (written before a ceiling change)
	// never applies above it.
	if got := (APIKeySettings{MaxLifetimeDays: 1000}).EffectiveMaxLifetimeDays(); got != APIKeyLifetimeCeilingDays {
		t.Errorf("above the ceiling: %d", got)
	}
}
