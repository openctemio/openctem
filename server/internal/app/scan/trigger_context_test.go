package scan

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestValidateCallerTriggerContext(t *testing.T) {
	ok := []map[string]any{
		nil,
		{},
		{"reason": "re-run after the fix"},
	}
	for _, c := range ok {
		if err := ValidateCallerTriggerContext(c); err != nil {
			t.Fatalf("context %v: want accepted, got %v", c, err)
		}
	}

	refused := []map[string]any{
		// platform-owned keys that reach sensor jobs or decide the outcome
		{"uncovered_targets": 3},
		{RunContextKeyRuleSources: "x"},
		{"sensor_routing": map[string]any{}},
		{"scan_zone_id": "z"},
		{"actor_user_id": "u"},
		{"system_policy": true},
		{RunContextKeySkipped: []any{"a"}},
		{"reason": "ok", "intensity": "aggressive"},
		// reason of the wrong type or too long
		{"reason": 42},
		{"reason": strings.Repeat("a", maxTriggerReasonLen+1)},
	}
	for _, c := range refused {
		err := ValidateCallerTriggerContext(c)
		if err == nil || !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("context %v: want a validation error, got %v", c, err)
		}
		var de *shared.DomainError
		if !errors.As(err, &de) || de.Code != CodeTriggerContextRefused {
			t.Fatalf("context %v: want code %s, got %v", c, CodeTriggerContextRefused, err)
		}
	}
}
