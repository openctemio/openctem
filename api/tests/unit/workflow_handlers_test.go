package unit

import (
	"context"
	"io"
	"strings"
	"testing"

	automationsvc "github.com/openctemio/openctem/api/internal/app/automation"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// =============================================================================
// Helpers
// =============================================================================

// wfHandlerNewLogger creates a no-op logger for handler tests.
func wfHandlerNewLogger() *logger.Logger {
	return logger.New(logger.Config{
		Level:  "error",
		Format: "json",
		Output: io.Discard,
	})
}

// =============================================================================
// TestWfHandlerConditionEvaluator — DefaultConditionEvaluator.Evaluate
// =============================================================================

func TestWfHandlerConditionEvaluatorSimpleEquality(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"severity": "critical",
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.severity == critical", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for trigger.severity == critical")
	}
}

func TestWfHandlerConditionEvaluatorNotEqual(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"severity": "high",
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.severity != low", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for trigger.severity != low when value is high")
	}
}

func TestWfHandlerConditionEvaluatorNotEqualFalse(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"severity": "low",
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.severity != low", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false for trigger.severity != low when value is low")
	}
}

func TestWfHandlerConditionEvaluatorNumericGreaterThanTrue(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"cvss": 8.5,
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.cvss > 7.0", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for 8.5 > 7.0")
	}
}

func TestWfHandlerConditionEvaluatorNumericGreaterThanFalse(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"cvss": 5.0,
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.cvss > 7.0", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false for 5.0 > 7.0")
	}
}

func TestWfHandlerConditionEvaluatorNumericLessThanTrue(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"cvss": 2.0,
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.cvss < 3.0", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for 2.0 < 3.0")
	}
}

func TestWfHandlerConditionEvaluatorNumericLessThanFalse(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"cvss": 9.9,
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.cvss < 3.0", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false for 9.9 < 3.0")
	}
}

func TestWfHandlerConditionEvaluatorGreaterOrEqual(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}

	tests := []struct {
		name  string
		score float64
		want  bool
	}{
		{"equal boundary", 8.0, true},
		{"above boundary", 9.5, true},
		{"below boundary", 7.9, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := map[string]any{
				"trigger": map[string]any{
					"score": tc.score,
				},
			}
			result, err := e.Evaluate(context.Background(), "trigger.score >= 8", data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tc.want {
				t.Errorf("for score=%.1f: got %v, want %v", tc.score, result, tc.want)
			}
		})
	}
}

func TestWfHandlerConditionEvaluatorLessOrEqual(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}

	tests := []struct {
		name  string
		count float64
		want  bool
	}{
		{"equal boundary", 5.0, true},
		{"below boundary", 3.0, true},
		{"above boundary", 6.0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := map[string]any{
				"trigger": map[string]any{
					"count": tc.count,
				},
			}
			result, err := e.Evaluate(context.Background(), "trigger.count <= 5", data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tc.want {
				t.Errorf("for count=%.1f: got %v, want %v", tc.count, result, tc.want)
			}
		})
	}
}

func TestWfHandlerConditionEvaluatorBooleanComparison(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}

	t.Run("confirmed true matches", func(t *testing.T) {
		data := map[string]any{
			"trigger": map[string]any{
				"confirmed": true,
			},
		}
		result, err := e.Evaluate(context.Background(), "trigger.confirmed == true", data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result {
			t.Error("expected true for confirmed == true when confirmed is true")
		}
	})

	t.Run("confirmed false does not match", func(t *testing.T) {
		data := map[string]any{
			"trigger": map[string]any{
				"confirmed": false,
			},
		}
		result, err := e.Evaluate(context.Background(), "trigger.confirmed == true", data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result {
			t.Error("expected false for confirmed(false) == true")
		}
	})
}

func TestWfHandlerConditionEvaluatorNestedPath(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"finding": map[string]any{
				"severity": "high",
			},
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.finding.severity == high", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for nested trigger.finding.severity == high")
	}
}

func TestWfHandlerConditionEvaluatorDeepNesting(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"c": map[string]any{
					"d": "value",
				},
			},
		},
	}

	result, err := e.Evaluate(context.Background(), "a.b.c.d == value", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for deep nested a.b.c.d == value")
	}
}

func TestWfHandlerConditionEvaluatorNonExistentPathReturnsFalse(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"severity": "high",
		},
	}

	// Non-existent path resolves to nil; fmt.Sprintf("%v", nil) == "<nil>" ≠ "somevalue"
	result, err := e.Evaluate(context.Background(), "trigger.nonexistent == somevalue", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false for non-existent path")
	}
}

func TestWfHandlerConditionEvaluatorEmptyExpressionReturnsTrue(t *testing.T) {
	// Per source: empty expression → true (no condition = always passes)
	e := &automationsvc.DefaultConditionEvaluator{}

	result, err := e.Evaluate(context.Background(), "", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for empty expression")
	}
}

func TestWfHandlerConditionEvaluatorExpressionTooLong(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	// Build expression longer than 500 chars
	longExpr := strings.Repeat("a", 501)

	_, err := e.Evaluate(context.Background(), longExpr, map[string]any{})
	if err == nil {
		t.Error("expected error for expression longer than 500 chars")
	}
	if !strings.Contains(err.Error(), "expression too long") {
		t.Errorf("expected 'expression too long' error, got: %v", err)
	}
}

func TestWfHandlerConditionEvaluatorNoOperatorEvaluatesAsPath(t *testing.T) {
	// Expressions with no known operator fall through to boolean path resolution.
	// A path that resolves to a non-empty string returns true.
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"active": "yes",
		},
	}

	// "trigger.active" resolves to "yes" (non-empty string → true)
	result, err := e.Evaluate(context.Background(), "trigger.active", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for non-empty string path without operator")
	}
}

func TestWfHandlerConditionEvaluatorNilPathReturnsFalse(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{}

	// Path "trigger.missing" resolves to nil → false
	result, err := e.Evaluate(context.Background(), "trigger.missing", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false for nil path resolution")
	}
}

func TestWfHandlerConditionEvaluatorStringContains(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"title": "SQL Injection found in login endpoint",
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.title contains SQL", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for title contains SQL")
	}
}

func TestWfHandlerConditionEvaluatorStringContainsFalse(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"title": "XSS vulnerability",
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.title contains SQL", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false for title that does not contain SQL")
	}
}

func TestWfHandlerConditionEvaluatorCaseSensitivity(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"severity": "Critical", // Capital C
		},
	}

	// Should NOT match lowercase "critical"
	result, err := e.Evaluate(context.Background(), "trigger.severity == critical", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false: comparison should be case-sensitive (Critical != critical)")
	}

	// Should match exact case
	result, err = e.Evaluate(context.Background(), "trigger.severity == Critical", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for exact case match (Critical == Critical)")
	}
}

func TestWfHandlerConditionEvaluatorMapDataType(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"metadata": map[string]any{
				"source": "scanner-v2",
			},
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.metadata.source == scanner-v2", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for nested map data type access")
	}
}

func TestWfHandlerConditionEvaluatorNilDataDoesNotPanic(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Evaluate panicked with nil data: %v", r)
		}
	}()

	// nil data → resolvePath returns nil → formatted as "<nil>" ≠ "critical"
	result, err := e.Evaluate(context.Background(), "trigger.severity == critical", nil)
	if err != nil {
		t.Fatalf("unexpected error with nil data: %v", err)
	}
	if result {
		t.Error("expected false for nil data comparison")
	}
}

func TestWfHandlerConditionEvaluatorBooleanLiteralTrue(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}

	result, err := e.Evaluate(context.Background(), "true", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for literal 'true'")
	}
}

func TestWfHandlerConditionEvaluatorBooleanLiteralFalse(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}

	result, err := e.Evaluate(context.Background(), "false", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false for literal 'false'")
	}
}

func TestWfHandlerConditionEvaluatorInOperator(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"severity": "critical",
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.severity in [critical, high]", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for severity in [critical, high]")
	}
}

func TestWfHandlerConditionEvaluatorInOperatorFalse(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"severity": "low",
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.severity in [critical, high]", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false for severity low not in [critical, high]")
	}
}

func TestWfHandlerConditionEvaluatorIntValue(t *testing.T) {
	e := &automationsvc.DefaultConditionEvaluator{}
	data := map[string]any{
		"trigger": map[string]any{
			"count": 10, // int (not float64)
		},
	}

	result, err := e.Evaluate(context.Background(), "trigger.count > 5", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for int count 10 > 5")
	}
}
