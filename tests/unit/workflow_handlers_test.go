package unit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/workflow"
	"github.com/openctemio/api/pkg/logger"
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

// wfHandlerNewActionInput builds a minimal ActionInput for tests.
func wfHandlerNewActionInput(config map[string]any, triggerData map[string]any) *app.ActionInput {
	return &app.ActionInput{
		TenantID:     shared.NewID(),
		WorkflowID:   shared.NewID(),
		RunID:        shared.NewID(),
		NodeKey:      "test-node",
		ActionType:   workflow.ActionTypeHTTPRequest,
		ActionConfig: config,
		TriggerData:  triggerData,
	}
}

// wfHandlerNewTestHandler creates an HTTPRequestHandler with SSRF disabled for unit testing.
// NEVER use this in production code.
func wfHandlerNewTestHandler() *app.HTTPRequestHandler {
	h := app.NewHTTPRequestHandler(wfHandlerNewLogger())
	h.SetClient(&http.Client{})
	h.AllowLocalhostForTesting()
	return h
}

// =============================================================================
// TestWfHandlerConditionEvaluator — DefaultConditionEvaluator.Evaluate
// =============================================================================

func TestWfHandlerConditionEvaluatorSimpleEquality(t *testing.T) {
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}

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
	e := &app.DefaultConditionEvaluator{}

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
	e := &app.DefaultConditionEvaluator{}

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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}

	result, err := e.Evaluate(context.Background(), "", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for empty expression")
	}
}

func TestWfHandlerConditionEvaluatorExpressionTooLong(t *testing.T) {
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}

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
	e := &app.DefaultConditionEvaluator{}

	result, err := e.Evaluate(context.Background(), "true", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("expected true for literal 'true'")
	}
}

func TestWfHandlerConditionEvaluatorBooleanLiteralFalse(t *testing.T) {
	e := &app.DefaultConditionEvaluator{}

	result, err := e.Evaluate(context.Background(), "false", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false for literal 'false'")
	}
}

func TestWfHandlerConditionEvaluatorInOperator(t *testing.T) {
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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
	e := &app.DefaultConditionEvaluator{}
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

// =============================================================================
// TestWfHandlerHTTPRequest — HTTPRequestHandler.Execute
// =============================================================================

func TestWfHandlerHTTPRequestValidGET(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	input := wfHandlerNewActionInput(map[string]any{
		"url":    ts.URL + "/test",
		"method": "GET",
	}, nil)

	output, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output["status_code"] != http.StatusOK {
		t.Errorf("expected status 200, got %v", output["status_code"])
	}
}

func TestWfHandlerHTTPRequestValidPOST(t *testing.T) {
	var receivedBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"created":true}`))
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	input := wfHandlerNewActionInput(map[string]any{
		"url":    ts.URL + "/create",
		"method": "POST",
		"body":   `{"name":"test"}`,
	}, nil)

	output, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output["status_code"] != http.StatusCreated {
		t.Errorf("expected status 201, got %v", output["status_code"])
	}
	if !strings.Contains(string(receivedBody), "test") {
		t.Errorf("expected body to contain 'test', got: %s", string(receivedBody))
	}
}

func TestWfHandlerHTTPRequestBlockedSchemeFile(t *testing.T) {
	h := app.NewHTTPRequestHandler(wfHandlerNewLogger())

	input := wfHandlerNewActionInput(map[string]any{
		"url":    "file:///etc/passwd",
		"method": "GET",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for file:// scheme")
	}
	if !strings.Contains(err.Error(), "security policy") {
		t.Errorf("expected security policy error, got: %v", err)
	}
}

func TestWfHandlerHTTPRequestBlockedSchemeFTP(t *testing.T) {
	h := app.NewHTTPRequestHandler(wfHandlerNewLogger())

	input := wfHandlerNewActionInput(map[string]any{
		"url":    "ftp://example.com/file.txt",
		"method": "GET",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for ftp:// scheme")
	}
	if !strings.Contains(err.Error(), "security policy") {
		t.Errorf("expected security policy error, got: %v", err)
	}
}

func TestWfHandlerHTTPRequestBlockedLoopbackIP(t *testing.T) {
	h := app.NewHTTPRequestHandler(wfHandlerNewLogger())

	input := wfHandlerNewActionInput(map[string]any{
		"url":    "http://127.0.0.1/admin",
		"method": "GET",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for loopback IP 127.0.0.1")
	}
	if !strings.Contains(err.Error(), "security policy") {
		t.Errorf("expected security policy error, got: %v", err)
	}
}

func TestWfHandlerHTTPRequestBlockedLinkLocalIP(t *testing.T) {
	// 169.254.x.x is the link-local / cloud metadata range
	h := app.NewHTTPRequestHandler(wfHandlerNewLogger())

	input := wfHandlerNewActionInput(map[string]any{
		"url":    "http://169.254.169.254/latest/meta-data/",
		"method": "GET",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for cloud metadata IP 169.254.169.254")
	}
	if !strings.Contains(err.Error(), "security policy") {
		t.Errorf("expected security policy error, got: %v", err)
	}
}

func TestWfHandlerHTTPRequestBlockedPrivateIP10(t *testing.T) {
	h := app.NewHTTPRequestHandler(wfHandlerNewLogger())

	input := wfHandlerNewActionInput(map[string]any{
		"url":    "http://10.0.0.1/internal",
		"method": "GET",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for private IP 10.0.0.1")
	}
	if !strings.Contains(err.Error(), "security policy") {
		t.Errorf("expected security policy error, got: %v", err)
	}
}

func TestWfHandlerHTTPRequestMissingURL(t *testing.T) {
	h := app.NewHTTPRequestHandler(wfHandlerNewLogger())

	input := wfHandlerNewActionInput(map[string]any{
		"method": "GET",
		// no "url" field
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing URL")
	}
	if !strings.Contains(err.Error(), "url is required") {
		t.Errorf("expected 'url is required' error, got: %v", err)
	}
}

func TestWfHandlerHTTPRequestDefaultsMethodToGET(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET default, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()

	// No "method" field - should default to GET
	input := wfHandlerNewActionInput(map[string]any{
		"url": ts.URL,
		// no method
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWfHandlerHTTPRequestInvalidMethod(t *testing.T) {
	h := wfHandlerNewTestHandler()

	// CONNECT is not in the allowed methods list
	input := wfHandlerNewActionInput(map[string]any{
		"url":    "http://example.com",
		"method": "CONNECT",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for disallowed HTTP method CONNECT")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("expected 'not allowed' error, got: %v", err)
	}
}

func TestWfHandlerHTTPRequestResponseBodyInOutput(t *testing.T) {
	responsePayload := map[string]any{
		"id":     42,
		"status": "active",
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(responsePayload)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	input := wfHandlerNewActionInput(map[string]any{
		"url":    ts.URL,
		"method": "GET",
	}, nil)

	output, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body, ok := output["body"]
	if !ok {
		t.Fatal("expected 'body' key in output")
	}

	// Body should be parsed as JSON map
	bodyMap, ok := body.(map[string]any)
	if !ok {
		t.Fatalf("expected body to be map[string]any, got %T", body)
	}
	if fmt.Sprintf("%v", bodyMap["status"]) != "active" {
		t.Errorf("expected status=active in body, got %v", bodyMap["status"])
	}
}

func TestWfHandlerHTTPRequestStatusCodeInOutput(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	input := wfHandlerNewActionInput(map[string]any{
		"url":    ts.URL,
		"method": "GET",
	}, nil)

	output, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output["status_code"] != http.StatusAccepted {
		t.Errorf("expected status_code=202, got %v", output["status_code"])
	}
}

func TestWfHandlerHTTPRequestErrorStatusReturnsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server error"}`))
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	input := wfHandlerNewActionInput(map[string]any{
		"url":    ts.URL,
		"method": "GET",
	}, nil)

	output, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for 500 status code")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to mention status 500, got: %v", err)
	}
	// Output should still be populated even on HTTP error
	if output == nil {
		t.Error("expected non-nil output even on HTTP error")
	}
}

func TestWfHandlerHTTPRequestCustomHeaders(t *testing.T) {
	var receivedAuthHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	input := wfHandlerNewActionInput(map[string]any{
		"url":    ts.URL,
		"method": "GET",
		"headers": map[string]any{
			"Authorization": "Bearer test-token-123",
		},
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedAuthHeader != "Bearer test-token-123" {
		t.Errorf("expected Authorization header 'Bearer test-token-123', got '%s'", receivedAuthHeader)
	}
}

func TestWfHandlerHTTPRequestSensitiveHeadersBlocked(t *testing.T) {
	var receivedCustomHeader string
	var receivedXForwardedFor string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCustomHeader = r.Header.Get("X-Custom-Safe")
		receivedXForwardedFor = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	input := wfHandlerNewActionInput(map[string]any{
		"url":    ts.URL,
		"method": "GET",
		"headers": map[string]any{
			"host":            "evil.example.com", // blocked — lowercase key
			"x-forwarded-for": "1.2.3.4",          // blocked
			"X-Custom-Safe":   "should-pass",       // allowed
		},
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Sensitive headers should be filtered
	if receivedXForwardedFor != "" {
		t.Errorf("expected X-Forwarded-For to be blocked, got '%s'", receivedXForwardedFor)
	}
	// Safe custom header should pass through
	if receivedCustomHeader != "should-pass" {
		t.Errorf("expected X-Custom-Safe='should-pass', got '%s'", receivedCustomHeader)
	}
}

func TestWfHandlerHTTPRequestTimeoutConfig(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()

	// Provide a custom timeout (5 seconds) — verifying config doesn't break execution
	input := wfHandlerNewActionInput(map[string]any{
		"url":     ts.URL,
		"method":  "GET",
		"timeout": float64(5),
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error with timeout config: %v", err)
	}
}

func TestWfHandlerHTTPRequestJSONBody(t *testing.T) {
	var receivedContentType string
	var receivedBody []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	// Pass a map body — should be auto-marshalled to JSON
	input := wfHandlerNewActionInput(map[string]any{
		"url":    ts.URL,
		"method": "POST",
		"body": map[string]any{
			"alert": "critical",
			"count": 5,
		},
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Content-Type should be auto-set to application/json
	if !strings.Contains(receivedContentType, "application/json") {
		t.Errorf("expected Content-Type application/json, got %s", receivedContentType)
	}

	// Body should be valid JSON
	var parsed map[string]any
	if err := json.Unmarshal(receivedBody, &parsed); err != nil {
		t.Errorf("received body is not valid JSON: %v, body=%s", err, string(receivedBody))
	}
}

// =============================================================================
// TestWfHandlerSafeInterpolate — tested via Execute (safeInterpolate is unexported)
// =============================================================================

func TestWfHandlerSafeInterpolateRunID(t *testing.T) {
	runID := shared.NewID()

	var capturedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	input := &app.ActionInput{
		TenantID:   shared.NewID(),
		WorkflowID: shared.NewID(),
		RunID:      runID,
		NodeKey:    "n1",
		ActionType: workflow.ActionTypeHTTPRequest,
		ActionConfig: map[string]any{
			"url":    ts.URL + "/runs/{{.run_id}}",
			"method": "GET",
		},
	}

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedPath := "/runs/" + runID.String()
	if capturedPath != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, capturedPath)
	}
}

func TestWfHandlerSafeInterpolateWorkflowID(t *testing.T) {
	workflowID := shared.NewID()

	var capturedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	input := &app.ActionInput{
		TenantID:   shared.NewID(),
		WorkflowID: workflowID,
		RunID:      shared.NewID(),
		NodeKey:    "n1",
		ActionType: workflow.ActionTypeHTTPRequest,
		ActionConfig: map[string]any{
			"url":    ts.URL + "/workflow/{{.workflow_id}}",
			"method": "GET",
		},
	}

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedPath := "/workflow/" + workflowID.String()
	if capturedPath != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, capturedPath)
	}
}

func TestWfHandlerSafeInterpolateNoMarkersUnchanged(t *testing.T) {
	var capturedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	input := wfHandlerNewActionInput(map[string]any{
		"url":    ts.URL + "/static/path",
		"method": "GET",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedPath != "/static/path" {
		t.Errorf("expected unchanged path /static/path, got %s", capturedPath)
	}
}

func TestWfHandlerSafeInterpolateMultipleReplacements(t *testing.T) {
	tenantID := shared.NewID()
	workflowID := shared.NewID()

	var capturedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	input := &app.ActionInput{
		TenantID:   tenantID,
		WorkflowID: workflowID,
		RunID:      shared.NewID(),
		NodeKey:    "n1",
		ActionType: workflow.ActionTypeHTTPRequest,
		ActionConfig: map[string]any{
			"url":    ts.URL + "/tenants/{{.tenant_id}}/workflows/{{.workflow_id}}",
			"method": "GET",
		},
	}

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedPath := "/tenants/" + tenantID.String() + "/workflows/" + workflowID.String()
	if capturedPath != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, capturedPath)
	}
}

func TestWfHandlerSafeInterpolateBodyString(t *testing.T) {
	var receivedBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	runID := shared.NewID()
	h := wfHandlerNewTestHandler()
	input := &app.ActionInput{
		TenantID:   shared.NewID(),
		WorkflowID: shared.NewID(),
		RunID:      runID,
		NodeKey:    "body-test",
		ActionType: workflow.ActionTypeHTTPRequest,
		ActionConfig: map[string]any{
			"url":    ts.URL,
			"method": "POST",
			"body":   `{"run_id":"{{.run_id}}"}`,
		},
	}

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedBody := `{"run_id":"` + runID.String() + `"}`
	if string(receivedBody) != expectedBody {
		t.Errorf("expected body %s, got %s", expectedBody, string(receivedBody))
	}
}

// =============================================================================
// TestWfHandlerSanitizeForLogging — tested indirectly via NodeKey in safeInterpolate
// =============================================================================

func TestWfHandlerSanitizeNodeKeyStripsNewlines(t *testing.T) {
	var capturedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	// NodeKey with newline injection attempt
	input := &app.ActionInput{
		TenantID:   shared.NewID(),
		WorkflowID: shared.NewID(),
		RunID:      shared.NewID(),
		NodeKey:    "node\ninjected",
		ActionType: workflow.ActionTypeHTTPRequest,
		ActionConfig: map[string]any{
			"url":    ts.URL + "/node/{{.node_key}}",
			"method": "GET",
		},
	}

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Newline should be replaced with underscore
	if strings.Contains(capturedPath, "\n") {
		t.Error("expected newline to be sanitized from node_key")
	}
	// "node\ninjected" → newline becomes "_" → "node_injected"
	expectedPath := "/node/node_injected"
	if capturedPath != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, capturedPath)
	}
}

func TestWfHandlerSanitizeNodeKeyTruncatesLongStrings(t *testing.T) {
	var capturedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	// NodeKey longer than 100 chars — all safe alphanumeric chars
	longKey := strings.Repeat("a", 150)
	input := &app.ActionInput{
		TenantID:   shared.NewID(),
		WorkflowID: shared.NewID(),
		RunID:      shared.NewID(),
		NodeKey:    longKey,
		ActionType: workflow.ActionTypeHTTPRequest,
		ActionConfig: map[string]any{
			"url":    ts.URL + "/node/{{.node_key}}",
			"method": "GET",
		},
	}

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The sanitized node key should be max 100 chars
	nodeKeyInPath := strings.TrimPrefix(capturedPath, "/node/")
	if len(nodeKeyInPath) > 100 {
		t.Errorf("expected node_key to be truncated to max 100 chars, got %d chars", len(nodeKeyInPath))
	}
}

func TestWfHandlerSanitizeNodeKeyShortStringUnchanged(t *testing.T) {
	var capturedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	input := &app.ActionInput{
		TenantID:   shared.NewID(),
		WorkflowID: shared.NewID(),
		RunID:      shared.NewID(),
		NodeKey:    "my-node-01",
		ActionType: workflow.ActionTypeHTTPRequest,
		ActionConfig: map[string]any{
			"url":    ts.URL + "/node/{{.node_key}}",
			"method": "GET",
		},
	}

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedPath := "/node/my-node-01"
	if capturedPath != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, capturedPath)
	}
}

func TestWfHandlerSanitizeNodeKeySpecialCharsReplaced(t *testing.T) {
	var capturedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := wfHandlerNewTestHandler()
	// NodeKey with special characters — each should be replaced with underscore
	input := &app.ActionInput{
		TenantID:   shared.NewID(),
		WorkflowID: shared.NewID(),
		RunID:      shared.NewID(),
		NodeKey:    "node@#$!",
		ActionType: workflow.ActionTypeHTTPRequest,
		ActionConfig: map[string]any{
			"url":    ts.URL + "/node/{{.node_key}}",
			"method": "GET",
		},
	}

	_, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// @, #, $, ! → each replaced with _
	expectedPath := "/node/node____"
	if capturedPath != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, capturedPath)
	}
}
