package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// A command's result settles the scan run step its payload names
// (scan_run_id + step_key). Only the platform sets those keys when it plans a
// run: a command created through POST /api/v1/commands that carried another
// organization's run id could complete or fail that organization's step.

func TestPayloadCarriesStepRouting(t *testing.T) {
	cases := map[string]struct {
		payload string
		want    bool
	}{
		"empty":           {``, false},
		"plain scan":      {`{"scanner":"httpx","targets":["a.example.test"]}`, false},
		"run id":          {`{"scan_run_id":"01a17000-0000-7000-8000-000000000001"}`, true},
		"step key":        {`{"step_key":"probe"}`, true},
		"step run id":     {`{"scan_run_step_id":"01a17000-0000-7000-8000-000000000002"}`, true},
		"empty run id":    {`{"scan_run_id":""}`, true},
		"nested only":     {`{"config":{"scan_run_id":"x"}}`, false},
		"not an object":   {`["scan_run_id"]`, false},
		"text mentioning": {`{"note":"scan_run_id"}`, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := payloadCarriesStepRouting(json.RawMessage(tc.payload)); got != tc.want {
				t.Fatalf("payloadCarriesStepRouting(%s) = %v, want %v", tc.payload, got, tc.want)
			}
		})
	}
}

func TestCommandCreate_StepRoutingKeysRefused(t *testing.T) {
	// The service is nil: the refusal must come before it is reached (a
	// panic fails the test otherwise). Administrators are refused too: the
	// keys are the platform's, whoever sends them.
	h := NewCommandHandler(nil, validator.New(), logger.NewNop())
	for _, typ := range []string{"scan", "collect", "config_update"} {
		t.Run(typ, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"type": typ,
				"payload": map[string]any{
					"scanner":     "httpx",
					"targets":     []string{"a.example.test"},
					"scan_run_id": "01a17000-0000-7000-8000-000000000001",
					"step_key":    "probe",
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.WithValue(context.Background(), middleware.IsAdminKey, true)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/commands", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			h.Create(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
		})
	}
}
