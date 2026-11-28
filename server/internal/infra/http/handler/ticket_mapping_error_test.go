package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appticketmap "github.com/openctemio/openctem/server/internal/app/ticketmap"
	"github.com/openctemio/openctem/server/internal/infra/jira"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	ticketmapdom "github.com/openctemio/openctem/server/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type errBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details struct {
		Params map[string]string `json:"params"`
	} `json:"details"`
}

func failBody(t *testing.T, err error) (int, errBody) {
	t.Helper()
	h := &TicketMappingHandler{logger: logger.NewNop()}
	rec := httptest.NewRecorder()
	h.fail(rec, err)
	var b errBody
	if e := json.Unmarshal(rec.Body.Bytes(), &b); e != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), e)
	}
	return rec.Code, b
}

// A refused ticket mapping says which field is wrong and why
// (TICKET_MAPPING_INVALID_FIELD, details.params.field), never the generic
// "Invalid request".
func TestTicketMappingHandler_FieldErrorsNameTheField(t *testing.T) {
	tenant, intg := shared.NewID(), shared.NewID()
	cases := []struct {
		name  string
		err   error
		field string
	}{
		{"object kind", func() error {
			_, err := ticketmapdom.NewProfile(tenant, intg, "remediation_task", "10000", "SEC", "10002", "Task", "", nil)
			return err
		}(), "object_kind"},
		{"no issue type id", func() error {
			_, err := ticketmapdom.NewProfile(tenant, intg, ticketmapdom.ObjectFinding, "", "SEC", "", "Bug", "", nil)
			return err
		}(), "issue_type_id"},
		{"no project key", func() error {
			_, err := ticketmapdom.NewProfile(tenant, intg, ticketmapdom.ObjectFinding, "", "", "10004", "Bug", "", nil)
			return err
		}(), "project_key"},
		{"long name", func() error {
			_, err := ticketmapdom.NewProfile(tenant, intg, ticketmapdom.ObjectFinding, "", "SEC", "10004", "Bug", strings.Repeat("n", 121), nil)
			return err
		}(), "name"},
		{"wrapped", fmt.Errorf("create: %w", ticketmapdom.FieldInvalid("preset", "it is not a preset of this object kind")), "preset"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, b := failBody(t, c.err)
			if status != http.StatusBadRequest || b.Code != "TICKET_MAPPING_INVALID_FIELD" || b.Details.Params["field"] != c.field {
				t.Fatalf("got %d %s %+v, want 400 TICKET_MAPPING_INVALID_FIELD field=%s", status, b.Code, b.Details.Params, c.field)
			}
			if !strings.Contains(b.Message, c.field) || b.Message == "Invalid request" {
				t.Fatalf("message %q does not name %s", b.Message, c.field)
			}
		})
	}
}

// An integration that is not a connected Jira site has its own code: the
// fields are fine, the destination is not ready.
func TestTicketMappingHandler_TrackerNotConnected(t *testing.T) {
	for _, err := range []error{jira.ErrNotATracker, fmt.Errorf("x: %w", appticketmap.ErrTrackerNotConnected)} {
		status, b := failBody(t, err)
		if status != http.StatusConflict || b.Code != "TICKET_MAPPING_TRACKER_NOT_CONNECTED" {
			t.Fatalf("got %d %s, want 409 TICKET_MAPPING_TRACKER_NOT_CONNECTED", status, b.Code)
		}
	}
}
