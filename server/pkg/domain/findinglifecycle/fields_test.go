package findinglifecycle

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestCheckFields(t *testing.T) {
	ok := map[string]string{
		"ticket_link":   " https://tracker.example.com/browse/SEC-1 ",
		"fix_reference": "A1B2C3D",
		"due_date":      "2026-12-31",
		"change_id":     "CHG-42",
	}
	got, err := CheckFields([]RequiredField{FieldTicketLink, FieldFixReference}, ok)
	if err != nil {
		t.Fatal(err)
	}
	if got["ticket_link"] != "https://tracker.example.com/browse/SEC-1" || got["fix_reference"] != "a1b2c3d" {
		t.Errorf("cleaned %v", got)
	}

	var missing *FieldsRequiredError
	if _, err := CheckFields([]RequiredField{FieldChangeID, FieldTargetVersion}, map[string]string{"change_id": " "}); !errors.As(err, &missing) || len(missing.Fields) != 2 {
		t.Errorf("missing fields: %v", err)
	}
	for name, given := range map[string]map[string]string{
		"unknown field":         {"password": "x"},
		"javascript link":       {"ticket_link": "javascript:alert(1)"},
		"link without host":     {"ticket_link": "https:///path"},
		"credentials in link":   {"ticket_link": "https://user:pw@example.com/x"},
		"bad date":              {"due_date": "31/12/2026"},
		"markup in change id":   {"change_id": "<b>x</b>"},
		"fix ref neither":       {"fix_reference": "not a link"},
		"long compensating ctl": {"compensating_control": string(make([]byte, 201))},
	} {
		if _, err := CheckFields(nil, given); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
