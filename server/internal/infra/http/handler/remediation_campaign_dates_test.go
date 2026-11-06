package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A PATCH date is absent (unchanged), null (clear) or a string the service
// parses; any other JSON value is a 400, never ignored.
func TestOptionalDateField(t *testing.T) {
	cases := []struct {
		raw     string
		want    *string
		wantErr bool
	}{
		{raw: "", want: nil},
		{raw: "null", want: strPtr("")},
		{raw: `"2026-10-31"`, want: strPtr("2026-10-31")},
		{raw: "20261031", wantErr: true},
		{raw: `{"d":1}`, wantErr: true},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		got, ok := optionalDateField(rec, "due_date", json.RawMessage(c.raw))
		if c.wantErr {
			if ok || rec.Code != http.StatusBadRequest {
				t.Fatalf("%q: ok=%v status=%d, want a 400", c.raw, ok, rec.Code)
			}
			continue
		}
		if !ok {
			t.Fatalf("%q: refused", c.raw)
		}
		if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
			t.Fatalf("%q: got %v, want %v", c.raw, got, c.want)
		}
	}
}

func strPtr(s string) *string { return &s }
