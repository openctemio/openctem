package handler

import (
	"encoding/json"
	"testing"
)

// expires_at on PUT /secret-store/{id}: absent = unchanged, null or "" =
// clear, RFC 3339 = set. A bare date is refused with a message that says the
// format (the UI used to send one and got an opaque 400).
func TestParseOptionalExpiry(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		set     bool
		hasTime bool
		wantErr bool
	}{
		{"absent", "", false, false, false},
		{"null clears", "null", true, false, false},
		{"empty string clears", `""`, true, false, false},
		{"rfc3339 sets", `"2030-01-02T23:59:59Z"`, true, true, false},
		{"bare date refused", `"2030-01-02"`, false, false, true},
		{"number refused", `42`, false, false, true},
	}
	for _, tc := range cases {
		got, err := parseOptionalExpiry(json.RawMessage(tc.raw))
		if (err != nil) != tc.wantErr {
			t.Fatalf("%s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
		if tc.wantErr {
			continue
		}
		if got.Set != tc.set || (got.Value != nil) != tc.hasTime {
			t.Fatalf("%s: got %+v", tc.name, got)
		}
	}
}
