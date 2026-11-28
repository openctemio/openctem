package apierror

import "testing"

// NotFound names a resource or carries a whole sentence; either way the reply
// says "not found" once.
func TestNotFound_SaysNotFoundOnce(t *testing.T) {
	cases := map[string]string{
		"":                     "Resource not found",
		"Asset":                "Asset not found",
		"Saved view":           "Saved view not found",
		"Attachment not found": "Attachment not found",
		"credential not found": "credential not found",
		"Credential Not Found": "Credential Not Found",
		" Finding ":            "Finding not found",
		"source_finding_id not found in this tenant":       "source_finding_id not found in this tenant",
		"No risk change request is waiting for this asset": "No risk change request is waiting for this asset",
	}
	for in, want := range cases {
		got := NotFound(in)
		if got.Message != want {
			t.Errorf("NotFound(%q) message %q, want %q", in, got.Message, want)
		}
		if got.Status != 404 || got.Code != CodeNotFound {
			t.Errorf("NotFound(%q) = %d %s, want 404 %s", in, got.Status, got.Code, CodeNotFound)
		}
	}
}
