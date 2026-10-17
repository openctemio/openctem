package main

import "testing"

// Each operator command in the API image is a link to the server binary:
// the link's name selects the command, and any other name runs the server.
func TestToolFor(t *testing.T) {
	for _, argv0 := range []string{
		"/app/bootstrap-admin", "./refingerprint", "repomerge", "/app/ci-trust-scope-plan",
	} {
		if toolFor(argv0) == nil {
			t.Errorf("toolFor(%q) = nil, want the command", argv0)
		}
	}
	for _, argv0 := range []string{"/app/server", "./server", "server", "", "/app/bootstrap-admin/x", "bootstrap-admin.exe"} {
		if toolFor(argv0) != nil {
			t.Errorf("toolFor(%q) runs a command, want the server", argv0)
		}
	}
}
