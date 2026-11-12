package server

import (
	"os"
	"strings"
	"testing"
)

// The exploration lead handler is built only when the scan policy service
// exists, and that service is created by wireScopeApprovers inside
// NewHandlers. Building the handler in the Handlers literal, before that
// call, left it nil: every /api/v1/exploration/leads and /summary request
// answered 404 on a running API with no error anywhere.
func TestExplorationLeadHandlerBuiltAfterScanPolicyIsWired(t *testing.T) {
	b, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	wire := strings.Index(src, "\twireScopeApprovers(svc, repos,")
	build := strings.Index(src, "newExplorationLeadHandler(deps.DB, svc, log)")
	if wire < 0 || build < 0 {
		t.Fatalf("anchors missing (wire=%d build=%d)", wire, build)
	}
	if build < wire {
		t.Fatal("newExplorationLeadHandler is called before wireScopeApprovers: svc.ScanPolicy is still nil, so the handler is nil and its routes are never registered")
	}
}
