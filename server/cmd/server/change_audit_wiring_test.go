package main

import (
	"os"
	"strings"
	"testing"
)

// The handlers that audit changes to what sensors scan and run take their
// audit service through a setter; an unwired setter audits nothing and fails
// nowhere (RFC-040 §5.11). The route tests wire it themselves, so check the
// composition root here.
func TestChangeAuditIsWiredForScopeToolsAndTemplates(t *testing.T) {
	src, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{
		"handlers.Scope.SetAuditService(svc.Audit)",
		"handlers.Tool.SetAuditService(svc.Audit)",
		"handlers.ScannerTemplate.SetAuditService(svc.Audit)",
		"handlers.AssetOwner.SetAuditService(svc.Audit)",
	} {
		if !strings.Contains(string(src), call) {
			t.Errorf("cmd/server/handlers.go does not call %s", call)
		}
	}
}
