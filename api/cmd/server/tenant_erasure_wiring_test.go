package main

import (
	"os"
	"strings"
	"testing"
)

// Organization deletion erases stored files only through the seam
// TenantService.SetBlobEraser, which nil-guards: forgetting the call in the
// composition root would delete the rows and silently leave every attachment
// of a deleted organization on disk or in the bucket.
func TestTenantDeletion_StoredFileErasureIsWired(t *testing.T) {
	src, err := os.ReadFile("services.go")
	if err != nil {
		t.Fatalf("read services.go: %v", err)
	}
	if !strings.Contains(string(src), "s.Tenant.SetBlobEraser(s.Attachment)") {
		t.Fatal("services.go does not wire s.Tenant.SetBlobEraser(s.Attachment): " +
			"deleting an organization would leave its stored files behind")
	}
}
