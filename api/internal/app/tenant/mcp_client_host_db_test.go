package tenant_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Approving an AI application publisher adds its host to the MCP policy
// without touching the rest of the policy, once, and within the host cap.
func TestAllowMCPClientHost(t *testing.T) {
	f := newSettingsFixture(t)
	ctx := context.Background()
	if _, err := f.svc.UpdateMCPSettings(ctx, f.tenantID, tenantdom.MCPSettings{ClientHosts: []string{"a.example"}, RefreshDays: 7}, noAudit()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := f.svc.AllowMCPClientHost(ctx, f.tenantID, "claude.example", noAudit()); err != nil {
			t.Fatal(err)
		}
	}
	got, err := f.svc.GetMCPSettings(ctx, f.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.ClientHosts, []string{"a.example", "claude.example"}) || got.RefreshDays != 7 {
		t.Fatalf("policy after approval: %+v", got)
	}
	if err := f.svc.AllowMCPClientHost(ctx, f.tenantID, "https://bad.example/x", noAudit()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid host accepted: %v", err)
	}
	full := make([]string, 0, tenantdom.MaxMCPClientHosts)
	for i := range tenantdom.MaxMCPClientHosts {
		full = append(full, "h"+string(rune('a'+i%26))+string(rune('a'+i/26))+".example")
	}
	if _, err := f.svc.UpdateMCPSettings(ctx, f.tenantID, tenantdom.MCPSettings{ClientHosts: full}, noAudit()); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.AllowMCPClientHost(ctx, f.tenantID, "one-more.example", noAudit()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("host cap not applied: %v", err)
	}
}
