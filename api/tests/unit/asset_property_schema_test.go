package unit

import (
	"context"
	"errors"
	"slices"
	"sort"
	"testing"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The REST create and update paths apply the property schema (RFC-042
// §6.3.9): synonyms fold into their canonical key, and a key only another
// class may hold (a port on a domain) is refused, not stored.

func propStrings(v any) []string {
	var out []string
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, x...)
	}
	sort.Strings(out)
	return out
}

func TestAssetService_CreateAsset_FoldsPropertySynonyms(t *testing.T) {
	svc, _ := newTestService()
	a, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID: serviceTenantID.String(), Name: "schema.example.com", Type: "domain", Criticality: "low",
		Properties: map[string]any{
			"resolvedIps": "192.0.2.1, 192.0.2.2",
			"ip":          "192.0.2.1",
			"nameserver":  "ns1.example.com",
			"domain": map[string]any{"dns_records": []any{
				map[string]any{"type": "A", "value": "192.0.2.3"},
				map[string]any{"type": "CNAME", "value": "edge.example.net"},
			}},
		},
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	p := a.Properties()
	if got := propStrings(p[asset.PropKeyIPAddresses]); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}) {
		t.Errorf("ip_addresses = %v", got)
	}
	if got := propStrings(p["nameservers"]); !slices.Equal(got, []string{"ns1.example.com"}) {
		t.Errorf("nameservers = %v", got)
	}
	for _, k := range []string{"resolved_ips", "resolved_ip", "ip", "nameserver"} {
		if _, ok := p[k]; ok {
			t.Errorf("synonym %q stored: %v", k, p)
		}
	}
}

func TestAssetService_CreateAsset_RefusesMisplacedProperty(t *testing.T) {
	svc, repo := newTestService()
	_, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID: serviceTenantID.String(), Name: "port.example.com", Type: "domain", Criticality: "low",
		Properties: map[string]any{"port": 443},
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a port on a domain: err = %v, want a validation error", err)
	}
	if repo.createCalls != 0 {
		t.Errorf("the asset was stored anyway")
	}
	// The same key on a service is its own.
	if _, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID: serviceTenantID.String(), Name: "port.example.com:443", Type: "service", Criticality: "low",
		Properties: map[string]any{"port": 443},
	}); err != nil {
		t.Fatalf("a port on a service: %v", err)
	}
}

func TestAssetService_UpdateAsset_RefusesMisplacedPropertyAndFolds(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()
	host := createAssetForTest(t, svc, tenantID, "schema-host-01")

	_, err := svc.UpdateAsset(context.Background(), host.ID().String(), tenantID,
		assetapp.UpdateAssetInput{Properties: map[string]any{"status_code": 200}})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an HTTP status on a host: err = %v, want a validation error", err)
	}

	updated, err := svc.UpdateAsset(context.Background(), host.ID().String(), tenantID,
		assetapp.UpdateAssetInput{Properties: map[string]any{"ips": []any{"198.51.100.1"}}})
	if err != nil {
		t.Fatalf("UpdateAsset: %v", err)
	}
	p := updated.Properties()
	if got := propStrings(p[asset.PropKeyIPAddresses]); !slices.Equal(got, []string{"198.51.100.1"}) {
		t.Errorf("ip_addresses = %v", got)
	}
	if _, ok := p["ips"]; ok {
		t.Errorf("synonym stored on update: %v", p)
	}
}
