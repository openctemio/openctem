package connector

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// registry + framework-level tests.

// stubConnector is a minimal Connector for registry tests.
type stubConnector struct {
	provider Provider
	assets   []DiscoveredAsset
	discErr  error
}

func (s *stubConnector) Provider() Provider                              { return s.provider }
func (s *stubConnector) Validate(_ context.Context, _ Credentials) error { return nil }
func (s *stubConnector) Discover(_ context.Context, tid shared.ID, _ Credentials) (*DiscoveryResult, error) {
	if s.discErr != nil {
		return nil, s.discErr
	}
	return &DiscoveryResult{Provider: s.provider, TenantID: tid, Assets: s.assets}, nil
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubConnector{provider: ProviderAWS})
	r.Register(&stubConnector{provider: ProviderGCP})

	if _, ok := r.Get(ProviderAWS); !ok {
		t.Fatal("aws not registered")
	}
	if _, ok := r.Get(ProviderGCP); !ok {
		t.Fatal("gcp not registered")
	}
	if _, ok := r.Get(ProviderAzure); ok {
		t.Fatal("azure must not be registered")
	}
}

func TestRegistry_ProvidersList(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubConnector{provider: ProviderAWS})
	r.Register(&stubConnector{provider: ProviderGCP})
	list := r.Providers()
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
}

func TestRegistry_Run_DispatchesToConnector(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubConnector{provider: ProviderAWS, assets: []DiscoveredAsset{{ExternalID: "e-1"}}})

	res, err := r.Run(context.Background(), ProviderAWS, shared.NewID(), Credentials{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Assets) != 1 || res.Assets[0].ExternalID != "e-1" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestRegistry_Run_UnknownProvider(t *testing.T) {
	r := NewRegistry()
	_, err := r.Run(context.Background(), "not-a-provider", shared.NewID(), Credentials{})
	if !errors.Is(err, ErrProviderNotRegistered) {
		t.Fatalf("want ErrProviderNotRegistered, got %v", err)
	}
}

func TestRegistry_Register_Replaces(t *testing.T) {
	// Replacing is explicitly allowed — tests frequently re-register.
	r := NewRegistry()
	r.Register(&stubConnector{provider: ProviderAWS, assets: []DiscoveredAsset{{ExternalID: "old"}}})
	r.Register(&stubConnector{provider: ProviderAWS, assets: []DiscoveredAsset{{ExternalID: "new"}}})
	res, _ := r.Run(context.Background(), ProviderAWS, shared.NewID(), Credentials{})
	if res.Assets[0].ExternalID != "new" {
		t.Fatalf("replacement didn't take")
	}
}
