// Package adapters provides a registry for scanner output adapters.
// Each adapter converts a specific scanner's output format to CTIS.
package adapters

import (
	"context"
	"fmt"
	"sync"

	"github.com/openctemio/api/internal/infra/adapters/core"
	"github.com/openctemio/api/internal/infra/adapters/gitleaks"
	"github.com/openctemio/api/internal/infra/adapters/nuclei"
	"github.com/openctemio/api/internal/infra/adapters/recon"
	"github.com/openctemio/api/internal/infra/adapters/sarif"
	"github.com/openctemio/api/internal/infra/adapters/semgrep"
	"github.com/openctemio/api/internal/infra/adapters/trivy"
	"github.com/openctemio/api/internal/infra/adapters/vuls"
	"github.com/openctemio/ctis"
)

// Registry manages registered scanner adapters.
type Registry struct {
	adapters map[string]core.Adapter
	mu       sync.RWMutex
}

// NewRegistry creates a new adapter registry with built-in adapters.
func NewRegistry() *Registry {
	r := &Registry{
		adapters: make(map[string]core.Adapter),
	}

	// Register built-in adapters.
	// P0-1: SARIF adapter (661 LoC built, previously unregistered — a "fake
	// CTEM signal" per the framework audit). Now wired so SAST/DAST tools
	// that emit SARIF (CodeQL, Bandit, various IDE integrations) are
	// ingestible without bespoke code.
	r.Register(trivy.NewAdapter())
	r.Register(nuclei.NewAdapter())
	r.Register(semgrep.NewAdapter())
	r.Register(gitleaks.NewAdapter())
	r.Register(vuls.NewAdapter())
	r.Register(sarif.NewAdapter())
	// Recon adapter — subdomain/DNS/port/http_probe/url_crawl outputs
	// go through the same unified ingest path as vuln scanners.
	r.Register(recon.NewAdapter())

	return r
}

// Register adds an adapter to the registry.
func (r *Registry) Register(adapter core.Adapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adapters[adapter.Name()] = adapter
}

// Get returns an adapter by name.
func (r *Registry) Get(name string) (core.Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[name]
	return a, ok
}

// List returns all registered adapter names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.adapters))
	for name := range r.adapters {
		names = append(names, name)
	}
	return names
}

// AutoDetect tries to find an adapter that can convert the input.
func (r *Registry) AutoDetect(input []byte) (core.Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, adapter := range r.adapters {
		if adapter.CanConvert(input) {
			return adapter, true
		}
	}
	return nil, false
}

// Convert uses the specified adapter (or auto-detects) to convert input to CTIS.
func (r *Registry) Convert(ctx context.Context, scannerType string, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	var adapter core.Adapter

	if scannerType != "" {
		var ok bool
		adapter, ok = r.Get(scannerType)
		if !ok {
			return nil, fmt.Errorf("unknown scanner type: %s, supported: %v", scannerType, r.List())
		}
	} else {
		var ok bool
		adapter, ok = r.AutoDetect(input)
		if !ok {
			return nil, fmt.Errorf("could not auto-detect scanner format, please specify scanner_type")
		}
	}

	return adapter.Convert(ctx, input, opts)
}
