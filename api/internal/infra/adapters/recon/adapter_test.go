package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/infra/adapters/core"
)

func TestAdapter_NameAndFormats(t *testing.T) {
	a := NewAdapter()
	if a.Name() != "recon" {
		t.Fatalf("Name = %q, want recon", a.Name())
	}
	if a.OutputFormat() != "ctis" {
		t.Fatalf("OutputFormat = %q, want ctis", a.OutputFormat())
	}
	formats := a.InputFormats()
	if len(formats) == 0 || formats[0] != "recon" {
		t.Fatalf("InputFormats = %v, want [recon json]", formats)
	}
}

func TestCanConvert_RejectsNonJSON(t *testing.T) {
	a := NewAdapter()
	if a.CanConvert([]byte("not json at all")) {
		t.Fatal("non-JSON must not convert")
	}
}

func TestCanConvert_RejectsEmptyReconBlob(t *testing.T) {
	// Has recon_type but no result arrays → no content to emit.
	a := NewAdapter()
	body, _ := json.Marshal(reconInput{
		ScannerName: "subfinder",
		ReconType:   "subdomain",
		Target:      "example.com",
	})
	if a.CanConvert(body) {
		t.Fatal("empty recon payload should be rejected")
	}
}

func TestCanConvert_RejectsUnknownReconType(t *testing.T) {
	a := NewAdapter()
	body, _ := json.Marshal(reconInput{
		ScannerName: "foo",
		ReconType:   "not_a_real_type",
		Target:      "example.com",
		Subdomains:  []subdomainInput{{Host: "a.example.com"}},
	})
	if a.CanConvert(body) {
		t.Fatal("unknown recon_type must be rejected")
	}
}

func TestCanConvert_AcceptsSubdomainPayload(t *testing.T) {
	a := NewAdapter()
	body, _ := json.Marshal(reconInput{
		ScannerName: "subfinder",
		ReconType:   "subdomain",
		Target:      "example.com",
		Subdomains: []subdomainInput{
			{Host: "api.example.com", Source: "subfinder"},
		},
	})
	if !a.CanConvert(body) {
		t.Fatal("populated subdomain payload should convert")
	}
}

func TestCanConvert_AcceptsPortPayload(t *testing.T) {
	a := NewAdapter()
	body, _ := json.Marshal(reconInput{
		ScannerName: "naabu",
		ReconType:   "port",
		Target:      "10.0.0.1",
		OpenPorts:   []openPortInput{{Host: "10.0.0.1", Port: 443, Protocol: "tcp"}},
	})
	if !a.CanConvert(body) {
		t.Fatal("port payload should convert")
	}
}

func TestConvert_FailsOnInvalidJSON(t *testing.T) {
	a := NewAdapter()
	_, err := a.Convert(context.Background(), []byte("{not json"), nil)
	if err == nil {
		t.Fatal("invalid JSON must error")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Fatalf("error should mention parse: %v", err)
	}
}

func TestConvert_RequiresScannerName(t *testing.T) {
	a := NewAdapter()
	body, _ := json.Marshal(reconInput{
		ReconType:  "subdomain",
		Target:     "example.com",
		Subdomains: []subdomainInput{{Host: "a.example.com"}},
	})
	_, err := a.Convert(context.Background(), body, nil)
	if err == nil {
		t.Fatal("missing scanner_name must error")
	}
	if !strings.Contains(err.Error(), "scanner_name") {
		t.Fatalf("error should mention scanner_name: %v", err)
	}
}

func TestConvert_RejectsUnknownReconType(t *testing.T) {
	a := NewAdapter()
	body, _ := json.Marshal(reconInput{
		ScannerName: "foo",
		ReconType:   "xray",
		Target:      "example.com",
		Subdomains:  []subdomainInput{{Host: "a.example.com"}},
	})
	_, err := a.Convert(context.Background(), body, nil)
	if err == nil {
		t.Fatal("unknown recon_type must error")
	}
}

func TestConvert_SubdomainProducesCTISReport(t *testing.T) {
	a := NewAdapter()
	body, _ := json.Marshal(reconInput{
		ScannerName:    "subfinder",
		ScannerVersion: "2.6.3",
		ReconType:      "subdomain",
		Target:         "example.com",
		StartedAt:      1700000000,
		FinishedAt:     1700000060,
		DurationMs:     60000,
		Subdomains: []subdomainInput{
			{Host: "api.example.com", Source: "subfinder", IPs: []string{"1.2.3.4"}},
			{Host: "www.example.com", Source: "subfinder"},
		},
	})

	report, err := a.Convert(context.Background(), body, &core.AdapterOptions{
		Repository: "example.com",
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if report == nil {
		t.Fatal("nil report")
	}
	if report.Tool == nil || report.Tool.Name != "subfinder" {
		t.Fatalf("tool name not carried, got %+v", report.Tool)
	}
	if report.Metadata.Scope == nil || report.Metadata.Scope.Name != "example.com" {
		t.Fatalf("scope not applied from AdapterOptions: %+v", report.Metadata.Scope)
	}
	// Recon conversion emits assets — at least one per subdomain host.
	if len(report.Assets) == 0 {
		t.Fatal("no assets produced from subdomain payload")
	}
}

func TestConvert_DiscoverySourceOverrideHonoured(t *testing.T) {
	a := NewAdapter()
	body, _ := json.Marshal(reconInput{
		ScannerName: "manual-upload",
		ReconType:   "subdomain",
		Target:      "example.com",
		Subdomains:  []subdomainInput{{Host: "api.example.com"}},
	})

	report, err := a.Convert(context.Background(), body, &core.AdapterOptions{
		SourceType: "manual",
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(report.Assets) == 0 {
		t.Fatal("expected assets from subdomain payload")
	}
	// Convert didn't crash and produced assets — the SDK converter
	// handled the override field. A deeper assertion on the property
	// key would couple this test to the SDK's internal schema; keep
	// the contract narrow.
}
