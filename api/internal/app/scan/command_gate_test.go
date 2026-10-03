package scan

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Scan commands created through POST /api/v1/commands get the target checks
// of a scan trigger (RFC-040 Q5 (c)).

type gateZones struct {
	zones []*scanzone.Zone
	err   error
}

func (g *gateZones) List(context.Context, shared.ID) ([]*scanzone.Zone, error) { return g.zones, g.err }

func (g *gateZones) RoutableSensors(context.Context, shared.ID, []shared.ID, string) (map[shared.ID][]scanzone.SensorCandidate, error) {
	return nil, nil
}

func gateService(excl ScopeExclusionFilter, zones ZoneDirectory) *Service {
	return &Service{scopeExclusions: excl, zones: zones, logger: logger.NewNop()}
}

func mustZone(t *testing.T, tenantID shared.ID, name string, ranges []string, sensors ...shared.ID) *scanzone.Zone {
	t.Helper()
	z, err := scanzone.NewZone(tenantID, name, "", false, ranges, nil)
	if err != nil {
		t.Fatal(err)
	}
	z.SensorIDs = sensors
	return z
}

func requireRefused(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("command accepted, want refusal containing %q", contains)
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("refusal must be a validation error (400), got %v", err)
	}
	if contains != "" && !strings.Contains(err.Error(), contains) {
		t.Fatalf("refusal %q does not mention %q", err.Error(), contains)
	}
}

func TestGateCommandPayload_InScopeTargetAccepted(t *testing.T) {
	svc := gateService(&stubExclusions{values: map[string]bool{"excluded.example.com": true}}, nil)
	got, err := svc.GateCommandPayload(context.Background(), shared.NewID(), nil,
		json.RawMessage(`{"scanner":"nuclei","target":"app.example.com","targets":["app.example.com"," api.example.com "]}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"app.example.com", "api.example.com"}; !reflect.DeepEqual(got.Targets, want) {
		t.Fatalf("targets = %v, want %v", got.Targets, want)
	}
	if got.ScanZoneID != nil {
		t.Fatalf("no zones: zone = %v, want nil", got.ScanZoneID)
	}
	var p map[string]any
	if err := json.Unmarshal(got.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if _, has := p["target"]; has {
		t.Fatalf("nuclei takes the list: payload must not keep a single target: %s", got.Payload)
	}
	if p["scanner"] != "nuclei" || len(p["targets"].([]any)) != 2 {
		t.Fatalf("payload not rewritten to the checked list: %s", got.Payload)
	}
}

func TestGateCommandPayload_ExcludedTargetRefused(t *testing.T) {
	svc := gateService(&stubExclusions{values: map[string]bool{"payroll.example.com": true}}, nil)
	_, err := svc.GateCommandPayload(context.Background(), shared.NewID(), nil,
		json.RawMessage(`{"scanner":"nuclei","targets":["app.example.com","payroll.example.com"]}`))
	requireRefused(t, err, "payroll.example.com")
	if !errors.Is(err, ErrCommandTargetRefused) {
		t.Fatalf("want ErrCommandTargetRefused, got %v", err)
	}
}

func TestGateCommandPayload_PrivateTargetWithoutZoneRefused(t *testing.T) {
	svc := gateService(&stubExclusions{}, nil)
	for _, target := range []string{"10.0.0.5", "192.168.1.0/24", "127.0.0.1", "169.254.169.254", "localhost"} {
		_, err := svc.GateCommandPayload(context.Background(), shared.NewID(), nil,
			json.RawMessage(`{"scanner":"nmap","target":"`+target+`"}`))
		requireRefused(t, err, "")
	}
}

func TestGateCommandPayload_FailsClosed(t *testing.T) {
	ctx := context.Background()
	body := json.RawMessage(`{"scanner":"nuclei","target":"app.example.com"}`)

	if _, err := gateService(nil, nil).GateCommandPayload(ctx, shared.NewID(), nil, body); err == nil {
		t.Fatal("no exclusion filter: command accepted, want refusal")
	}
	if _, err := gateService(&stubExclusions{err: errors.New("db down")}, nil).GateCommandPayload(ctx, shared.NewID(), nil, body); err == nil {
		t.Fatal("exclusion lookup failed: command accepted, want refusal")
	}
	if _, err := gateService(&stubExclusions{}, &gateZones{err: errors.New("db down")}).GateCommandPayload(ctx, shared.NewID(), nil, body); err == nil {
		t.Fatal("zone lookup failed: command accepted, want refusal")
	}
}

func TestGateCommandPayload_PayloadShape(t *testing.T) {
	svc := gateService(&stubExclusions{}, nil)
	for name, body := range map[string]string{
		"empty":                ``,
		"not an object":        `["app.example.com"]`,
		"no target":            `{"scanner":"nuclei"}`,
		"blank target":         `{"scanner":"nuclei","target":"  "}`,
		"target not a string":  `{"scanner":"nuclei","target":["a.example.com"]}`,
		"targets not strings":  `{"scanner":"nuclei","targets":[1]}`,
		"targets in config":    `{"scanner":"nuclei","target":"app.example.com","config":{"targets":["10.0.0.5"]}}`,
		"target in context":    `{"scanner":"nuclei","target":"app.example.com","context":{"target":"10.0.0.5"}}`,
		"targets in scan conf": `{"scanner":"nuclei","target":"app.example.com","scanner_config":{"targets":["10.0.0.5"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := svc.GateCommandPayload(context.Background(), shared.NewID(), nil, json.RawMessage(body))
			requireRefused(t, err, "")
		})
	}
}

func TestGateCommandPayload_Zones(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	inZone, outside := shared.NewID(), shared.NewID()
	lab := mustZone(t, tenantID, "lab", []string{"10.10.0.0/16"}, inZone)
	office := mustZone(t, tenantID, "office", []string{"10.20.0.0/16"})
	svc := gateService(&stubExclusions{}, &gateZones{zones: []*scanzone.Zone{lab, office}})

	t.Run("zoned private target, unpinned: stamped with the zone", func(t *testing.T) {
		got, err := svc.GateCommandPayload(ctx, tenantID, nil, json.RawMessage(`{"scanner":"nmap","target":"10.10.1.5"}`))
		if err != nil {
			t.Fatal(err)
		}
		if got.ScanZoneID == nil || *got.ScanZoneID != lab.ID {
			t.Fatalf("zone = %v, want %s", got.ScanZoneID, lab.ID)
		}
	})
	t.Run("pinned sensor in the zone", func(t *testing.T) {
		got, err := svc.GateCommandPayload(ctx, tenantID, &inZone, json.RawMessage(`{"scanner":"nmap","target":"10.10.1.5"}`))
		if err != nil {
			t.Fatal(err)
		}
		if got.ScanZoneID == nil || *got.ScanZoneID != lab.ID {
			t.Fatalf("zone = %v, want %s", got.ScanZoneID, lab.ID)
		}
	})
	t.Run("pinned sensor outside the zone", func(t *testing.T) {
		_, err := svc.GateCommandPayload(ctx, tenantID, &outside, json.RawMessage(`{"scanner":"nmap","target":"10.10.1.5"}`))
		requireRefused(t, err, "not assigned")
	})
	t.Run("private address outside every zone", func(t *testing.T) {
		_, err := svc.GateCommandPayload(ctx, tenantID, nil, json.RawMessage(`{"scanner":"nmap","target":"10.30.0.1"}`))
		requireRefused(t, err, "")
	})
	t.Run("targets in two zones", func(t *testing.T) {
		_, err := svc.GateCommandPayload(ctx, tenantID, nil, json.RawMessage(`{"scanner":"nuclei","targets":["10.10.1.5","10.20.1.5"]}`))
		requireRefused(t, err, "more than one scan zone")
	})
	t.Run("zoned next to unzoned", func(t *testing.T) {
		_, err := svc.GateCommandPayload(ctx, tenantID, nil, json.RawMessage(`{"scanner":"nuclei","targets":["10.10.1.5","198.51.100.7"]}`))
		requireRefused(t, err, "more than one scan zone")
	})
	t.Run("public target in a zoned tenant stays unzoned", func(t *testing.T) {
		got, err := svc.GateCommandPayload(ctx, tenantID, &outside, json.RawMessage(`{"scanner":"nuclei","target":"198.51.100.7"}`))
		if err != nil {
			t.Fatal(err)
		}
		if got.ScanZoneID != nil {
			t.Fatalf("zone = %v, want nil", got.ScanZoneID)
		}
	})
}
