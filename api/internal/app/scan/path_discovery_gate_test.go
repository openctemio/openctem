package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeTriggerGate struct {
	on      bool
	refused map[string]string
}

func (g fakeTriggerGate) PathDiscoveryEnabled(context.Context, shared.ID) (bool, error) {
	return g.on, nil
}
func (g fakeTriggerGate) PathDiscoveryRefusals(context.Context, shared.ID, []string) (map[string]string, error) {
	return g.refused, nil
}

func singleScan(t *testing.T, tool string) *scan.Scan {
	t.Helper()
	sc, err := scan.NewScan(shared.NewID(), "s", shared.ID{}, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.SetSingleScanner(tool, map[string]any{}, 1); err != nil {
		t.Fatal(err)
	}
	return sc
}

// SECURITY: a path discovery scan started by a person is refused at trigger
// when the organization turned path discovery off, when the shared gate
// refuses its origins, and when no gate is wired; any other scan is never
// asked.
func TestRefusePathDiscovery_AtTrigger(t *testing.T) {
	ctx := context.Background()
	targets := []string{"https://app.example.com"}
	code := func(err error) string {
		var de *shared.DomainError
		if errors.As(err, &de) {
			return de.Code
		}
		return ""
	}
	disc := singleScan(t, "webguess")

	if err := (&Service{}).refusePathDiscovery(ctx, singleScan(t, "nuclei"), targets); err != nil {
		t.Fatalf("another scan was refused: %v", err)
	}
	if got := code((&Service{}).refusePathDiscovery(ctx, disc, targets)); got != CodePathDiscoveryRefused {
		t.Fatalf("unwired: %q", got)
	}
	s := &Service{pathGate: fakeTriggerGate{on: false}}
	if got := code(s.refusePathDiscovery(ctx, disc, targets)); got != CodePathDiscoveryOff {
		t.Fatalf("switch off: %q", got)
	}
	s = &Service{pathGate: fakeTriggerGate{on: true, refused: map[string]string{"https://app.example.com": "path_ran_recently"}}}
	if err := s.refusePathDiscovery(ctx, disc, targets); code(err) != CodePathDiscoveryRefused {
		t.Fatalf("refused origin: %v", err)
	}
	s = &Service{pathGate: fakeTriggerGate{on: true}}
	if err := s.refusePathDiscovery(ctx, disc, targets); err != nil {
		t.Fatalf("allowed: %v", err)
	}
}
