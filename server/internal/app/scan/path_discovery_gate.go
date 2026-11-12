package scan

// The path discovery gate at trigger (docs/architecture/web-discovery.md): a
// single-scanner scan that runs path discovery (tool webguess, capability
// enumerate.web_paths) is refused up front when the organization has it turned
// off or the shared gate refuses its origins, so the person sees why instead
// of a failed job. The dispatch itself is claimed in the path discovery
// ledger by the web job guard every command passes, so a scan started here,
// the coverage planner and a workflow step cannot together exceed the
// per-origin cap.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/scan"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// PathDiscoveryTriggerGate is the organization's path discovery policy
// (coverage.PathDiscoveryPolicy).
type PathDiscoveryTriggerGate interface {
	PathDiscoveryEnabled(ctx context.Context, tenantID shared.ID) (bool, error)
	PathDiscoveryRefusals(ctx context.Context, tenantID shared.ID, targets []string) (map[string]string, error)
}

// Codes of a refused path discovery trigger.
const (
	CodePathDiscoveryOff     = "PATH_DISCOVERY_OFF"
	CodePathDiscoveryRefused = "PATH_DISCOVERY_REFUSED"
)

// SetPathDiscoveryGate makes the trigger refuse path discovery runs the
// shared gate does not allow. Unwired, a path discovery scan is refused (fail
// closed).
func (s *Service) SetPathDiscoveryGate(g PathDiscoveryTriggerGate) { s.pathGate = g }

// scanDiscovers reports whether a single-scanner scan's jobs run path
// discovery.
func scanDiscovers(sc *scan.Scan) bool {
	if sc == nil || sc.ScannerName == "" {
		return false
	}
	raw, err := json.Marshal(map[string]any{payloadKeyScanner: sc.ScannerName, payloadKeyScannerConfig: sc.ScannerConfig})
	if err != nil {
		return false
	}
	return commanddom.IsDiscoveryJob(raw)
}

// refusePathDiscovery refuses a path discovery scan the gate does not allow
// on its targets (any other scan passes).
func (s *Service) refusePathDiscovery(ctx context.Context, sc *scan.Scan, targets []string) error {
	if !scanDiscovers(sc) {
		return nil
	}
	if s.pathGate == nil {
		return shared.NewDomainError(CodePathDiscoveryRefused, "Path discovery is not configured on this server.", shared.ErrValidation)
	}
	on, err := s.pathGate.PathDiscoveryEnabled(ctx, sc.TenantID)
	if err != nil {
		return fmt.Errorf("path discovery switch: %w", err)
	}
	if !on {
		return shared.NewDomainError(CodePathDiscoveryOff, "Path discovery is turned off for the organization (scope settings).", shared.ErrValidation)
	}
	refused, err := s.pathGate.PathDiscoveryRefusals(ctx, sc.TenantID, targets)
	if err != nil {
		return fmt.Errorf("path discovery gate: %w", err)
	}
	if len(refused) == 0 {
		return nil
	}
	reasons := make([]string, 0, len(refused))
	for t, why := range refused {
		reasons = append(reasons, t+": "+why)
	}
	sort.Strings(reasons)
	return shared.NewDomainError(CodePathDiscoveryRefused,
		"Path discovery does not run on these origins now: "+strings.Join(reasons, "; ")+".", shared.ErrValidation)
}
