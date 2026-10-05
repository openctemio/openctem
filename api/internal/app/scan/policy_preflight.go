package scan

// The scan-trigger preflight against the sensors' reported local policies
// (research/25 §3.6, RFC-040 §5.7): a batch is pinned only to a zone sensor
// whose policy accepts it, and a trigger that no available sensor would
// accept is refused with the layer and rule that block it, instead of
// queueing jobs that sit pending until they expire. The preflight uses the
// same check as poll and claim (sensor.Accepts). It only narrows: the
// sensor still enforces its own policy on whatever it receives.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// codeSensorPolicyRefused is the trigger refusal when every sensor that
// could run the scan reports a local policy that refuses it.
const codeSensorPolicyRefused = "SENSOR_POLICY_REFUSED"

// PrivateTargetPolicy says whether a tenant keeps jobs with private targets
// away from sensors without an enforced local policy. Satisfied by the
// tenant service.
type PrivateTargetPolicy interface {
	RequiresLocalPolicyForPrivateTargets(ctx context.Context, tenantID shared.ID) (bool, error)
}

// AvailableSensorLister lists the tenant's sensors that can take a job for
// tool now. Satisfied by the sensor repository.
type AvailableSensorLister interface {
	FindAvailableWithCapacity(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*sensordom.Sensor, error)
}

// WithDispatchPolicy enables the trigger preflight: sensors lists the
// tenant sensors for scans outside zones, private reads the tenant's
// private-target switch. Either may be nil.
func WithDispatchPolicy(sensors AvailableSensorLister, private PrivateTargetPolicy) ServiceOption {
	return func(s *Service) {
		s.policySensors = sensors
		s.privatePolicy = private
	}
}

// dispatchOptions reads the tenant's platform-side dispatch settings. An
// error stops the trigger (fail closed).
func (s *Service) dispatchOptions(ctx context.Context, tenantID shared.ID) (sensordom.DispatchOptions, error) {
	var o sensordom.DispatchOptions
	if s.privatePolicy == nil {
		return o, nil
	}
	required, err := s.privatePolicy.RequiresLocalPolicyForPrivateTargets(ctx, tenantID)
	if err != nil {
		return o, fmt.Errorf("read the tenant's private-target policy, scan not dispatched: %w", err)
	}
	o.RequireLocalPolicyForPrivate = required
	return o, nil
}

// scanJob is the job one command of sc for targets would be, as the
// sensor's admission check reads it.
func scanJob(sc *scan.Scan, targets []string) sensordom.Job {
	job := sensordom.Job{
		Type:            "scan",
		Tool:            sensordom.CanonicalTool(sc.ScannerName),
		Interactsh:      sensordom.ConfigAsksInteractsh(sc.ScannerConfig),
		CustomTemplates: len(customTemplateIDs(sc.ScannerConfig)),
	}
	if v, ok := sc.ScannerConfig["ports"].(string); ok {
		job.Ports = strings.TrimSpace(v)
	}
	raw, _ := json.Marshal(map[string]any{"targets": targets})
	job.Private = sensordom.HasPrivateTarget(raw)
	job.PrivateAddress = sensordom.HasPrivateAddress(raw)
	return job
}

// customTemplateIDs returns the custom template ids a scanner config names.
func customTemplateIDs(cfg map[string]any) []string {
	var out []string
	switch v := cfg["custom_template_ids"].(type) {
	case []string:
		out = v
	case []any:
		for _, id := range v {
			if s, ok := id.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// policyVerdict collects, for one set of sensors, which accept a job and
// why the others refuse it.
type policyVerdict struct {
	total    int
	accepted []int
	// byRule counts the refusing sensors per "layer/rule"; detail keeps
	// one operator-facing detail per rule.
	byRule map[string]int
	detail map[string]string
}

func judge(reports []*sensordom.LocalPolicyReport, job sensordom.Job, opts sensordom.DispatchOptions) policyVerdict {
	v := policyVerdict{total: len(reports), byRule: map[string]int{}, detail: map[string]string{}}
	for i, r := range reports {
		ref := sensordom.Accepts(r, job, opts)
		if ref == nil {
			v.accepted = append(v.accepted, i)
			continue
		}
		key := ref.Layer + "/" + ref.Rule
		v.byRule[key]++
		if _, ok := v.detail[key]; !ok {
			v.detail[key] = ref.Detail
		}
	}
	return v
}

// reason explains a verdict in which no sensor accepts, for the sensors of
// where ("zone \"DMZ\"", "this organization"): per rule, how many sensors
// refuse and why, and who can change it.
func (v policyVerdict) reason(where string) string {
	keys := make([]string, 0, len(v.byRule))
	for k := range v.byRule {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		layer, rule, _ := strings.Cut(k, "/")
		who := "the network owner must allow it in the sensor's local policy on the host"
		if layer == sensordom.RefusalLayerManaged {
			who = "an administrator can change the organization setting"
		}
		parts = append(parts, fmt.Sprintf("%s: refused by the %s policy on %d of %d sensor(s) in %s (%s; %s)",
			rule, layer, v.byRule[k], v.total, where, v.detail[k], who))
	}
	return strings.Join(parts, "; ")
}

// policyRefusedError refuses a trigger that no sensor would accept.
func policyRefusedError(sc *scan.Scan, reasons []string) error {
	return shared.NewDomainError(codeSensorPolicyRefused, fmt.Sprintf(
		"No sensor can run scan %q: %s", sc.Name, strings.Join(reasons, "; ")), shared.ErrValidation)
}

// preflightUnzoned checks the targets that go to the tenant's sensors
// outside any zone (all of them when the tenant has no zones): when sensors
// are available and none accepts the job, the targets are not dispatched.
// It returns the refusal reason ("" when a sensor accepts, nothing is
// available to judge, or the preflight is off).
func (s *Service) preflightUnzoned(ctx context.Context, sc *scan.Scan, targets []string) (string, error) {
	if s.policySensors == nil || len(targets) == 0 {
		return "", nil
	}
	opts, err := s.dispatchOptions(ctx, sc.TenantID)
	if err != nil {
		return "", err
	}
	available, err := s.policySensors.FindAvailableWithCapacity(ctx, sc.TenantID, nil, sc.ScannerName)
	if err != nil {
		return "", fmt.Errorf("sensor lookup failed, scan not dispatched: %w", err)
	}
	if len(available) == 0 {
		return "", nil // nothing to judge: the availability check decides
	}
	reports := make([]*sensordom.LocalPolicyReport, len(available))
	for i, a := range available {
		reports[i] = a.LocalPolicy
	}
	v := judge(reports, scanJob(sc, targets), opts)
	if len(v.accepted) > 0 {
		return "", nil
	}
	return v.reason("this organization"), nil
}

// applyUnzonedPreflight runs preflightUnzoned for a tenant-routed trigger.
// Without a zone plan a refusal refuses the trigger. With one, the unzoned
// batches are dropped with a warning, and the trigger is refused only when
// no batch is left.
func (s *Service) applyUnzonedPreflight(ctx context.Context, sc *scan.Scan, plan *zonePlan, targets []string, runContext map[string]any) error {
	if plan != nil {
		targets = plan.Routing.Unzoned
	}
	reason, err := s.preflightUnzoned(ctx, sc, targets)
	if err != nil || reason == "" {
		return err
	}
	if plan == nil {
		return policyRefusedError(sc, []string{reason})
	}
	kept := plan.Batches[:0:0]
	for _, b := range plan.Batches {
		if b.Zone != nil {
			kept = append(kept, b)
		}
	}
	if len(kept) == 0 {
		return policyRefusedError(sc, append(plan.PolicyRefused, reason))
	}
	plan.Batches = kept
	warning := fmt.Sprintf("%d target(s) outside every scan zone are not scanned: %s", len(targets), reason)
	warnings, _ := runContext["dispatch_warnings"].([]string)
	runContext["dispatch_warnings"] = append(warnings, warning)
	return nil
}
