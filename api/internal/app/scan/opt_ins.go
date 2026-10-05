package scan

// The organization's sensor opt-ins (research/25 D3, D9): out-of-band
// callbacks (interactsh) and custom templates in sensor jobs are off unless
// an owner enabled them. With an opt-in off the platform:
//
//   - refuses a scan create or update whose scanner_config asks for it
//     (allow_interactsh true, custom_template_ids not empty);
//   - at trigger, strips allow_interactsh from an existing scan's config
//     (the scan still runs, with a run warning) and refuses a scan with
//     custom templates (running it without them would run the scanner's
//     default set, which is wider than what the author chose);
//   - refuses a POST /api/v1/commands scan payload that asks for either;
//   - never dispatches such a command (command.WithOptInPolicy, backstop).
//
// Everything here only narrows what reaches a sensor.

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// codeSensorOptInDisabled is the refusal when a scan asks for an opt-in the
// organization has not enabled.
const codeSensorOptInDisabled = "SENSOR_OPT_IN_DISABLED"

// OptInPolicy returns the tenant's sensor opt-ins. Satisfied by the tenant
// service.
type OptInPolicy interface {
	SensorOptIns(ctx context.Context, tenantID shared.ID) (sensordom.OptIns, error)
}

// WithOptInPolicy enforces the organization's sensor opt-ins on scan
// create, update, trigger and command payloads.
func WithOptInPolicy(p OptInPolicy) ServiceOption {
	return func(s *Service) { s.optIns = p }
}

// optInsFor reads the tenant's opt-ins. Without a policy wired every
// opt-in counts as enabled (the pre-D3 behaviour, for tests that do not
// wire it). An error refuses (fail closed).
func (s *Service) optInsFor(ctx context.Context, tenantID shared.ID) (sensordom.OptIns, error) {
	if s.optIns == nil {
		return sensordom.OptIns{AllowInteractsh: true, AllowCustomTemplates: true}, nil
	}
	o, err := s.optIns.SensorOptIns(ctx, tenantID)
	if err != nil {
		return sensordom.OptIns{}, fmt.Errorf("read the organization's sensor opt-ins: %w", err)
	}
	return o, nil
}

// optInDisabledError explains a refusal and who can lift it.
func optInDisabledError(what string) error {
	return shared.NewDomainError(codeSensorOptInDisabled, fmt.Sprintf(
		"%s is turned off for this organization: the platform does not send it to sensors. An owner can enable it in Settings → Security (sensor opt-ins); enabling it is audited.",
		what), shared.ErrValidation)
}

// refuseDisabledOptIns refuses a scanner config that asks for an opt-in
// the tenant has not enabled (scan create and update).
func (s *Service) refuseDisabledOptIns(ctx context.Context, tenantID shared.ID, cfg map[string]any) error {
	asksInteractsh := sensordom.ConfigAsksInteractsh(cfg)
	asksTemplates := len(customTemplateIDs(cfg)) > 0
	if !asksInteractsh && !asksTemplates {
		return nil
	}
	o, err := s.optInsFor(ctx, tenantID)
	if err != nil {
		return err
	}
	if asksInteractsh && !o.AllowInteractsh {
		return optInDisabledError("Out-of-band callbacks (allow_interactsh)")
	}
	if asksTemplates && !o.AllowCustomTemplates {
		return optInDisabledError("Custom templates (custom_template_ids)")
	}
	return nil
}

// applyOptInsAtTrigger narrows a scan about to run: allow_interactsh is
// removed from its config (in memory only; the stored scan is unchanged)
// with a run warning, and custom templates refuse the trigger. It returns
// the warning to record, or "".
func (s *Service) applyOptInsAtTrigger(ctx context.Context, sc *scan.Scan) (string, error) {
	asksInteractsh := sensordom.ConfigAsksInteractsh(sc.ScannerConfig)
	asksTemplates := len(customTemplateIDs(sc.ScannerConfig)) > 0
	if !asksInteractsh && !asksTemplates {
		return "", nil
	}
	o, err := s.optInsFor(ctx, sc.TenantID)
	if err != nil {
		return "", err
	}
	if asksTemplates && !o.AllowCustomTemplates {
		return "", optInDisabledError(fmt.Sprintf("Scan %q uses custom templates, which", sc.Name))
	}
	if asksInteractsh && !o.AllowInteractsh {
		cfg := maps.Clone(sc.ScannerConfig)
		delete(cfg, "allow_interactsh")
		sc.ScannerConfig = cfg
		return "allow_interactsh was removed for this run: out-of-band callbacks are turned off for this organization (an owner can enable them in Settings → Security)", nil
	}
	return "", nil
}

// refuseDisabledOptInPayload refuses a scan command payload (POST
// /api/v1/commands) that asks for an opt-in the tenant has not enabled, in
// any of the configuration objects a reader might use.
func (s *Service) refuseDisabledOptInPayload(ctx context.Context, tenantID shared.ID, fields map[string]any) error {
	asksInteractsh, asksTemplates := false, false
	for _, key := range []string{"config", "scanner_config"} {
		if cfg, ok := fields[key].(map[string]any); ok {
			asksInteractsh = asksInteractsh || sensordom.ConfigAsksInteractsh(cfg)
			asksTemplates = asksTemplates || len(customTemplateIDs(cfg)) > 0
		}
	}
	if raw, ok := fields["custom_templates"]; ok {
		if b, err := json.Marshal(raw); err == nil && string(b) != "null" && string(b) != "[]" {
			asksTemplates = true
		}
	}
	if !asksInteractsh && !asksTemplates {
		return nil
	}
	o, err := s.optInsFor(ctx, tenantID)
	if err != nil {
		return err
	}
	if asksInteractsh && !o.AllowInteractsh {
		return refused("out-of-band callbacks (allow_interactsh) are turned off for this organization")
	}
	if asksTemplates && !o.AllowCustomTemplates {
		return refused("custom templates are turned off for this organization")
	}
	return nil
}

// OptInImpactScan is a scan that asks for a sensor opt-in.
type OptInImpactScan struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	UsesInteractsh  bool   `json:"uses_interactsh"`
	UsesCustomTmpls bool   `json:"uses_custom_templates"`
}

// OptInImpact is what the opt-ins banner shows: the organization's
// switches and the scans affected while they are off.
type OptInImpact struct {
	OptIns sensordom.OptIns  `json:"opt_ins"`
	Scans  []OptInImpactScan `json:"scans"`
	// Truncated: more scans are affected than listed.
	Truncated bool `json:"truncated"`
}

// optInScanLister lists a tenant's scans whose scanner_config asks for
// interactsh or custom templates (postgres.ScanRepository).
type optInScanLister interface {
	ListOptInScans(ctx context.Context, tenantID shared.ID, limit int) ([]*scan.Scan, error)
}

// maxOptInImpactScans bounds the banner list.
const maxOptInImpactScans = 100

// SensorOptInImpact lists the tenant's scans that ask for an opt-in, with
// the current switches (research/25 D3 banner). Tenant-scoped.
func (s *Service) SensorOptInImpact(ctx context.Context, tenantIDStr string) (*OptInImpact, error) {
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	o, err := s.optInsFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := &OptInImpact{OptIns: o, Scans: []OptInImpactScan{}}
	lister, ok := s.scanRepo.(optInScanLister)
	if !ok {
		return out, nil
	}
	scans, err := lister.ListOptInScans(ctx, tenantID, maxOptInImpactScans+1)
	if err != nil {
		return nil, err
	}
	if len(scans) > maxOptInImpactScans {
		scans, out.Truncated = scans[:maxOptInImpactScans], true
	}
	for _, sc := range scans {
		out.Scans = append(out.Scans, OptInImpactScan{
			ID: sc.ID.String(), Name: sc.Name, Status: string(sc.Status),
			UsesInteractsh:  sensordom.ConfigAsksInteractsh(sc.ScannerConfig),
			UsesCustomTmpls: len(customTemplateIDs(sc.ScannerConfig)) > 0,
		})
	}
	return out, nil
}
