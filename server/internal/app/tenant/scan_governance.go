package tenant

// The organization's scan approval settings section (RFC-073,
// docs/rfcs/RFC-073-scan-approval-governance.md). The routes require the
// owner (mode) or an administrator (rules), step-up and a reason; the scan
// governance service checks the platform policy before it writes the mode.

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// GetScanGovernanceSettings returns the organization's scan approval
// settings (the zero value: Off, no rules).
func (s *TenantService) GetScanGovernanceSettings(ctx context.Context, tenantID string) (*tenantdom.ScanGovernanceSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	gs := t.TypedSettings().ScanGovernance
	return &gs, nil
}

// UpdateScanGovernanceSettings applies change to the section (one
// compare-and-swap write) and audits the before/after values at high
// severity with the reason. action is the audit action of the change.
func (s *TenantService) UpdateScanGovernanceSettings(
	ctx context.Context,
	tenantID string,
	change func(*tenantdom.ScanGovernanceSettings) error,
	action audit.Action,
	reason string,
	actx auditapp.AuditContext,
) (*tenantdom.ScanGovernanceSettings, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > scangov.MaxNoteLen {
		return nil, fmt.Errorf("%w: a reason (at most %d characters) is required", shared.ErrValidation, scangov.MaxNoteLen)
	}
	var before tenantdom.ScanGovernanceSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionScanGovernance, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().ScanGovernance
		next := before
		next.Rules = append([]scangov.Rule(nil), before.Rules...)
		if err := change(&next); err != nil {
			return err
		}
		return t.UpdateScanGovernanceSettings(next)
	})
	if err != nil {
		return nil, err
	}
	after := t.TypedSettings().ScanGovernance
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(action, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, after)).
		WithMessage("Scan approval settings changed").
		WithMetadata("reason", reason).
		WithMetadata("mode_before", string(before.EffectiveMode())).
		WithMetadata("mode_after", string(after.EffectiveMode())).
		WithSeverity(audit.SeverityHigh)
	modeLowered, rulesLoosened := scanGovernanceLoosened(before, after)
	if modeLowered || rulesLoosened {
		event = event.WithSeverity(audit.SeverityCritical).WithMetadata("loosened", true)
	}
	s.logAudit(ctx, actx, event)
	switch {
	case modeLowered:
		s.notifyPolicyLoosened(ctx, tenantID, actx, "Scan approval lowered",
			fmt.Sprintf("scan approval from %s to %s (fewer scans wait for an approver)", before.EffectiveMode(), after.EffectiveMode()),
			"/settings/scanning/scan-approval")
	case rulesLoosened:
		s.notifyPolicyLoosened(ctx, tenantID, actx, "Scan approval rules loosened",
			"the scan approval rules (a rule that held scans for approval was removed, turned off, set to monitor or edited)",
			"/settings/scanning/scan-approval")
	}
	return &after, nil
}

// scanGovernanceLoosened reports a lower mode (strict, on, off in that
// order) and, separately, rules that hold fewer scans: an enforcing rule
// (enabled, not monitor-only) that is gone, turned off, set to monitor or
// edited. An edit is counted whatever it changed, so a narrowed condition or
// a lighter requirement is never missed; adding a rule is not loosening.
func scanGovernanceLoosened(before, after tenantdom.ScanGovernanceSettings) (modeLowered, rulesLoosened bool) {
	rank := map[scangov.Mode]int{scangov.ModeOff: 0, scangov.ModeOn: 1, scangov.ModeStrict: 2}
	modeLowered = rank[after.EffectiveMode()] < rank[before.EffectiveMode()]
	if after.EffectiveMode() == scangov.ModeOff {
		// Rules do nothing while the mode is off.
		return modeLowered, false
	}
	kept := make(map[string]scangov.Rule, len(after.Rules))
	for _, r := range after.Rules {
		kept[r.ID] = r
	}
	for _, b := range before.Rules {
		if !b.Enabled || b.Monitor {
			continue
		}
		a, ok := kept[b.ID]
		if !ok || !a.Enabled || a.Monitor || !reflect.DeepEqual(a, b) {
			return modeLowered, true
		}
	}
	return modeLowered, false
}
