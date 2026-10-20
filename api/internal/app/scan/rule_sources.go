package scan

// Rule sources at trigger and dispatch (docs/architecture/rule-sources.md):
// a single-scanner scan runs the platform's rules, the organization's own
// scanner templates, or both together. The scan's own setting wins, else
// its profile's, else both. The choice is resolved once per trigger,
// recorded in the run context and sent in every command of the run; a
// tenant-only command is claimable only by a sensor that reports
// rule.sources@1 (an older sensor would also run the platform's rules).

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RunContextKeyRuleSources is the run context key of the run's resolved
// rule sources (set at trigger, never taken from a caller).
const RunContextKeyRuleSources = "rule_sources"

// Domain error codes of the rule sources checks.
const (
	codeRuleSourcesNoTemplates = "RULE_SOURCES_NO_TEMPLATES"
	codeCustomTemplatesFailed  = "CUSTOM_TEMPLATES_UNRESOLVED"
)

// checkScanRuleSources refuses a scan that runs only the organization's
// templates but names none (scan create and update).
func checkScanRuleSources(sc *scan.Scan) error {
	if sc.RuleSources == scannertemplate.RuleSourcesTenant && len(customTemplateIDs(sc.ScannerConfig)) == 0 {
		return shared.NewDomainError(codeRuleSourcesNoTemplates,
			"rule_sources is tenant (only the organization's templates), but the scan names no custom template (scanner_config.custom_template_ids)",
			shared.ErrValidation)
	}
	return nil
}

// effectiveRuleSources is the rule sources a run of sc uses: the scan's,
// else its profile's, else both. A profile that no longer exists counts as
// none; any other read error refuses the trigger (fail closed).
func (s *Service) effectiveRuleSources(ctx context.Context, sc *scan.Scan) (scannertemplate.RuleSources, error) {
	if sc.RuleSources.IsValid() {
		return sc.RuleSources, nil
	}
	var profileValue scannertemplate.RuleSources
	if sc.ProfileID != nil && s.profileRepo != nil {
		p, err := s.profileRepo.GetAccessibleByID(ctx, sc.TenantID, *sc.ProfileID)
		switch {
		case errors.Is(err, shared.ErrNotFound):
		case err != nil:
			return "", fmt.Errorf("read the scan's profile for its rule sources: %w", err)
		default:
			profileValue = p.RuleSources
		}
	}
	return scannertemplate.EffectiveRuleSources(sc.RuleSources, profileValue), nil
}

// applyRuleSourcesAtTrigger resolves the run's rule sources and narrows the
// scan in memory to them (the stored scan is unchanged): platform-only
// drops the custom template ids, so neither the opt-in check nor the
// sensor preflight counts templates that will not be sent; tenant-only
// without templates refuses the trigger. It returns the resolved value.
func (s *Service) applyRuleSourcesAtTrigger(ctx context.Context, sc *scan.Scan) (scannertemplate.RuleSources, error) {
	rs, err := s.effectiveRuleSources(ctx, sc)
	if err != nil {
		return "", err
	}
	ids := customTemplateIDs(sc.ScannerConfig)
	switch {
	case rs == scannertemplate.RuleSourcesPlatform && len(ids) > 0:
		cfg := maps.Clone(sc.ScannerConfig)
		delete(cfg, "custom_template_ids")
		sc.ScannerConfig = cfg
	case rs == scannertemplate.RuleSourcesTenant && len(ids) == 0:
		return "", shared.NewDomainError(codeRuleSourcesNoTemplates, fmt.Sprintf(
			"Scan %q runs only the organization's templates (rule sources: tenant), but it names no custom template. Add templates to the scan or choose another rule source.",
			sc.Name), shared.ErrValidation)
	}
	return rs, nil
}

// ruleSourcesOfRun reads the run's resolved rule sources from its context
// (both when absent: a run triggered before rule sources existed).
func ruleSourcesOfRun(runContext map[string]any) scannertemplate.RuleSources {
	if v, ok := runContext[RunContextKeyRuleSources].(string); ok {
		if rs := scannertemplate.RuleSources(v); rs.IsValid() {
			return rs
		}
	}
	return scannertemplate.RuleSourcesBoth
}

// customTemplatesFor resolves the run's custom templates, failing closed:
// when the organization's templates are to run, every named template must
// exist in the scan's organization and be usable, or the run fails with
// the reason. Nothing is resolved for a platform-only run.
func (s *Service) customTemplatesFor(ctx context.Context, sc *scan.Scan, rs scannertemplate.RuleSources) ([]EmbeddedTemplate, error) {
	if !rs.RunsTenant() {
		return nil, nil
	}
	templates, err := s.resolveCustomTemplates(ctx, sc)
	if err != nil {
		return nil, shared.NewDomainError(codeCustomTemplatesFailed, fmt.Sprintf(
			"The scan's custom templates could not be resolved, so the run was not dispatched: %s", err.Error()),
			shared.ErrValidation)
	}
	if rs == scannertemplate.RuleSourcesTenant && len(templates) == 0 {
		return nil, shared.NewDomainError(codeRuleSourcesNoTemplates,
			"The scan runs only the organization's templates, but none could be sent", shared.ErrValidation)
	}
	if len(templates) > 0 {
		s.logger.Info("embedded custom templates in scan command",
			"scan_id", sc.ID.String(), "template_count", len(templates), "tenant_only", rs == scannertemplate.RuleSourcesTenant)
	}
	return templates, nil
}

// unresolvedTemplatesError names the templates of a scan that are missing
// (deleted, or another organization's) or not usable.
func unresolvedTemplatesError(missing, unusable []string) error {
	var parts []string
	if len(missing) > 0 {
		parts = append(parts, fmt.Sprintf("%d not found (%s)", len(missing), strings.Join(missing, ", ")))
	}
	if len(unusable) > 0 {
		parts = append(parts, fmt.Sprintf("%d not active (%s)", len(unusable), strings.Join(unusable, ", ")))
	}
	return fmt.Errorf("custom templates: %s", strings.Join(parts, "; "))
}

// withRuleSources adds the run's rule sources to a scan command payload;
// a tenant-only command requires a sensor that honors them.
func withRuleSources(payload map[string]any, rs scannertemplate.RuleSources) {
	payload[scannertemplate.PayloadKeyRuleSources] = string(rs)
	if rs == scannertemplate.RuleSourcesTenant {
		payload[command.PayloadKeyRequiredFeatures] = withRequiredFeature(payload[command.PayloadKeyRequiredFeatures], scannertemplate.SensorCapabilityRuleSources)
	}
}

// withRequiredFeature adds feature to a payload's required features list
// once.
func withRequiredFeature(existing any, feature string) []string {
	var out []string
	switch v := existing.(type) {
	case []string:
		out = append(out, v...)
	case []any:
		for _, f := range v {
			if s, ok := f.(string); ok {
				out = append(out, s)
			}
		}
	}
	for _, f := range out {
		if f == feature {
			return out
		}
	}
	return append(out, feature)
}
