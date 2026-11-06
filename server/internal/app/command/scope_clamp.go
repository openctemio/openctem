package command

// Clamping a job to the caps of its targets at claim (docs/rfcs/RFC-054-scope-model.md
// §16). When the re-check refuses every target of a job only because the
// job goes beyond the low-impact profile of unclassified assets, or beyond
// the web ports of names whose addresses are not in scope, the job is cut
// down to those caps instead of failing: ports, rates and concurrency are
// lowered and nuclei is limited to info templates tagged tech or exposure.
// A job with any other refusal, or one the caps cannot describe (a tool
// outside the profile, custom templates, a higher tier), is not clamped.
// A job that mixes such targets with in-scope ones keeps the in-scope
// targets (the others are left out, as for any refusal).

import (
	"context"
	"encoding/json"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// clampable reports whether every refusal is a cap a clamp can meet.
func clampable(refused map[string]string) bool {
	if len(refused) == 0 {
		return false
	}
	for _, code := range refused {
		if code != scopedom.RefusalLowImpact && code != scopedom.RefusalWebPortsOnly {
			return false
		}
	}
	return true
}

// clampPayload returns payload with its tool settings cut to the caps
// (lowImpact: the low-impact profile; webPorts: the web ports), and false
// when the job cannot run inside them.
func clampPayload(payload json.RawMessage, tool string, lowImpact, webPorts bool) (json.RawMessage, bool) {
	var p map[string]json.RawMessage
	if json.Unmarshal(payload, &p) != nil || p == nil {
		return nil, false
	}
	keys := []string{}
	for _, k := range []string{"config", "scanner_config"} {
		if _, ok := p[k]; ok {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		keys = []string{"config"}
	}
	clamped := map[string]map[string]any{}
	for _, k := range keys {
		cfg := map[string]any{}
		if raw, ok := p[k]; ok && string(raw) != "null" {
			if json.Unmarshal(raw, &cfg) != nil {
				return nil, false
			}
		}
		if lowImpact {
			var ok bool
			if cfg, ok = scopedom.LowImpactClamp(tool, cfg); !ok {
				return nil, false
			}
		}
		if webPorts {
			ports, _ := cfg["ports"].(string)
			delete(cfg, "top_ports")
			cfg["ports"] = scopedom.ClampPorts(ports, scopedom.WebPorts)
		}
		clamped[k] = cfg
	}
	if lowImpact {
		merged, ok := scopedom.LowImpactConfig(clamped["config"], clamped["scanner_config"])
		if !ok {
			return nil, false
		}
		var probe struct {
			CustomTemplates []json.RawMessage `json:"custom_templates"`
		}
		_ = json.Unmarshal(payload, &probe)
		job := scopedom.LowImpactJob{Tool: tool, Config: merged, CustomTemplates: len(probe.CustomTemplates) > 0}
		if scopedom.LowImpactRefusal(job) != "" {
			return nil, false
		}
	}
	for k, cfg := range clamped {
		b, err := json.Marshal(cfg)
		if err != nil {
			return nil, false
		}
		p[k] = b
	}
	out, err := json.Marshal(p)
	if err != nil {
		return nil, false
	}
	return out, true
}

// clampAtClaim clamps j's payload to the caps its refusals name and keeps
// the job; false when it cannot (the caller fails or narrows it as usual).
func (s *Service) clampAtClaim(ctx context.Context, j recheckJob, refused map[string]string,
	outcomes map[shared.ID]recheckOutcome, replaced map[shared.ID]*commanddom.Command,
) bool {
	if j.job.Interactsh || j.job.CustomTemplates {
		return false
	}
	store, ok := s.repo.(ScopeRecheckStore)
	if !ok {
		return false
	}
	payload, ok := clampPayload(j.cmd.Payload, j.job.Tool,
		hasCode(refused, scopedom.RefusalLowImpact), hasCode(refused, scopedom.RefusalWebPortsOnly))
	if !ok {
		return false
	}
	won, err := store.NarrowPendingPayload(ctx, j.cmd, payload)
	if err != nil || !won {
		outcomes[j.cmd.ID] = recheckWithheld
		return true
	}
	cp := *j.cmd
	cp.Payload = payload
	replaced[j.cmd.ID] = &cp
	outcomes[j.cmd.ID] = recheckKeep
	s.logger.Info("job clamped at claim to the low-impact or web-port caps of its targets",
		"tenant_id", j.cmd.TenantID.String(), "command_id", j.cmd.ID.String(), "codes", refusalCodes(refused))
	return true
}
