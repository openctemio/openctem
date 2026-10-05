package ingest

// Subdomain-takeover confirmation from scan results (RFC-036 P1). A nuclei
// takeover-template match in a report bound to a command the tenant's own
// sensor ran (RFC-040 §5.3), on an asset the command covered, is handed to
// the takeover confirmer, which raises subdomain_takeover only where the DNS
// check already found an open dangling_cname. The probe itself went through
// the scan gate when the command was created; nothing is dispatched here.

import (
	"context"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/easmdns"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TakeoverConfirmer raises confirmed subdomain takeovers. Satisfied by
// *easmdns.TakeoverConfirmer.
type TakeoverConfirmer interface {
	ConfirmTakeovers(ctx context.Context, tenantID shared.ID, sightings []easmdns.TakeoverSighting) (int, error)
}

// SetTakeoverConfirmer wires takeover confirmation. Nil-safe: unwired,
// takeover-template findings stay plain findings (prior behavior).
func (s *Service) SetTakeoverConfirmer(c TakeoverConfirmer) {
	s.takeoverConfirmer = c
}

// takeoverSightings picks the nuclei takeover-template findings of a
// command-bound report whose asset the report may change.
func takeoverSightings(agt *sensor.Sensor, binding Binding, scope *alterScope, report *ctis.Report, assetMap map[string]shared.ID) []easmdns.TakeoverSighting {
	if binding.Kind != BindingCommand || scope == nil || report == nil || report.Tool == nil ||
		!tooldom.SameTool(report.Tool.Name, "nuclei") {
		return nil
	}
	out := make([]easmdns.TakeoverSighting, 0, len(report.Findings))
	for i := range report.Findings {
		f := &report.Findings[i]
		if !easmdns.IsTakeoverTemplate(f.RuleID, f.Tags) || f.AssetRef == "" {
			continue
		}
		id, ok := assetMap[f.AssetRef]
		if !ok || id.IsZero() || !scope.allowed[id] {
			continue
		}
		out = append(out, easmdns.TakeoverSighting{
			AssetID:    id,
			TemplateID: strings.TrimSpace(f.RuleID),
			Matched:    f.Evidence,
			SensorID:   agt.ID,
			CommandID:  binding.CommandID,
		})
	}
	return out
}

// confirmTakeovers is best-effort: the findings are already stored.
func (s *Service) confirmTakeovers(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, binding Binding, scope *alterScope, report *ctis.Report, assetMap map[string]shared.ID) {
	if s.takeoverConfirmer == nil {
		return
	}
	sightings := takeoverSightings(agt, binding, scope, report, assetMap)
	if len(sightings) == 0 {
		return
	}
	if _, err := s.takeoverConfirmer.ConfirmTakeovers(ctx, tenantID, sightings); err != nil {
		s.logger.Warn("ingest: takeover confirmation failed",
			"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
	}
}
