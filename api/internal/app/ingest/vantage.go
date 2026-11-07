package ingest

// The sensors' own DNS answers (vantage points). Design:
// docs/architecture/scan-zones.md "Vantage resolution".

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SetVantageResolution wires where the sensors' answers are recorded. Nil:
// nothing is recorded and routing reads the platform's resolver only.
func (s *Service) SetVantageResolution(w scanzone.VantageWriter) { s.vantage = w }

// maxVantageNamesPerReport bounds the names one report records.
const maxVantageNamesPerReport = 5000

// recordVantage records, for a report bound to a command of one of the
// tenant's own sensors, the addresses the report says each host name
// resolved to. The observer is the authenticated sensor and the zone is the
// command's routing, never a value of the report. A shared sensor, an
// unbound or trusted report and a CI run record nothing. A failure is
// logged; it never fails the ingest (the answers only add routes).
func (s *Service) recordVantage(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, binding Binding, report *ctis.Report, at time.Time) {
	if s.vantage == nil || agt == nil || report == nil || binding.Kind != BindingCommand || binding.CommandID == nil {
		return
	}
	if agt.ID.IsZero() || agt.IsShared() || agt.TenantID == nil || *agt.TenantID != tenantID {
		return
	}
	answers := vantageAnswers(report)
	if len(answers) == 0 {
		return
	}
	if err := s.vantage.RecordAnswers(ctx, tenantID, agt.ID, binding.ScanZoneID, answers, at); err != nil {
		s.logger.Warn("vantage answers not recorded", "command_id", binding.CommandID.String(), "error", logger.SanitizeError(err))
	}
}

// vantageAnswers are the host names of a report's assets with the addresses
// they carry (ip_addresses and its synonyms), bounded.
func vantageAnswers(report *ctis.Report) map[string][]netip.Addr {
	out := map[string][]netip.Addr{}
	for i := range report.Assets {
		a := &report.Assets[i]
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(getAssetName(a)), "."))
		if name == "" || stage.ClassifyTarget(name) != stage.KindName {
			continue
		}
		for _, v := range asset.IPAddresses(a.Properties) {
			ad, err := netip.ParseAddr(strings.TrimSpace(v))
			if err != nil {
				continue
			}
			if _, seen := out[name]; !seen && len(out) >= maxVantageNamesPerReport {
				break
			}
			if len(out[name]) < scanzone.MaxAnswerAddrs {
				out[name] = append(out[name], ad.Unmap())
			}
		}
	}
	return out
}
