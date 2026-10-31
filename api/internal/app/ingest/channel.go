package ingest

// The ingest channel of a report's findings (docs/architecture/decisions/
// 004-finding-provenance.md; docs/architecture/sensor-platform-workflow.md).
// findings.ingest_channel says who reported a finding: a scanner run through
// a sensor, a collector, an integration or a person. Retest and closure
// treat a person's and an integration's findings differently from a scan's,
// so a sensor must never be able to choose its own label.

import (
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// principalSourceType is the report's channel, decided from who submitted
// it. A sensor's report (bound to a command or not, and a quarantined one a
// person accepted, whose content is still the sensor's) is a collector's
// when the sensor's role is collector and a scanner's otherwise, whatever
// its metadata.source_type says. A server-side ingest with no sensor (an
// import, an upload, a program feed) and a CI run keep the value their
// trusted producer set.
func principalSourceType(agt *sensor.Sensor, b Binding, claimed string) string {
	if agt == nil || agt.ID.IsZero() || b.Kind == BindingCIRun {
		return claimed
	}
	if agt.Type == sensor.SensorTypeCollector {
		return string(vulnerability.IngestChannelCollector)
	}
	return string(vulnerability.IngestChannelScanner)
}
