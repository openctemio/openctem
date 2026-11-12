package handler

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// The sensor is shown only with sensors:read; text is redacted for secrets
// on read; differences come with the records, in the same order.
func TestToFindingSourcesResponse(t *testing.T) {
	sensor := shared.NewID()
	recs := []vulnerability.SourceRecord{
		{Channel: "scan", SensorID: &sensor, SensorName: "dc1", Tool: "nessus", Primary: true,
			Values: vulnerability.SourceRecordValues{Severity: "high", Description: "token ghp_" + strings.Repeat("a", 36),
				Interop: vulnerability.InteropData{Native: &vulnerability.InteropNative{Severity: "3"}}}},
		{Channel: "upload", Tool: "openvas", Values: vulnerability.SourceRecordValues{Severity: "critical",
			Interop: vulnerability.InteropData{Native: &vulnerability.InteropNative{Severity: "8.1"}}}},
	}
	full := toFindingSourcesResponse(recs, true)
	if len(full.Data) != 2 || full.Data[0].Sensor == nil || full.Data[0].Sensor.Name != "dc1" || !full.Data[0].Primary {
		t.Fatalf("with sensors:read: %+v", full.Data)
	}
	if strings.Contains(full.Data[0].Description, strings.Repeat("a", 36)) {
		t.Errorf("secret not redacted: %q", full.Data[0].Description)
	}
	fields := map[string][]string{}
	for _, d := range full.Differences {
		fields[d.Field] = d.Values
	}
	if v := fields["severity"]; len(v) != 2 || v[0] != "high" || v[1] != "critical" {
		t.Errorf("severity difference = %v", v)
	}
	if v := fields["vendor_severity"]; len(v) != 2 || v[0] != "3" || v[1] != "8.1" {
		t.Errorf("vendor severity difference = %v", v)
	}
	bare := toFindingSourcesResponse(recs, false)
	if bare.Data[0].Sensor != nil {
		t.Error("sensor shown without sensors:read")
	}
	if empty := toFindingSourcesResponse(nil, true); empty.Data == nil || empty.Differences == nil {
		t.Error("empty answer must be [] not null")
	}
}
