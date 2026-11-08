package sourceretire

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The ingest side of "this source" agrees with the SQL function: a sensor's
// tool only from that sensor, an upload tool only from uploads, a connector
// only by its source name; tool names compare without case.
func TestSelectorMatches(t *testing.T) {
	sensor, other := shared.NewID(), shared.NewID()
	sensorTool := Selector{Kind: KindSensorTool, SensorID: &sensor, Tool: "nuclei"}
	upload := Selector{Kind: KindUpload, Tool: "nessus"}
	connector := Selector{Kind: KindConnector, Sender: "feed"}
	sensorInst := func(id shared.ID) ingestreceipt.Instance {
		return ingestreceipt.Instance{Kind: ingestreceipt.InstanceSensor, ID: id.String()}
	}
	cases := []struct {
		name string
		sel  Selector
		r    Report
		want bool
	}{
		{"same sensor and tool", sensorTool, Report{Channel: ingestreceipt.ChannelScan, Instance: sensorInst(sensor), Tool: "NUCLEI"}, true},
		{"same tool, another sensor", sensorTool, Report{Channel: ingestreceipt.ChannelScan, Instance: sensorInst(other), Tool: "nuclei"}, false},
		{"same sensor, another tool", sensorTool, Report{Channel: ingestreceipt.ChannelTask, Instance: sensorInst(sensor), Tool: "httpx"}, false},
		{"upload of the tool", upload, Report{Channel: ingestreceipt.ChannelUpload, Instance: ingestreceipt.Instance{Kind: ingestreceipt.InstanceImport}, Tool: "Nessus"}, true},
		{"sensor scan of the upload tool", upload, Report{Channel: ingestreceipt.ChannelScan, Instance: sensorInst(sensor), Tool: "nessus"}, false},
		{"connector by name", connector, Report{Channel: ingestreceipt.ChannelConnector, Instance: ingestreceipt.Instance{Kind: ingestreceipt.InstanceConnector, ID: "feed"}, Tool: "x"}, true},
		{"another connector", connector, Report{Channel: ingestreceipt.ChannelConnector, Instance: ingestreceipt.Instance{Kind: ingestreceipt.InstanceConnector, ID: "feed2"}}, false},
		{"CI repository named like the connector", connector, Report{Channel: ingestreceipt.ChannelCI, Instance: ingestreceipt.Instance{Kind: ingestreceipt.InstanceCI, ID: "feed"}}, false},
	}
	for _, c := range cases {
		if got := c.sel.Matches(c.r); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSelectorValidateAndOptions(t *testing.T) {
	s := shared.NewID()
	for name, sel := range map[string]Selector{
		"sensor without tool":    {Kind: KindSensorTool, SensorID: &s},
		"upload with sensor":     {Kind: KindUpload, SensorID: &s, Tool: "x"},
		"connector with tool":    {Kind: KindConnector, Sender: "a", Tool: "x"},
		"unknown kind":           {Kind: "asset"},
		"connector without name": {Kind: KindConnector},
	} {
		if err := sel.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	o, err := Options{}.Normalize()
	if err != nil || o.Mode != ModeArchive {
		t.Fatalf("default options = %+v, %v", o, err)
	}
	if _, err := (Options{Mode: "purge"}).Normalize(); err == nil {
		t.Fatal("unknown mode accepted")
	}
}
