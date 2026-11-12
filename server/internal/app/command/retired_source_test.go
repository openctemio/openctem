package command

import (
	"encoding/json"
	"errors"
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/sourceretire"
)

func retiredJob(t *testing.T, typ commanddom.CommandType, tool string, pinned *shared.ID) *commanddom.Command {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"scanner": tool, "scan_run_id": shared.NewID().String()})
	c, err := commanddom.NewCommand(shared.NewID(), typ, commanddom.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	c.SensorID = pinned
	return c
}

func sensorTool(sensorID shared.ID, tool string) sourceretire.Selector {
	return sourceretire.Selector{Kind: sourceretire.KindSensorTool, SensorID: &sensorID, Tool: tool}
}

func TestDecideRetired(t *testing.T) {
	s1, s2 := shared.NewID(), shared.NewID()
	sels := []sourceretire.Selector{
		sensorTool(s1, "Nuclei"),
		sensorTool(s2, "nuclei"),
		{Kind: sourceretire.KindUpload, Tool: "subfinder"},
		{Kind: sourceretire.KindConnector, Sender: "feed"},
	}
	never := func([]shared.ID) (bool, error) { t.Fatal("asked for another sensor"); return false, nil }
	other := func(ok bool, err error) func([]shared.ID) (bool, error) {
		return func(ex []shared.ID) (bool, error) { return ok, err }
	}

	cases := []struct {
		name      string
		sels      []sourceretire.Selector
		sensor    shared.ID
		job       *commanddom.Command
		elsewhere func([]shared.ID) (bool, error)
		want      retiredOutcome
	}{
		{"no retirement", nil, s1, retiredJob(t, commanddom.CommandTypeScan, "nuclei", nil), never, retiredKeep},
		{"another tool on the same sensor runs", sels, s1, retiredJob(t, commanddom.CommandTypeScan, "httpx", nil), never, retiredKeep},
		{"an upload retirement of the tool does not stop a sensor", sels, s1, retiredJob(t, commanddom.CommandTypeScan, "subfinder", nil), never, retiredKeep},
		{"another sensor's retirement does not stop this one", []sourceretire.Selector{sensorTool(s2, "nuclei")}, s1,
			retiredJob(t, commanddom.CommandTypeScan, "nuclei", nil), never, retiredKeep},
		{"not a scan job", sels, s1, retiredJob(t, commanddom.CommandTypeValidate, "nuclei", nil), never, retiredKeep},
		{"pinned to the sensor: refused (case-insensitive tool)", sels, s1, retiredJob(t, commanddom.CommandTypeScan, "NUCLEI", &s1), never, retiredRefuse},
		{"connector scan pinned: refused", []sourceretire.Selector{sensorTool(s1, "tenable_sc")}, s1,
			retiredJob(t, commanddom.CommandTypeConnectorScan, "tenable_sc", &s1), never, retiredRefuse},
		{"unpinned, another sensor may run it: withheld", sels, s1, retiredJob(t, commanddom.CommandTypeScan, "nuclei", nil), other(true, nil), retiredWithhold},
		{"unpinned, no other sensor: refused", sels, s1, retiredJob(t, commanddom.CommandTypeScan, "nuclei", nil), other(false, nil), retiredRefuse},
		{"unpinned, lookup error: withheld (fail closed)", sels, s1, retiredJob(t, commanddom.CommandTypeScan, "nuclei", nil), other(false, errors.New("db down")), retiredWithhold},
		{"unpinned, no candidate finder: refused", sels, s1, retiredJob(t, commanddom.CommandTypeScan, "nuclei", nil), nil, retiredRefuse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideRetired(tc.sels, tc.sensor, tc.job, tc.elsewhere); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// The other sensors asked about exclude every sensor the tool is retired
// on, the claiming one included.
func TestDecideRetired_ExcludesEverySensorTheToolIsRetiredOn(t *testing.T) {
	s1, s2, s3 := shared.NewID(), shared.NewID(), shared.NewID()
	sels := []sourceretire.Selector{sensorTool(s1, "nuclei"), sensorTool(s2, "Nuclei"), sensorTool(s3, "httpx")}
	var got []shared.ID
	decideRetired(sels, s1, retiredJob(t, commanddom.CommandTypeScan, "nuclei", nil), func(ex []shared.ID) (bool, error) {
		got = ex
		return true, nil
	})
	want := map[shared.ID]bool{s1: true, s2: true}
	if len(got) != 2 || !want[got[0]] || !want[got[1]] {
		t.Fatalf("excluded %v, want s1 and s2 only", got)
	}
}
