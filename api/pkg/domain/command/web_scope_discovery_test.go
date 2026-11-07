package command

import (
	"encoding/json"
	"testing"
)

func TestIsDiscoveryJob(t *testing.T) {
	cases := map[string]struct {
		payload string
		want    bool
	}{
		"capability":                  {`{"capability":"enumerate.web_paths@1","scanner":"x"}`, true},
		"discovery tool":              {`{"scanner":"webguess"}`, true},
		"step required capabilities":  {`{"scanner":"othertool","required_capabilities":["enumerate.web_paths"]}`, true},
		"step required cap versioned": {`{"scanner":"othertool","required_capabilities":["Enumerate.Web_Paths@2"]}`, true},
		"step without tool":           {`{"required_capabilities":["probe.http","enumerate.web_paths"]}`, true},
		"other capability":            {`{"scanner":"nuclei","required_capabilities":["vuln.templates"]}`, false},
		"no capability":               {`{"scanner":"nuclei"}`, false},
	}
	for name, c := range cases {
		if got := IsDiscoveryJob(json.RawMessage(c.payload)); got != c.want {
			t.Errorf("%s: got %v want %v", name, got, c.want)
		}
	}
}

func TestWebJobOfStepPayloadNamingOtherToolIsDiscovery(t *testing.T) {
	cmd := &Command{Type: CommandTypeScan, Payload: json.RawMessage(`{"scanner":"othertool","targets":["https://app.example.com"],"required_capabilities":["enumerate.web_paths"]}`)}
	job, ok := WebJobOf(cmd)
	if !ok || !job.Discovery {
		t.Fatalf("a step naming enumerate.web_paths with another tool must be a discovery web job, got ok=%v discovery=%v", ok, job.Discovery)
	}
}
