package sensor

import (
	"reflect"
	"testing"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// The projection reads each implemented capability's param mapping from
// the descriptor: a param without a key sets the key of its own name, and
// an implements entry the contract does not list is ignored.
func TestDeclarationOfReadsParamMappings(t *testing.T) {
	desc := []byte(`{"apiVersion":"openctem.io/tool/v1","name":"acme-headers","version":"1.2.0",
		"implements":[
			{"capability":"vuln.templates@1","params":{"rate":{"key":"rps","max":50},"severity":{}}},
			{"capability":"scan.ports@1","params":{"rate":{}}}
		]}`)
	d := declarationOf(sensordom.DeclaredTool{Name: "acme-headers", Contract: &sensordom.ToolContract{
		Digest: "sha256:ab", Implements: []string{"vuln.templates@1"}, Descriptor: desc,
	}})
	want := map[string]map[string]string{"vuln.templates@1": {"rate": "rps", "severity": "severity"}}
	if !reflect.DeepEqual(d.Params, want) {
		t.Fatalf("params = %v, want %v", d.Params, want)
	}
	if d.Version != "1.2.0" {
		t.Fatalf("version = %q", d.Version)
	}

	// No implements in the descriptor: no mappings, nothing invented.
	d = declarationOf(sensordom.DeclaredTool{Name: "x", Contract: &sensordom.ToolContract{
		Digest: "sha256:cd", Implements: []string{"vuln.templates@1"}, Descriptor: []byte(`{"name":"x"}`),
	}})
	if d.Params != nil {
		t.Fatalf("params = %v, want none", d.Params)
	}
}
