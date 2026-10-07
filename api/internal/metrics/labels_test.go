package metrics

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// RFC-046 B9: no metric carries a tenant, sensor, scan workflow or run id as a
// label. Per-tenant views come from logs and traces; ids as labels leak
// tenant identity into every metrics consumer and blow up cardinality.
// Every metric definition file of the API is checked.
func TestNoIdentifierLabels(t *testing.T) {
	forbidden := []string{"tenant_id", "sensor_id", "scan_workflow_id", "run_id", "scan_id", "user_id"}
	files := []string{
		"metrics.go",
		"security_defenses.go",
		filepath.Join("..", "infra", "telemetry", "ctem_metrics.go"),
	}
	labels := regexp.MustCompile(`\[\]string\{([^}]*)\}`)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range labels.FindAllStringSubmatch(string(raw), -1) {
			for _, bad := range forbidden {
				if strings.Contains(m[1], `"`+bad+`"`) {
					t.Errorf("%s: metric label list %s carries %q", f, m[0], bad)
				}
			}
		}
	}
}
